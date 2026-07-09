#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eh_diagnose.py — Azure Event Hubs read-only diagnostic CLI.

Part of the Azure diagnostic tool suite (pg_diagnose / aks_diagnose / adx_diagnose).
Design mirrors aks_diagnose's explicit separation of authentication domains.

Three (+1 optional) auth domains
--------------------------------
  1. Control plane (ARM)       namespace / event hub configuration   --azure-auth
  2. Metrics plane             Azure Monitor platform metrics        (shares Entra token)
  3. Data / runtime plane      partition runtime properties          --eh-auth {entra|connstr}
  (optional) Checkpoint store  consumer lag from Blob checkpoints    --checkpoint-store

Every operation is strictly READ-ONLY. The tool never sends, receives, or
modifies events, keyslots, configuration, or checkpoints.

Output schema (matches pg_diagnose)
-----------------------------------
  { "tool": "eh_diagnose", "namespace": "...", "checks": [
      { "category": "throttling", "severity": "critical|warning|info|ok",
        "title": "...", "detail": "...", "evidence": { ... } }, ... ] }

Windows note: Python stdout defaults to cp1252 on Windows. Set
  $env:PYTHONIOENCODING="utf-8"
before running if you see UnicodeEncodeError with the table renderer.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

TOOL_NAME = "eh_diagnose"
TOOL_VERSION = "1.1.0"

# --------------------------------------------------------------------------- #
# Rule / threshold table  (adx_diagnose-style, single source of truth)
# --------------------------------------------------------------------------- #
# Metric-based rules are data-driven. `agg` is the aggregation reduced over the
# whole window; `cmp` is how the reduced value is compared to warn/crit.
METRIC_RULES: dict[str, dict[str, Any]] = {
    "throttling": {
        "metric": "ThrottledRequests", "agg": "total", "cmp": "gt",
        "warn": 1, "crit": 100,
        "title": "요청 스로틀링(용량 압박)",
        "hint": "Auto-Inflate(Standard)를 활성화하거나 TU/PU를 늘리세요. 스로틀링은 "
                "ingress/egress가 프로비저닝된 처리량을 초과했음을 의미합니다.",
    },
    "server_errors": {
        "metric": "ServerErrors", "agg": "total", "cmp": "gt",
        "warn": 1, "crit": 50,
        "title": "서버 측 오류",
        "hint": "서비스 측 실패입니다. 스로틀링과의 상관성을 확인하고, 스로틀링 없이 "
                "지속되면 지원 케이스를 열어 주세요.",
    },
    "user_errors": {
        "metric": "UserErrors", "agg": "total", "cmp": "gt",
        "warn": 100, "crit": 1000,
        "title": "사용자(클라이언트 측) 오류",
        "hint": "대개 클라이언트 설정 문제입니다: 인증, 잘못된 엔티티(이름), 또는 "
                "잘못된 요청 형식(HTTP 4xx 계열)을 확인하세요.",
    },
    "quota_errors": {
        "metric": "QuotaExceededErrors", "agg": "total", "cmp": "gt",
        "warn": 1, "crit": 50,
        "title": "쿼터 초과 오류",
        "hint": "쿼터(크기, 연결 수, 또는 TU)를 초과했습니다. 네임스페이스 "
                "Size와 ActiveConnections를 티어 한도와 대조하세요.",
    },
    "capture_backlog": {
        "metric": "CaptureBacklog", "agg": "average", "cmp": "gt",
        "warn": 1, "crit": 1000,
        "title": "Capture 백로그 증가",
        "hint": "Capture가 뒤처지고 있습니다. 대상 Storage/ADLS의 권한·처리량과 "
                "컨테이너 존재 여부를 확인하세요.",
    },
}

# Non-metric / derived thresholds (overridable via CLI where workload-specific).
DERIVED_DEFAULTS = {
    "egress_ratio_warn": 0.90,   # egress/ingress below this over the window = consumers lagging
    "egress_ratio_crit": 0.50,
    "partition_skew_warn": 2.0,  # max/mean of retained events per partition
    "partition_skew_crit": 5.0,
    "conn_pct_warn": 0.80,       # ActiveConnections / --max-connections
    "conn_pct_crit": 0.95,
    "lag_warn": 10_000,          # consumer lag in messages (per partition, worst)
    "lag_crit": 100_000,
}

# Platform metrics we pull (Microsoft.EventHub/namespaces, confirmed REST names).
METRIC_NAMES = [
    "ThrottledRequests", "IncomingRequests", "SuccessfulRequests",
    "IncomingMessages", "OutgoingMessages", "IncomingBytes", "OutgoingBytes",
    "ServerErrors", "UserErrors", "QuotaExceededErrors",
    "ActiveConnections", "ConnectionsOpened", "ConnectionsClosed",
    "CaptureBacklog", "CapturedMessages", "CapturedBytes", "Size",
]

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
SEV_LABEL_KO = {"critical": "위험", "warning": "주의", "info": "정보", "ok": "양호"}


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class Check:
    category: str
    severity: str  # critical | warning | info | ok
    title: str
    detail: str
    recommendation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    tool: str = TOOL_NAME
    version: str = TOOL_VERSION
    namespace: str = ""
    event_hub: Optional[str] = None
    generated_at: str = ""
    window: str = ""
    checks: list[Check] = field(default_factory=list)

    def add(self, category: str, severity: str, title: str, detail: str,
            evidence: Optional[dict[str, Any]] = None,
            recommendation: str = "") -> None:
        self.checks.append(Check(category, severity, title, detail,
                                 recommendation, evidence or {}))

    def worst_severity(self) -> str:
        if not self.checks:
            return "ok"
        return min((c.severity for c in self.checks), key=lambda s: SEVERITY_ORDER[s])

    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "warning": 0, "info": 0, "ok": 0}
        for c in self.checks:
            if c.severity in counts:
                counts[c.severity] += 1
        return counts

    def health_score(self) -> int:
        """0-100 health score. critical/warning findings reduce the score;
        info/ok are neutral so purely informational runs stay near 100."""
        penalty = {"critical": 25, "warning": 8, "info": 0, "ok": 0}
        score = 100 - sum(penalty.get(c.severity, 0) for c in self.checks)
        return max(0, min(100, score))

    def recommended_actions(self) -> list[dict[str, str]]:
        """Prioritized, deduplicated actions (severity-ordered) for the SRE Agent
        to surface as 'next steps'. Only findings that carry a recommendation."""
        seen: set[str] = set()
        actions: list[dict[str, str]] = []
        for c in sorted(self.checks, key=lambda x: SEVERITY_ORDER[x.severity]):
            if not c.recommendation or c.recommendation in seen:
                continue
            seen.add(c.recommendation)
            actions.append({"severity": c.severity, "category": c.category,
                            "title": c.title, "action": c.recommendation})
        return actions

    def summary_text(self) -> str:
        """One-line natural-language summary for the SRE Agent / chat surface."""
        c = self.severity_counts()
        tgt = self.namespace + (f"/{self.event_hub}" if self.event_hub else "")
        s = (f"건강 점수 {self.health_score()}/100 "
             f"({SEV_LABEL_KO.get(self.worst_severity(), self.worst_severity())}). "
             f"위험 {c['critical']}, 주의 {c['warning']}, 정보 {c['info']}건 "
             f"— {tgt}, {self.window}.")
        top = next((ch for ch in sorted(self.checks, key=lambda x: SEVERITY_ORDER[x.severity])
                    if ch.severity in ("critical", "warning")), None)
        if top:
            s += f" 핵심 이슈: {top.title}."
            if top.recommendation:
                s += f" 권장: {top.recommendation}"
        return s


# --------------------------------------------------------------------------- #
# Optional-dependency import guards (tool degrades gracefully)
# --------------------------------------------------------------------------- #
def _lazy_import(name: str):
    try:
        return __import__(name, fromlist=["*"])
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# Auth builders
# --------------------------------------------------------------------------- #
def build_entra_credential():
    """Entra ID credential for ARM + Azure Monitor (control & metrics planes)."""
    idmod = _lazy_import("azure.identity")
    if idmod is None:
        raise RuntimeError("azure-identity not installed. pip install azure-identity")
    # Exclude the interactive browser credential: this tool runs headless
    # (CI / MCP / Azure SRE Agent) and must never block on a browser prompt.
    return idmod.DefaultAzureCredential(exclude_interactive_browser_credential=True)


# --------------------------------------------------------------------------- #
# Resource-id helpers
# --------------------------------------------------------------------------- #
_RID_RE = re.compile(
    r"/subscriptions/(?P<sub>[^/]+)/resourceGroups/(?P<rg>[^/]+)/providers/"
    r"Microsoft\.EventHub/namespaces/(?P<ns>[^/]+)", re.IGNORECASE,
)


def parse_resource_id(rid: str) -> tuple[str, str, str]:
    m = _RID_RE.search(rid or "")
    if not m:
        raise ValueError(f"Could not parse Event Hubs namespace resource id: {rid!r}")
    return m.group("sub"), m.group("rg"), m.group("ns")


def build_resource_id(sub: str, rg: str, ns: str) -> str:
    return (f"/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.EventHub/namespaces/{ns}")


def normalize_region(location: str) -> str:
    return re.sub(r"\s+", "", (location or "")).lower()


# --------------------------------------------------------------------------- #
# Collector 1 — Control plane (ARM)
# --------------------------------------------------------------------------- #
def collect_control_plane(cred, sub: str, rg: str, ns: str,
                          event_hub: Optional[str]) -> dict[str, Any]:
    mgmt = _lazy_import("azure.mgmt.eventhub")
    if mgmt is None:
        return {"_error": "azure-mgmt-eventhub not installed "
                          "(pip install azure-mgmt-eventhub)"}
    client = mgmt.EventHubManagementClient(cred, sub)
    out: dict[str, Any] = {}
    ns_obj = client.namespaces.get(rg, ns)
    sku = getattr(ns_obj, "sku", None)
    out["location"] = getattr(ns_obj, "location", None)
    out["sku_tier"] = getattr(sku, "tier", None)
    out["sku_capacity"] = getattr(sku, "capacity", None)
    out["auto_inflate_enabled"] = getattr(ns_obj, "is_auto_inflate_enabled", None)
    out["maximum_throughput_units"] = getattr(ns_obj, "maximum_throughput_units", None)
    out["zone_redundant"] = getattr(ns_obj, "zone_redundant", None)
    out["minimum_tls_version"] = getattr(ns_obj, "minimum_tls_version", None)
    out["public_network_access"] = getattr(ns_obj, "public_network_access", None)
    out["disable_local_auth"] = getattr(ns_obj, "disable_local_auth", None)

    hubs: dict[str, Any] = {}
    hub_iter = ([event_hub] if event_hub
                else [h.name for h in client.event_hubs.list_by_namespace(rg, ns)])
    for hub in hub_iter:
        h = client.event_hubs.get(rg, ns, hub)
        cap = getattr(h, "capture_description", None)
        try:
            groups = [g.name for g in
                      client.consumer_groups.list_by_event_hub(rg, ns, hub)]
        except Exception:  # noqa: BLE001
            groups = []
        hubs[hub] = {
            "partition_count": getattr(h, "partition_count", None),
            "message_retention_days": getattr(h, "message_retention_in_days", None),
            "capture_enabled": bool(getattr(cap, "enabled", False)) if cap else False,
            "consumer_groups": groups,
        }
    out["event_hubs"] = hubs
    return out


# --------------------------------------------------------------------------- #
# Collector 2 — Metrics plane (Azure Monitor, MetricsClient 2.x regional)
# --------------------------------------------------------------------------- #
def _load_metrics_sdk():
    """Resolve (MetricsClient, MetricAggregationType) with 2.x-first / 1.x-fallback.

    azure-monitor-query 2.x removed metrics: MetricsClient now lives in
    azure-monitor-querymetrics (module `azure.monitor.querymetrics`). Older
    azure-monitor-query 1.2-1.x still exposes it under `azure.monitor.query`.
    """
    for mod in ("azure.monitor.querymetrics", "azure.monitor.query"):
        m = _lazy_import(mod)
        if m is not None and hasattr(m, "MetricsClient") \
                and hasattr(m, "MetricAggregationType"):
            return m.MetricsClient, m.MetricAggregationType
    return None, None


def _dim_entity(ts) -> Optional[str]:
    """Return the EntityName dimension value of a timeseries element, if present."""
    for mv in (getattr(ts, "metadata_values", None) or []):
        raw = getattr(mv, "name", None)
        name = raw if isinstance(raw, str) else getattr(raw, "value", None)
        if str(name).replace(" ", "").lower() == "entityname":
            return getattr(mv, "value", None)
    return None


def _reduce_metric(metric) -> dict[Optional[str], dict[str, float]]:
    """Reduce one Metric into {entity_name|None: {total, average, maximum}}."""
    per: dict[Optional[str], dict[str, float]] = {}
    for ts in metric.timeseries:
        entity = _dim_entity(ts)
        totals, avgs, maxes = [], [], []
        for point in ts.data:
            if getattr(point, "total", None) is not None:
                totals.append(point.total)
            if getattr(point, "average", None) is not None:
                avgs.append(point.average)
            if getattr(point, "maximum", None) is not None:
                maxes.append(point.maximum)
        per[entity] = {
            "total": float(sum(totals)) if totals else 0.0,
            "average": float(sum(avgs) / len(avgs)) if avgs else 0.0,
            "maximum": float(max(maxes)) if maxes else 0.0,
        }
    return per


def collect_metrics(cred, resource_id: str, region: str,
                    minutes: int) -> dict[str, Any]:
    MetricsClient, Agg = _load_metrics_sdk()
    if MetricsClient is None:
        return {"_error": "MetricsClient unavailable. Install "
                          "azure-monitor-querymetrics (2.x) or "
                          "azure-monitor-query>=1.2,<2 (1.x)."}
    endpoint = f"https://{region}.metrics.monitor.azure.com"
    client = MetricsClient(endpoint, cred)
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)
    aggs = [Agg.TOTAL, Agg.AVERAGE, Agg.MAXIMUM]

    def _run(names, use_filter):
        kwargs = dict(
            resource_ids=[resource_id],
            metric_namespace="Microsoft.EventHub/namespaces",
            metric_names=names, timespan=(start, end),
            granularity=timedelta(minutes=5), aggregations=aggs,
        )
        if use_filter:
            kwargs["filter"] = "EntityName eq '*'"   # split per event hub
        return client.query_resources(**kwargs)

    def _collect(names, use_filter):
        acc: dict[str, Any] = {}
        for result in _run(names, use_filter):
            for metric in result.metrics:
                acc[metric.name] = _reduce_metric(metric)
        return acc

    # Prefer a single batch call split by EntityName. If the dimension filter
    # is unsupported, retry without it. If the whole batch still fails (e.g. one
    # unsupported metric/aggregation), fall back to querying name-by-name so a
    # single bad metric cannot sink the entire plane.
    for use_filter in (True, False):
        try:
            return _collect(METRIC_NAMES, use_filter)
        except Exception:  # noqa: BLE001
            continue

    reduced: dict[str, Any] = {}
    notes: list[str] = []
    for name in METRIC_NAMES:
        try:
            reduced.update(_collect([name], False))
        except Exception as e:  # noqa: BLE001
            notes.append(f"{name}: {str(e).splitlines()[0]}")
    if not reduced:
        return {"_error": "metrics query failed: " + "; ".join(notes[:3])}
    if notes:
        reduced["_notes"] = notes
    return reduced


# --------------------------------------------------------------------------- #
# Collector 3 — Data / runtime plane (partition properties, read-only)
# --------------------------------------------------------------------------- #
def collect_partition_runtime(fqdn: str, event_hub: str, cred=None,
                              conn_str: Optional[str] = None) -> dict[str, Any]:
    eh = _lazy_import("azure.eventhub")
    if eh is None:
        return {"_error": "azure-eventhub not installed (pip install azure-eventhub)"}
    # EventHubProducerClient reads runtime properties without sending anything.
    if conn_str:
        producer = eh.EventHubProducerClient.from_connection_string(
            conn_str, eventhub_name=event_hub)
    else:
        producer = eh.EventHubProducerClient(
            fully_qualified_namespace=fqdn, eventhub_name=event_hub, credential=cred)
    partitions: dict[str, Any] = {}
    with producer:
        props = producer.get_eventhub_properties()
        for pid in props["partition_ids"]:
            p = producer.get_partition_properties(pid)
            begin = p["beginning_sequence_number"]
            last = p["last_enqueued_sequence_number"]
            partitions[pid] = {
                "beginning_sequence_number": begin,
                "last_enqueued_sequence_number": last,
                "last_enqueued_time_utc": str(p["last_enqueued_time_utc"]),
                "is_empty": p["is_empty"],
                "retained_events": max(0, (last - begin + 1)) if not p["is_empty"] else 0,
            }
    return {"partitions": partitions}


# --------------------------------------------------------------------------- #
# Collector 4 (optional) — Checkpoint store -> consumer lag
# --------------------------------------------------------------------------- #
def collect_all_checkpoint_lag(container_url: str, cred, fqdn: str,
                               runtime_by_hub: dict[str, Any],
                               consumer_group_filter: Optional[str] = None) -> Any:
    """
    Scan a BlobCheckpointStore container and compute per-partition consumer lag
    for EVERY (event hub, consumer group) present, as
    (last_enqueued_sequence_number - checkpoint sequence number).

    Checkpoint blob layout (azure-eventhub v5 BlobCheckpointStore):
      {fqdn}/{eventhub}/{consumer_group}/checkpoint/{partition_id}
      metadata: {"sequencenumber": "...", "offset": "..."}
    All names are lower-cased by the SDK, so matching is case-insensitive.

    Returns a list of {event_hub, consumer_group, partition_lag} entries, or
    {"_error": ...} when the store cannot be read.
    """
    blobmod = _lazy_import("azure.storage.blob")
    if blobmod is None:
        return {"_error": "azure-storage-blob not installed "
                          "(pip install azure-storage-blob)"}
    rt_by_lower = {h.lower(): (h, rt) for h, rt in (runtime_by_hub or {}).items()}
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    try:
        container = blobmod.ContainerClient.from_container_url(
            container_url, credential=cred)
        for blob in container.list_blobs(
                name_starts_with=f"{fqdn.lower()}/", include=["metadata"]):
            segs = blob.name.split("/")
            # {fqdn}/{eventhub}/{consumer_group}/checkpoint/{partition_id}
            if len(segs) < 5 or segs[3] != "checkpoint":
                continue
            hub_l, grp, pid = segs[1], segs[2], segs[-1]
            if consumer_group_filter and grp.lower() != consumer_group_filter.lower():
                continue
            match = rt_by_lower.get(hub_l)
            if not match:
                continue
            hub_name, rt = match
            rparts = (rt.get("partitions", {})
                      if isinstance(rt, dict) and not rt.get("_error") else {})
            if pid not in rparts:
                continue
            cp_seq = (blob.metadata or {}).get("sequencenumber")
            if cp_seq is None:
                continue
            try:
                cp_seq_i = int(cp_seq)
            except (TypeError, ValueError):
                continue
            last = rparts[pid]["last_enqueued_sequence_number"]
            grouped.setdefault((hub_name, grp), {})[pid] = {
                "checkpoint_sequence_number": cp_seq_i,
                "last_enqueued_sequence_number": last,
                "lag": max(0, last - cp_seq_i),
            }
    except Exception as e:  # noqa: BLE001
        return {"_error": f"checkpoint store: {str(e).splitlines()[0]}"}
    return [{"event_hub": h, "consumer_group": g, "partition_lag": pl}
            for (h, g), pl in sorted(grouped.items())]


# --------------------------------------------------------------------------- #
# Rule engine
# --------------------------------------------------------------------------- #
def _cmp(value: float, threshold: float, how: str) -> bool:
    return value > threshold if how == "gt" else value < threshold


def _mv(metrics: Any, name: str, entity: Optional[str], agg: str) -> Optional[float]:
    """Look up a reduced metric value for a given entity (event hub).

    Falls back to the namespace-level series (entity None) when a per-entity
    split is not available.
    """
    per = metrics.get(name) if isinstance(metrics, dict) else None
    if not isinstance(per, dict):
        return None
    d = per.get(entity)
    if d is None and entity is not None:
        d = per.get(None)
    return d.get(agg) if isinstance(d, dict) else None


def evaluate(report: Report, control: dict[str, Any], metrics: dict[str, Any],
             runtime_by_hub: dict[str, Any], lag_list: Any,
             derived: dict[str, float], max_connections: Optional[int],
             hubs: list[str]) -> None:

    # Consumer-group counts per hub (for egress/ingress fan-out normalization).
    cg_counts: dict[str, int] = {}
    if control and not control.get("_error"):
        for h, cfg in (control.get("event_hubs") or {}).items():
            cg_counts[h] = len((cfg or {}).get("consumer_groups") or [])

    # -- metric-driven rules, split per event hub ---------------------------- #
    metric_err = isinstance(metrics, dict) and metrics.get("_error")
    if metric_err:
        report.add("metrics", "info", "메트릭 평면 사용 불가",
                   str(metrics["_error"]))
    else:
        if isinstance(metrics, dict) and metrics.get("_notes"):
            report.add("metrics", "info", "일부 메트릭 건너뜀",
                       "; ".join(str(n) for n in metrics["_notes"][:5]))

        targets = list(hubs)
        if not targets:
            ents: set[str] = set()
            for _n, per in (metrics or {}).items():
                if isinstance(per, dict):
                    ents.update(k for k in per.keys() if k)
            targets = sorted(ents) or [None]  # type: ignore[list-item]

        for hub in targets:
            label = hub or "namespace"

            for cat, rule in METRIC_RULES.items():
                val = _mv(metrics, rule["metric"], hub, rule["agg"])
                if val is None:
                    continue
                if _cmp(val, rule["crit"], rule["cmp"]):
                    sev = "critical"
                elif _cmp(val, rule["warn"], rule["cmp"]):
                    sev = "warning"
                else:
                    sev = "ok"
                detail = (f"[{label}] {rule['metric']} ({rule['agg']})={val:g} "
                          f"(윈도우 집계).")
                report.add(cat, sev, f"{rule['title']} \u2014 {label}", detail,
                           {"event_hub": hub, "metric": rule["metric"],
                            "value": val, "warn": rule["warn"],
                            "crit": rule["crit"]},
                           recommendation=(rule["hint"] if sev != "ok" else ""))

            # egress/ingress balance (fan-out aware; per-group lag is authoritative)
            inc = _mv(metrics, "IncomingMessages", hub, "total")
            out = _mv(metrics, "OutgoingMessages", hub, "total")
            if inc and inc > 0 and out is not None:
                ratio = out / inc
                groups = cg_counts.get(hub, 0)
                if groups >= 1:
                    norm = ratio / groups
                    basis = (f"컨슈머 그룹 {groups}개; "
                             f"그룹당 비율={norm:.2f}")
                else:
                    norm = ratio
                    basis = ("컨슈머 그룹 수 미상; 원시 비율 "
                             "(팬아웃 미정규화)")
                if norm < derived["egress_ratio_crit"]:
                    sev = "critical"
                elif norm < derived["egress_ratio_warn"]:
                    sev = "warning"
                else:
                    sev = "ok"
                detail = (f"[{label}] egress/ingress 원시비율={ratio:.2f} "
                          f"(in={inc:g}, out={out:g}); {basis}. Egress는 컨슈머 "
                          f"그룹별로 분리할 수 없으므로 그룹별 consumer_lag를 "
                          f"기준으로 삼으세요." if sev != "ok"
                          else f"[{label}] egress/ingress 균형 양호 "
                               f"(원시 {ratio:.2f}; {basis}).")
                report.add("backlog", sev,
                           f"Egress/Ingress 균형 \u2014 {label}", detail,
                           {"event_hub": hub, "ratio": round(ratio, 3),
                            "per_group_ratio": round(norm, 3),
                            "consumer_groups": groups,
                            "incoming": inc, "outgoing": out},
                           recommendation=(
                               "컨슈머가 수집(ingress) 속도를 따라가지 못합니다. "
                               "컨슈머 상태를 확인하고 컨슈머/파티션을 증설하며, "
                               "느린 처리를 조사하세요. 그룹별 consumer_lag로 "
                               "지연되는 그룹을 특정하세요."
                               if sev != "ok" else ""))

            # active connections
            active = _mv(metrics, "ActiveConnections", hub, "maximum")
            if active is not None and max_connections:
                pct = active / max_connections
                if pct >= derived["conn_pct_crit"]:
                    sev = "critical"
                elif pct >= derived["conn_pct_warn"]:
                    sev = "warning"
                else:
                    sev = "ok"
                report.add("connections", sev,
                           f"활성 연결 수 대비 한도 \u2014 {label}",
                           f"[{label}] ActiveConnections(max)={active:g} / "
                           f"{max_connections} ({pct:.0%}).",
                           {"event_hub": hub, "active_max": active,
                            "limit": max_connections, "pct": round(pct, 3)},
                           recommendation=(
                               "연결 한도에 근접하고 있습니다. 클라이언트 연결을 "
                               "줄이거나(풀링/공유 클라이언트 사용), 연결 쿼터가 "
                               "더 큰 상위 티어로 이전하세요."
                               if sev != "ok" else ""))
            elif active:
                report.add("connections", "info",
                           f"활성 연결 수 \u2014 {label}",
                           f"[{label}] ActiveConnections(max)={active:g}. "
                           f"티어 한도와 비교하려면 --max-connections를 지정하세요.",
                           {"event_hub": hub, "active_max": active})

    # -- partition skew, per hub --------------------------------------------- #
    for hub, rt in (runtime_by_hub or {}).items():
        if not rt:
            continue
        if rt.get("_error"):
            report.add("runtime", "info", f"런타임 평면 사용 불가 \u2014 {hub}",
                       str(rt["_error"]))
            continue
        parts = rt.get("partitions", {})
        retained = [p["retained_events"] for p in parts.values()
                    if p.get("retained_events")]
        if len(retained) >= 2 and sum(retained) > 0:
            mean = sum(retained) / len(retained)
            skew = (max(retained) / mean) if mean else 0.0
            if skew >= derived["partition_skew_crit"]:
                sev = "critical"
            elif skew >= derived["partition_skew_warn"]:
                sev = "warning"
            else:
                sev = "ok"
            report.add("partition_skew", sev,
                       f"파티션 분포 편중 \u2014 {hub}",
                       f"[{hub}] 파티션 {len(retained)}개의 max/mean 보관 이벤트 "
                       f"편중도 = {skew:.1f}x."
                       + (" 편중도가 높으면 핫(hot) 파티션 키 가능성이 큽니다."
                          if sev != "ok" else ""),
                       {"event_hub": hub, "skew": round(skew, 2),
                        "partitions": len(retained)},
                       recommendation=(
                           "파티션 키를 재분배해 부하가 고르게 퍼지도록 하세요. "
                           "단일 핫 키를 피하고, 순서가 필요 없다면 고카디널리티 "
                           "키나 라운드로빈(키 없음)을 사용하세요."
                           if sev != "ok" else ""))

    # -- consumer lag, per (hub, consumer group) ----------------------------- #
    if isinstance(lag_list, dict) and lag_list.get("_error"):
        report.add("consumer_lag", "info", "체크포인트 저장소 미평가",
                   str(lag_list["_error"]))
    else:
        for entry in (lag_list or []):
            hub = entry.get("event_hub")
            grp = entry.get("consumer_group")
            plag = entry.get("partition_lag", {})
            if not plag:
                report.add("consumer_lag", "info",
                           f"체크포인트 없음 \u2014 {hub}/{grp}",
                           f"[{hub}/{grp}]에 대한 체크포인트 blob이 없습니다. "
                           f"컨슈머가 활성 상태여야 한다면 그 자체가 문제 신호입니다.",
                           {"event_hub": hub, "consumer_group": grp},
                           recommendation=(
                               "해당 그룹의 컨슈머가 실행 중이며 체크포인팅하는지 "
                               "확인하세요. 체크포인트 부재는 죽었거나 시작되지 않은 "
                               "컨슈머인 경우가 많습니다."))
                continue
            worst_lag = max(x["lag"] for x in plag.values())
            total_lag = sum(x["lag"] for x in plag.values())
            if worst_lag >= derived["lag_crit"]:
                sev = "critical"
            elif worst_lag >= derived["lag_warn"]:
                sev = "warning"
            else:
                sev = "ok"
            report.add("consumer_lag", sev, f"컨슈머 지연(lag) \u2014 {hub}/{grp}",
                       f"[{hub}/{grp}] 최악 파티션 lag={worst_lag:g}, "
                       f"총 {total_lag:g}개 메시지가 헤드 뒤에 있음." if sev != "ok"
                       else f"[{hub}/{grp}] 컨슈머가 잘 따라가는 중 "
                            f"(최악 lag {worst_lag:g}).",
                       {"event_hub": hub, "consumer_group": grp,
                        "worst_lag": worst_lag, "total_lag": total_lag,
                        "per_partition": plag},
                       recommendation=(
                           "컨슈머를 증설하거나(파티션 수까지) 이벤트당 처리 "
                           "속도를 높이세요. 느린 다운스트림 호출을 조사하고 "
                           "해당 그룹에 죽은 컨슈머가 없는지 확인하세요."
                           if sev != "ok" else ""))

    # -- config audit -------------------------------------------------------- #
    if control and not control.get("_error"):
        tier = control.get("sku_tier")
        if control.get("auto_inflate_enabled") is False and tier == "Standard":
            report.add("config", "warning", "Auto-Inflate 비활성화",
                       "Auto-Inflate가 꺼진 Standard 네임스페이스는 트래픽 "
                       "스파이크를 흡수하지 못해 스로틀링이 발생합니다.",
                       {"sku_tier": tier, "auto_inflate": False},
                       recommendation="Auto-Inflate를 활성화하고 "
                                      "maximumThroughputUnits를 안전한 상한으로 설정하세요.")
        if control.get("public_network_access") == "Enabled":
            report.add("config", "warning", "공용 네트워크 액세스 허용",
                       "네임스페이스가 공용 트래픽을 허용합니다.",
                       {"public_network_access": "Enabled"},
                       recommendation="프로덕션에서는 Private Endpoint를 사용하고 "
                                      "publicNetworkAccess=Disabled로 설정하세요.")
        tls = control.get("minimum_tls_version")
        if tls is not None:
            mtls = re.search(r"(\d+)\.(\d+)", str(tls).replace("_", "."))
            if mtls and (int(mtls.group(1)), int(mtls.group(2))) < (1, 2):
                report.add("config", "critical", "취약한 최소 TLS 버전",
                           f"minimumTlsVersion={tls}.",
                           {"minimum_tls_version": tls},
                           recommendation="minimumTlsVersion을 1.2 이상으로 설정하세요.")
        if control.get("disable_local_auth") is False:
            report.add("config", "info", "SAS(로컬 인증) 활성화",
                       "로컬(SAS) 인증이 활성화되어 있습니다.",
                       {"disable_local_auth": False},
                       recommendation="클라이언트가 지원한다면 Entra 전용 인증"
                                      "(disableLocalAuth=true)을 검토하세요.")
        for hub, hcfg in (control.get("event_hubs") or {}).items():
            if hcfg.get("partition_count") is not None:
                report.add("config", "info", f"파티션 수: {hub}",
                           f"partitionCount={hcfg['partition_count']}. 참고: "
                           f"Basic/Standard는 생성 후 변경할 수 없으므로 "
                           f"생성 시점에 적정 규모를 정해야 합니다.",
                           {"event_hub": hub,
                            "partition_count": hcfg["partition_count"]})

    if not report.checks:
        report.add("summary", "ok", "수집된 신호 없음",
                   "어느 평면에서도 데이터를 반환하지 않았습니다. 자격 증명과 플래그를 확인하세요.")


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
# Sanitization for the SRE Agent / MCP path (secrets, PII, prompt-injection).
_SECRET = re.compile(r'(?i)(password|pwd|secret|connection ?string|accountkey|sas|token|apikey)\s*[=:]\s*\S+')
_RRN = re.compile(r'\b\d{6}-\d{7}\b')
_EMAIL = re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b')
_INJECT = re.compile(r'(?i)(ignore (all|previous)|system prompt|<\s*important\s*>|assistant\s*:|tool_call)')


def _clean(v):
    if isinstance(v, str):
        v = _SECRET.sub(r'\1=***', v)
        v = _RRN.sub('[PII]', v)
        v = _EMAIL.sub('[PII]', v)
        v = _INJECT.sub('[filtered]', v)
        return v
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v


def render_json(report: Report) -> str:
    payload = _clean(asdict(report))
    payload["worst_severity"] = report.worst_severity()
    payload["health_score"] = report.health_score()
    payload["severity_counts"] = report.severity_counts()
    payload["summary"] = _clean(report.summary_text())
    payload["recommended_actions"] = _clean(report.recommended_actions())
    return json.dumps(payload, ensure_ascii=False, indent=2)


_SEV_TAG = {"critical": "[위험]", "warning": "[주의]", "info": "[정보]", "ok": "[양호]"}


def render_table(report: Report) -> str:
    counts = report.severity_counts()
    lines = [
        f"{TOOL_NAME} v{TOOL_VERSION}",
        f"네임스페이스 : {report.namespace}"
        + (f" / {report.event_hub}" if report.event_hub else ""),
        f"기간         : {report.window}   생성: {report.generated_at}",
        f"건강 점수    : {report.health_score()}/100   최악: "
        f"{SEV_LABEL_KO.get(report.worst_severity(), report.worst_severity())}",
        f"발견         : 위험 {counts['critical']}, 주의 {counts['warning']}, "
        f"정보 {counts['info']}, 양호 {counts['ok']}",
        "-" * 78,
    ]
    ordered = sorted(report.checks, key=lambda c: SEVERITY_ORDER[c.severity])
    for c in ordered:
        lines.append(f"{_SEV_TAG[c.severity]} {c.category:<15} {c.title}")
        lines.append(f"        {c.detail}")
        if c.recommendation:
            lines.append(f"        \u2192 조치: {c.recommendation}")
    actions = report.recommended_actions()
    if actions:
        lines.append("-" * 78)
        lines.append("권장 조치 (우선순위 순):")
        for i, a in enumerate(actions, 1):
            lines.append(f"  {i}. [{SEV_LABEL_KO.get(a['severity'], a['severity'])}] {a['title']}")
            lines.append(f"     {a['action']}")
    return "\n".join(lines)


_SEV_COLOR = {"critical": "#d93a3a", "warning": "#e8b42e",
              "info": "#3a7bd9", "ok": "#2ea84a"}


def render_html(report: Report) -> str:
    from html import escape as _esc
    worst = report.worst_severity()
    worst_color = _SEV_COLOR.get(worst, "#666")
    score = report.health_score()
    score_color = "#2ea84a" if score >= 80 else "#e8b42e" if score >= 50 else "#d93a3a"
    counts = report.severity_counts()
    hub = f" / {_esc(report.event_hub)}" if report.event_hub else ""
    ordered = sorted(report.checks, key=lambda c: SEVERITY_ORDER[c.severity])
    rows = []
    for c in ordered:
        color = _SEV_COLOR.get(c.severity, "#666")
        rec = (f'<div class="fix">\u2192 {_esc(c.recommendation)}</div>'
               if c.recommendation else "")
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{_esc(SEV_LABEL_KO.get(c.severity, c.severity))}</span></td>'
            f"<td>{_esc(c.category)}</td>"
            f"<td>{_esc(c.title)}</td>"
            f"<td>{_esc(c.detail)}{rec}</td>"
            "</tr>"
        )
    rows_html = "\n".join(rows) or '<tr><td colspan="4">발견된 항목이 없습니다.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>{_esc(TOOL_NAME)} report - {_esc(report.namespace)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 16px; line-height: 1.6; }}
  .score {{ display:inline-block; padding:6px 14px; border-radius:10px; color:#fff;
            font-weight:700; font-size:16px; background:{score_color}; }}
  .worst {{ display:inline-block; padding:3px 10px; border-radius:12px;
            background:{worst_color}; color:#fff; font-weight:700; }}
  .counts span {{ display:inline-block; margin-right:10px; font-size:13px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 13px; margin-top:12px; }}
  th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f2f2f2; }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:10px; color:#fff;
          font-size:12px; font-weight:600; }}
  .fix {{ margin-top:6px; padding:6px 8px; background:#eef4ff; border-left:3px solid #3a7bd9;
          color:#1a3b6b; font-size:12px; border-radius:2px; }}
  .summary {{ margin:12px 0; padding:10px 12px; background:#f7f9fc; border:1px solid #dbe4f0;
              border-radius:4px; font-size:13px; color:#33475b; }}
</style>
</head>
<body>
<h1>{_esc(TOOL_NAME)} v{_esc(TOOL_VERSION)}</h1>
<div class="meta">
  네임스페이스: <b>{_esc(report.namespace)}{hub}</b><br>
  기간: {_esc(report.window)} &nbsp; 생성: {_esc(report.generated_at)}<br>
  <div style="margin-top:8px">
    건강 점수: <span class="score">{score}/100</span>
    &nbsp; 최악: <span class="worst">{_esc(SEV_LABEL_KO.get(worst, worst))}</span>
  </div>
  <div class="counts" style="margin-top:8px">
    <span style="color:#d93a3a">\u25cf 위험: {counts['critical']}</span>
    <span style="color:#e8b42e">\u25cf 주의: {counts['warning']}</span>
    <span style="color:#3a7bd9">\u25cf 정보: {counts['info']}</span>
    <span style="color:#2ea84a">\u25cf 양호: {counts['ok']}</span>
  </div>
</div>
<div class="summary">{_esc(report.summary_text())}</div>
<table>
  <thead><tr><th>심각도</th><th>범주</th><th>제목</th><th>상세 &amp; 권장 조치</th></tr></thead>
  <tbody>
{rows_html}
  </tbody>
</table>
</body>
</html>"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Read-only Azure Event Hubs diagnostic tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Target
    tgt = p.add_argument_group("target")
    tgt.add_argument("--resource-id", help="Full ARM resource id of the namespace")
    tgt.add_argument("--subscription")
    tgt.add_argument("--resource-group")
    tgt.add_argument("--namespace")
    tgt.add_argument("--event-hub", help="Limit to a single event hub (entity)")
    tgt.add_argument("--region", help="Azure region for the metrics endpoint "
                                      "(e.g. koreacentral). Derived from ARM if omitted.")

    # Auth domains
    az = p.add_argument_group("azure / entra auth (control + metrics planes)")
    az.add_argument("--azure-auth", action="store_true",
                    help="Use DefaultAzureCredential for ARM + Azure Monitor")

    dp = p.add_argument_group("data / runtime plane auth")
    dp.add_argument("--eh-auth", choices=["entra", "connstr", "none"], default="entra",
                    help="How to read partition runtime properties")
    dp.add_argument("--eh-connstr", help="Event Hubs connection string (with --eh-auth connstr)")
    dp.add_argument("--fqdn", help="namespace FQDN, e.g. ehns.servicebus.windows.net "
                                   "(derived from --namespace if omitted)")

    cp = p.add_argument_group("checkpoint store (optional consumer-lag path)")
    cp.add_argument("--checkpoint-store", help="Blob container URL of the checkpoint store")
    cp.add_argument("--consumer-group", default=None,
                    help="Optional filter. By default, every consumer group found "
                         "in the checkpoint store is scanned.")

    # Tunables
    tn = p.add_argument_group("tunables")
    tn.add_argument("--window-minutes", type=int, default=60)
    tn.add_argument("--max-connections", type=int,
                    help="Tier connection limit, to evaluate ActiveConnections")
    tn.add_argument("--lag-warn", type=int, default=DERIVED_DEFAULTS["lag_warn"])
    tn.add_argument("--lag-crit", type=int, default=DERIVED_DEFAULTS["lag_crit"])

    # Output
    out = p.add_argument_group("output")
    out.add_argument("--format", choices=["table", "json", "html"], default="table")
    out.add_argument("--output", "-o",
                     help="Write the report to this file path instead of stdout "
                          "(e.g. report.html / report.json / report.txt)")
    out.add_argument("--exit-code", action="store_true",
                     help="Exit 2 if any critical, 1 if any warning, else 0")
    return p


def resolve_target(args) -> tuple[str, str, str, str]:
    if args.resource_id:
        sub, rg, ns = parse_resource_id(args.resource_id)
    elif args.subscription and args.resource_group and args.namespace:
        sub, rg, ns = args.subscription, args.resource_group, args.namespace
    else:
        raise SystemExit("Provide --resource-id OR --subscription/--resource-group/--namespace")
    rid = build_resource_id(sub, rg, ns)
    return sub, rg, ns, rid


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    sub, rg, ns, rid = resolve_target(args)

    derived = dict(DERIVED_DEFAULTS)
    derived["lag_warn"] = args.lag_warn
    derived["lag_crit"] = args.lag_crit

    report = Report(namespace=ns, event_hub=args.event_hub,
                    generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    window=f"last {args.window_minutes}m")

    cred = None
    if args.azure_auth or args.eh_auth == "entra" or args.checkpoint_store:
        try:
            cred = build_entra_credential()
        except RuntimeError as e:
            report.add("auth", "info", "Entra 자격 증명 사용 불가", str(e))

    # 1) control plane
    control: dict[str, Any] = {}
    region = normalize_region(args.region or "")
    if args.azure_auth and cred is not None:
        try:
            control = collect_control_plane(cred, sub, rg, ns, args.event_hub)
            if not region and control.get("location"):
                region = normalize_region(control["location"])
        except Exception as e:  # noqa: BLE001
            control = {"_error": f"control plane: {e}"}

    # 2) metrics plane
    metrics: dict[str, Any] = {}
    if cred is not None and region:
        try:
            metrics = collect_metrics(cred, rid, region, args.window_minutes)
        except Exception as e:  # noqa: BLE001
            metrics = {"_error": f"metrics plane: {e}"}
    elif cred is not None and not region:
        metrics = {"_error": "no region resolved; pass --region or --azure-auth"}

    # 3) data/runtime plane \u2014 inspect every event hub (or the one requested)
    if args.event_hub:
        hubs = [args.event_hub]
    else:
        hubs = list((control.get("event_hubs") or {}).keys())
    runtime_by_hub: dict[str, Any] = {}
    fqdn = args.fqdn or f"{ns}.servicebus.windows.net"
    if args.eh_auth != "none":
        for hub in hubs:
            try:
                if args.eh_auth == "connstr":
                    runtime_by_hub[hub] = collect_partition_runtime(
                        fqdn, hub, conn_str=args.eh_connstr)
                else:
                    runtime_by_hub[hub] = collect_partition_runtime(
                        fqdn, hub, cred=cred)
            except Exception as e:  # noqa: BLE001
                runtime_by_hub[hub] = {"_error": f"runtime plane: {e}"}
        if not hubs:
            report.add("runtime", "info", "런타임 평면 건너뜀",
                       "Event Hub를 확인할 수 없습니다. hub를 열거할 수 있도록 "
                       "--event-hub 또는 --azure-auth를 지정하세요.")

    # 4) checkpoint lag (optional) \u2014 auto-scan every consumer group present
    lag_list: Any = []
    if args.checkpoint_store and runtime_by_hub:
        try:
            lag_list = collect_all_checkpoint_lag(
                args.checkpoint_store, cred, fqdn, runtime_by_hub,
                consumer_group_filter=args.consumer_group)
        except Exception as e:  # noqa: BLE001
            lag_list = {"_error": f"checkpoint store: {e}"}

    evaluate(report, control, metrics, runtime_by_hub, lag_list, derived,
             args.max_connections, hubs)

    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "html":
        rendered = render_html(report)
    else:
        rendered = render_table(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"Output written to {args.output}")
    else:
        print(rendered)

    if args.exit_code:
        worst = report.worst_severity()
        return 2 if worst == "critical" else 1 if worst == "warning" else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
