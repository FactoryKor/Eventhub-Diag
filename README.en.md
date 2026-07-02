[한국어](README.md) | **English**

# 🚀 eh_diagnose

**A read-only diagnostic tool for Azure Event Hubs.**

Part of the Azure diagnostic tool suite (`pg_diagnose` / `aks_diagnose` / `adx_diagnose`), it follows the **explicit separation of authentication domains** design established in `aks_diagnose`.

- 👉 Analyzes from a *Control Plane → Metrics → Runtime* perspective.
- 👉 Diagnoses *Consumer Lag / Throttling / Capacity Pressure*.
- 👉 Supports Azure SRE Agent and MCP Tool integration.
- 👉 Every operation is **strictly read-only**. It never sends/receives events or modifies keyslots, configuration, or checkpoints.

Key diagnostic areas:

| 📋 Area | 📋 Area |
|---|---|
| Throughput Unit (TU) utilization | Consumer Lag |
| Throttling occurrence | Dead consumer detection |
| Incoming / Outgoing message trends | Auto-Inflate configuration check |
| Capture status | Partition configuration |
| Network & authentication errors | Storage-based checkpoint status |

---

## Authentication Domains (Core Design)

Event Hubs diagnostics require three (+1 optional) distinct access paths. The core design decision of this tool is to **separate them explicitly** rather than merging them into one — the same reason `aks_diagnose` separates "cluster connection (kubeconfig)" from "Azure/Entra auth (`--azure-auth`)".

| # | Domain | What it reads | Auth principal | Flag | Required RBAC |
|---|--------|---------------|----------------|------|---------------|
| 1 | **Control plane (ARM)** | namespace SKU, Auto-Inflate, partition count, network rules, TLS, retention | Entra (`DefaultAzureCredential`) | `--azure-auth` | `Reader` (namespace scope) |
| 2 | **Metrics plane** | Azure Monitor platform metrics | **Same** Entra token as above, `MetricsClient` 2.x regional endpoint | (shared with 1) | `Monitoring Reader` |
| 3 | **Data / runtime plane** | partition runtime properties (last enqueued sequence, etc.) | Event Hubs native connection | `--eh-auth {entra\|connstr}` | `Azure Event Hubs Data Receiver` **or** connection string |
| 4 | **Checkpoint store** *(optional)* | consumer checkpoint offset → lag calculation | Blob | `--checkpoint-store` | `Storage Blob Data Reader` |

**Why separate them.** Domains 1 and 2 are bound by a single Entra token (both are ARM/Monitor planes), but domain 3 is the Event Hubs data plane, so its auth principal is fundamentally different. Blurring this boundary causes the diagnostician to misunderstand partial-failure causes such as "metrics are visible but partitions can't be read." The tool is designed to report the success/failure of each domain **independently**.

```text
                    ┌───────────────────────── Entra ID ─────────────────────────┐
   --azure-auth ──▶ │  (1) ARM control plane    (2) Azure Monitor metrics plane   │
                    └────────────────────────────────────────────────────────────┘
   --eh-auth    ──▶ (3) Event Hubs data plane   (Data Receiver role | connstr)
   --checkpoint ──▶ (4) Blob checkpoint store   (Storage Blob Data Reader)
```

---

## ⚙️ Installation

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> [!NOTE]
> **Metrics package note.** In `azure-monitor-query` **2.x**, metrics were split out, so `MetricsClient` now lives in **`azure-monitor-querymetrics`** (module `azure.monitor.querymetrics`). The code handles this automatically with a 2.x-first / 1.x-fallback (`_load_metrics_sdk`). For a 1.x environment, use `azure-monitor-query>=1.2,<2`.

Each library is loaded **optionally**. If a library is missing, only that plane is skipped as `info` while the rest keep working.

> [!TIP]
> **Windows note.** Python stdout defaults to cp1252 on Windows, so the table renderer may raise `UnicodeEncodeError`. Set `$env:PYTHONIOENCODING="utf-8"` before running.

---

## 🧰 Usage

```bash
# All planes (Entra) — most common
python eh_diagnose.py \
  --resource-id "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.EventHub/namespaces/<ns>" \
  --azure-auth --eh-auth entra --event-hub orders --format table

# Specify individual arguments
python eh_diagnose.py \
  --subscription <sub> --resource-group <rg> --namespace ehns-prod-krc-001 \
  --azure-auth --region koreacentral --event-hub orders

# Data-plane auth via connection string (when there is no Entra Data Receiver role)
python eh_diagnose.py --namespace ehns-prod-krc-001 --azure-auth \
  --eh-auth connstr --eh-connstr "Endpoint=sb://...;SharedAccessKeyName=...;..."

# Include consumer lag (checkpoint store path)
python eh_diagnose.py --resource-id <rid> --azure-auth --event-hub orders \
  --checkpoint-store "https://<st>.blob.core.windows.net/eh-checkpoints" \
  --consumer-group "$Default" --lag-warn 5000 --lag-crit 50000

# Metrics only, fast (skip data plane)
python eh_diagnose.py --resource-id <rid> --azure-auth --region koreacentral --eh-auth none

# JSON output + CI exit code (crit=2, warn=1)
python eh_diagnose.py --resource-id <rid> --azure-auth --format json --exit-code
```

If `--region` is omitted, it is derived automatically from the namespace `location` retrieved via `--azure-auth`.

> [!NOTE]
> If `--event-hub` is omitted, **every event hub** in the namespace is diagnosed individually, and when `--checkpoint-store` is set, **every consumer group** present in the checkpoint store is auto-scanned. `--event-hub` / `--consumer-group` act as **optional filters** to narrow the results.

---

## 🧰 Diagnostic Rules

Like `adx_diagnose`, `eh_diagnose` is **rule-driven from a single threshold table**. All diagnostic results are generated from two rule sets:

- `METRIC_RULES`
- `DERIVED_DEFAULTS`

You can easily change the diagnostic policy by adjusting only the thresholds to match your organization's standards.

### Metric-Based Rules (`METRIC_RULES`)

| Category | Metric (REST) | Aggregation | Warning | Critical | Meaning / Recommendation |
|----------|---------------|-------------|---------|----------|--------------------------|
| `throttling` | `ThrottledRequests` | Total | > 1 | > 100 | Capacity pressure. Enable Auto-Inflate or increase TU/PU. |
| `server_errors` | `ServerErrors` | Total | > 1 | > 50 | Service-side failures. Correlate with throttling. |
| `user_errors` | `UserErrors` | Total | > 100 | > 1000 | Client-side (4xx) issues: auth, entity name, request format. |
| `quota_errors` | `QuotaExceededErrors` | Total | > 1 | > 50 | Quota exhaustion. Compare Size / ActiveConnections against tier limits. |
| `capture_backlog` | `CaptureBacklog` | Average | > 1 | > 1000 | Capture backlog. Verify target Storage permissions and throughput. |

> [!TIP]
> The rules above are evaluated based on Azure Monitor Metrics. Metrics are **split per event hub** via the `EntityName` dimension, producing an individual finding per hub.

### Derived Rules (`DERIVED_DEFAULTS`)

Rules computed by combining runtime data and metrics.

| Category | Signal | Warning | Critical | Formula / Notes |
|----------|--------|---------|----------|-----------------|
| `backlog` | Egress / Ingress ratio | < 0.90 | < 0.50 | Per-hub `OutgoingMessages / IncomingMessages` (window total). **Normalized by consumer-group count** (`per_group_ratio = ratio / groups`). Egress cannot be split per consumer group, so `consumer_lag` is authoritative for per-group delay. |
| `partition_skew` | Retained-event imbalance | ≥ 2.0× | ≥ 5.0× | `max / mean` retained events per partition |
| `connections` | Connection saturation | ≥ 80% | ≥ 95% | `ActiveConnections(max) / --max-connections` |
| `consumer_lag` | Worst-partition lag | ≥ `--lag-warn` | ≥ `--lag-crit` | `last_enqueued_seq − checkpoint_seq` |

> [!TIP]
> `consumer_lag` is calculated using **Runtime + Checkpoint Store** information, not an Azure Monitor metric.

### Configuration Audit Rules

Inspects Control Plane settings to check for operational best-practice violations.

| Condition | Severity | Rationale |
|-----------|----------|-----------|
| Auto-Inflate disabled on Standard tier | Warning | Cannot absorb traffic spikes → causes throttling |
| `publicNetworkAccess = Enabled` | Warning | Private Endpoint recommended for production |
| `minimumTlsVersion < 1.2` | Critical | Weak TLS version permitted |
| `disableLocalAuth = false` (SAS enabled) | Info | Entra-only authentication recommended |
| Partition count reported | Info | Basic/Standard cannot change partition count after creation → right-size at creation time |

---

## 🧰 Diagnostic Categories

| Category | Checks |
|----------|--------|
| Capacity | Throughput Unit utilization · Auto-Inflate configuration · Ingress/Egress utilization |
| Throttling | Throttled Requests · Server Busy exceptions · Quota exceeded conditions |
| Consumer Lag | Partition-level lag · Consumer Group health · Stale checkpoints |
| Availability | Receiver connectivity · Sender connectivity · Error rate trends |
| Capture | Capture enabled status · Storage write failures |
| Partition | Hot partitions · Partition imbalance |
| Checkpoint | Checkpoint update delays · Dead consumer detection |

---

## 🧰 Consumer Lag Detection

Consumer lag is one of the most important operational metrics in an Event Hubs environment. `eh_diagnose` does not depend directly on Azure Monitor Metrics; it prefers the **Runtime + Checkpoint approach (Approach B)**.

### Approach A — Azure Monitor Consumer Lag Metric (Limitations)

An AMQP consumer emits lag **only when there is an active receiver** in that consumer group, and a Kafka consumer group stops emitting once the last offset commit is **older than retention**. In other words, "no lag metric" does not mean "no lag" — it may mean "the receiver died or the commit is stale." Because metric names/availability can vary by tier and point in time, this tool does not hardcode Approach A.

### Approach B — Runtime + Checkpoint Calculation (Recommended)

This is the default method of `eh_diagnose`. When a Checkpoint Store is provided, it calculates Consumer Lag based on **actual data**.

**Formula**

```text
lag = last_enqueued_sequence_number (data plane)
    − checkpoint blob's sequencenumber (Blob)
```
(calculated per partition)

**Checkpoint blob path**

`{fqdn}/{eventhub}/{consumer_group}/checkpoint/{partition_id}`  *(lower-cased by the SDK)*

The tool scans the checkpoint store and automatically finds **every (event hub × consumer group)** pair present under this path, computing lag for each. Use `--consumer-group` to filter to a specific group.

> [!TIP]
> It also catches **dead/idle consumer** situations where the metric disappears.

---

## 🧰 Output Schema

`eh_diagnose` uses the same `category` + `severity` schema as the PostgreSQL diagnostic tool (`pg_diagnose`).

### Saving

`eh_diagnose` prints results to **stdout** only (no HTML/snapshot files).

| Mode | Content |
|---|---|
| `--format table` (default) | Human-readable text table |
| `--format json` | `checks[]` schema JSON (for SRE Agent / MCP) |

- With `--exit-code`, returns a CI exit code (critical=2, warning=1, otherwise 0)
- To persist to a file, redirect:
  ```powershell
  python eh_diagnose.py --resource-id <rid> --azure-auth --format json > result.json
  ```

> secret/PII/prompt-injection are masked automatically in JSON output.

### Severity Levels

| Severity | Meaning |
|----------|---------|
| `critical` | Immediate action required |
| `warning` | Investigation and optimization recommended |
| `info` | Informational finding |
| `ok` | Healthy / No issues detected |

### Sample Output

```json
{
  "tool": "eh_diagnose",
  "version": "1.0.0",
  "namespace": "ehns-prod-krc-001",
  "event_hub": "orders",
  "generated_at": "2026-07-01T00:36:51+00:00",
  "window": "last 60m",
  "checks": [
    {
      "category": "throttling",
      "severity": "critical",
      "title": "Requests throttled (capacity pressure) — orders",
      "detail": "[orders] ThrottledRequests (total)=1500 over window. Enable Auto-Inflate or increase throughput capacity.",
      "evidence": {
        "event_hub": "orders",
        "metric": "ThrottledRequests",
        "value": 1500,
        "warn": 1,
        "crit": 100
      }
    }
  ],
  "worst_severity": "critical"
}
```

---

## 🧰 MCP / Azure SRE Agent Integration

Added to an existing `mcp_server.py` with a one-line thin wrapper (same pattern as pg/aks/adx: `__file__`-anchored path + `sys.executable`).

```python
# mcp_server.py (excerpt)
@mcp.tool()
def eh_diagnose(resource_id: str, event_hub: str = "",
                window_minutes: int = 60) -> str:
    args = [sys.executable, os.path.join(HERE, "eh_diagnose.py"),
            "--resource-id", resource_id, "--azure-auth",
            "--eh-auth", "entra", "--format", "json",
            "--window-minutes", str(window_minutes)]
    if event_hub:
        args += ["--event-hub", event_hub]
    return subprocess.run(args, capture_output=True, text=True,
                          encoding="utf-8").stdout
```

It becomes a diagnostic surface that answers questions like "why is this namespace throttling?" directly in Azure SRE Agent. Grant a Managed Identity to the SRE Agent and assign the RBAC roles below at the namespace/storage scope:

- **Event Hubs Namespace**: `Azure Event Hubs Data Owner`, or `Data Receiver` / `Data Sender`
- **Azure Monitor**: `Monitoring Reader`
- **Checkpoint Storage**: `Storage Blob Data Reader`

---

## Accuracy Notes

- Metric REST names follow Microsoft Learn "Monitoring data reference for Azure Event Hubs." It is recommended to cross-check the actually exposed metrics on your namespace once with `az monitor metrics list-definitions --resource <rid>`.
- Azure Monitor metrics are retained for 90 days, and charts visualize up to 30 days at a time.
- Whether the partition count can be changed varies by tier and point in time (Standard is immutable), so re-verify on Learn before responding to a customer.
