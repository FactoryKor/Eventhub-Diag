**한국어** | [English](README.en.md)

# 🚀 eh_diagnose

**Azure Event Hubs 읽기 전용(read-only) 진단 프로그램**

Azure Event Hubs 환경을 위한 진단 도구입니다. `pg_diagnose` / `aks_diagnose` / `adx_diagnose`와 동일한 진단 도구 제품군의 일원이며, `aks_diagnose`에서 확립한 **인증 도메인 명시 분리** 설계 철학을 그대로 따릅니다.

- 👉 *Control Plane → Metrics → Runtime* 관점으로 분석합니다.
- 👉 *Consumer Lag / Throttling / Capacity Pressure* 를 진단합니다.
- 👉 Azure SRE Agent 및 MCP Tool 통합을 지원합니다.
- 👉 모든 동작은 **엄격히 read-only** 입니다. 이벤트를 send/receive하지 않고, keyslot·설정·checkpoint를 변경하지 않습니다.

주요 진단 항목:

| 📋 항목 | 📋 항목 |
|---|---|
| Throughput Unit(TU) 사용률 | Consumer Lag |
| Throttling 발생 여부 | Dead Consumer 감지 |
| Incoming / Outgoing 메시지 추이 | Auto-Inflate 설정 검증 |
| Capture 상태 | Partition 구성 |
| 네트워크 및 인증 오류 | Storage 기반 Checkpoint 상태 |

---

## 인증 도메인 (설계의 핵심)

Event Hubs 진단은 성격이 다른 3(+1)개의 접근 경로를 필요로 합니다. 이들을 하나로 뭉치지 않고 **명시적으로 분리**하는 것이 이 도구의 핵심 설계 결정입니다 — `aks_diagnose`가 "cluster 연결(kubeconfig)"과 "Azure/Entra 인증(`--azure-auth`)"을 분리한 것과 같은 이유입니다.

| # | 도메인 | 무엇을 읽나 | 인증 주체 | 플래그 | 필요 권한(RBAC) |
|---|--------|------------|-----------|--------|-----------------|
| 1 | **Control plane (ARM)** | namespace SKU, Auto-Inflate, partition 수, network 규칙, TLS, retention | Entra (`DefaultAzureCredential`) | `--azure-auth` | `Reader` (namespace scope) |
| 2 | **Metrics plane** | Azure Monitor 플랫폼 metric | 위와 **동일한** Entra 토큰, `MetricsClient` 2.x regional endpoint | (1과 공유) | `Monitoring Reader` |
| 3 | **Data / runtime plane** | 파티션 runtime 속성 (last enqueued sequence 등) | Event Hubs 자체 연결 | `--eh-auth {entra\|connstr}` | `Azure Event Hubs Data Receiver` **또는** connection string |
| 4 | **Checkpoint store** *(선택)* | consumer checkpoint offset → lag 계산 | Blob | `--checkpoint-store` | `Storage Blob Data Reader` |

**왜 분리하나.** 도메인 1·2는 Entra 토큰 하나로 묶이지만(둘 다 ARM/Monitor 평면), 도메인 3은 Event Hubs 데이터 평면이라 인증 주체가 근본적으로 다릅니다. 이 경계를 흐리면 "metric은 보이는데 partition은 못 읽는" 부분 실패의 원인을 진단자가 오해하게 됩니다. 도구가 각 도메인의 성공/실패를 **독립적으로** 보고하도록 설계했습니다.

```text
                    ┌───────────────────────── Entra ID ─────────────────────────┐
   --azure-auth ──▶ │  (1) ARM 제어 평면        (2) Azure Monitor metrics 평면    │
                    └────────────────────────────────────────────────────────────┘
   --eh-auth    ──▶ (3) Event Hubs 데이터 평면  (Data Receiver role | connstr)
   --checkpoint ──▶ (4) Blob checkpoint store   (Storage Blob Data Reader)
```

---

## ⚙️ 설치

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> [!NOTE]
> **metrics 패키지 주의.** `azure-monitor-query` **2.x**에서 metrics가 분리되어 `MetricsClient`는 이제 **`azure-monitor-querymetrics`**(모듈 `azure.monitor.querymetrics`)에 있습니다. 코드는 2.x-우선 / 1.x-폴백으로 자동 처리합니다(`_load_metrics_sdk`). 1.x 환경이면 `azure-monitor-query>=1.2,<2`를 쓰면 됩니다.

각 라이브러리는 **선택적**으로 로드됩니다. 특정 라이브러리가 없으면 해당 평면만 `info`로 skip되고 나머지는 정상 동작합니다.

> [!TIP]
> **Windows note.** Python stdout은 Windows에서 cp1252가 기본이라 table 렌더러가 `UnicodeEncodeError`를 낼 수 있습니다. 실행 전 `$env:PYTHONIOENCODING="utf-8"` 를 설정하세요.

---

## 🧰 사용법

```bash
# 전체 평면 (Entra) — 가장 일반적
python eh_diagnose.py \
  --resource-id "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.EventHub/namespaces/<ns>" \
  --azure-auth --eh-auth entra --event-hub orders --format table

# 개별 인자로 지정
python eh_diagnose.py \
  --subscription <sub> --resource-group <rg> --namespace ehns-prod-krc-001 \
  --azure-auth --region koreacentral --event-hub orders

# connection string으로 데이터 평면 인증 (Entra Data Receiver role이 없을 때)
python eh_diagnose.py --namespace ehns-prod-krc-001 --azure-auth \
  --eh-auth connstr --eh-connstr "Endpoint=sb://...;SharedAccessKeyName=...;..."

# consumer lag까지 (checkpoint store 경로)
python eh_diagnose.py --resource-id <rid> --azure-auth --event-hub orders \
  --checkpoint-store "https://<st>.blob.core.windows.net/eh-checkpoints" \
  --consumer-group "$Default" --lag-warn 5000 --lag-crit 50000

# metric만 빠르게 (데이터 평면 생략)
python eh_diagnose.py --resource-id <rid> --azure-auth --region koreacentral --eh-auth none

# JSON 출력 + CI용 exit code (crit=2, warn=1)
python eh_diagnose.py --resource-id <rid> --azure-auth --format json --exit-code
```

`--region`을 생략하면 `--azure-auth`로 조회한 namespace `location`에서 자동 유도합니다.

> [!NOTE]
> `--event-hub`를 생략하면 namespace의 **모든 Event Hub를 개별로** 진단하고, `--checkpoint-store` 지정 시 checkpoint store에 존재하는 **모든 consumer group을 자동 스캔**합니다. `--event-hub`·`--consumer-group`은 결과를 좁히는 **선택적 필터**입니다.

---

## 🧰 진단 규칙 (Diagnostic Rules)

`eh_diagnose`는 `adx_diagnose`와 동일하게 **단일 임계값 테이블 기반(rule-driven)** 으로 동작합니다. 모든 진단 결과는 다음 두 규칙 세트에서 생성됩니다.

- `METRIC_RULES`
- `DERIVED_DEFAULTS`

조직 표준에 맞춰 임계값만 조정하면 진단 정책을 쉽게 변경할 수 있습니다.

### Metric 기반 규칙 (`METRIC_RULES`)

| Category | Metric (REST) | 집계 | Warning | Critical | 의미 / 조치 |
|----------|---------------|------|---------|----------|-------------|
| `throttling` | `ThrottledRequests` | Total | > 1 | > 100 | 용량 초과. Auto-Inflate 활성화 또는 TU/PU 증설 |
| `server_errors` | `ServerErrors` | Total | > 1 | > 50 | 서비스측 실패. throttling과 상관 확인 |
| `user_errors` | `UserErrors` | Total | > 100 | > 1000 | 클라이언트측(4xx류). 인증/엔티티명/요청형식 |
| `quota_errors` | `QuotaExceededErrors` | Total | > 1 | > 50 | 쿼터 초과. Size·ActiveConnections를 tier 한도와 대조 |
| `capture_backlog` | `CaptureBacklog` | Average | > 1 | > 1000 | Capture 적체. 대상 Storage 권한/처리량 확인 |

> [!TIP]
> 위 규칙은 Azure Monitor Metrics 기반으로 평가됩니다. metric은 `EntityName` dimension으로 **Event Hub별로 분해**되어 hub마다 개별 finding이 생성됩니다.

### 파생 규칙 (`DERIVED_DEFAULTS`)

런타임 데이터 및 메트릭을 조합하여 계산되는 규칙입니다.

| Category | Signal | Warning | Critical | 계산식 / 비고 |
|----------|--------|---------|----------|---------------|
| `backlog` | Egress / Ingress 비율 | < 0.90 | < 0.50 | Event Hub별 `OutgoingMessages / IncomingMessages` (window total). **consumer group 수로 fan-out 정규화**(`per_group_ratio = ratio / group수`). egress는 group 단위로 분리 불가하므로 group별 지연은 `consumer_lag`가 결정적 |
| `partition_skew` | retained-events 편중 | ≥ 2.0× | ≥ 5.0× | 파티션별 `max / mean` retained events |
| `connections` | 연결 포화도 | ≥ 80% | ≥ 95% | `ActiveConnections(max) / --max-connections` |
| `consumer_lag` | 최악 파티션 lag | ≥ `--lag-warn` | ≥ `--lag-crit` | `last_enqueued_seq − checkpoint_seq` |

> [!TIP]
> `consumer_lag`는 Azure Monitor Metric이 아닌 **Runtime + Checkpoint Store** 정보를 활용하여 계산됩니다.

### 설정 audit 규칙 (Configuration Audit)

Control Plane 설정을 검사하여 운영 모범 사례(Best Practice) 위반 여부를 확인합니다.

| 조건 | Severity | 근거 |
|------|----------|------|
| Standard tier인데 Auto-Inflate 비활성 | Warning | 스파이크 흡수 불가 → throttling 유발 |
| `publicNetworkAccess = Enabled` | Warning | 프로덕션은 Private Endpoint 권장 |
| `minimumTlsVersion < 1.2` | Critical | 취약 TLS 강제 |
| `disableLocalAuth = false` (SAS 허용) | Info | Entra-only 인증 권장 |
| Partition 수 보고 | Info | Basic/Standard는 생성 후 변경 불가 → 생성 시점 right-sizing 필요 |

---

## 🧰 진단 카테고리 (Diagnostic Categories)

| Category | 검사 항목 |
|----------|-----------|
| Capacity | Throughput Unit 사용률 · Auto-Inflate 구성 · Ingress/Egress 사용률 |
| Throttling | Throttled Requests · Server Busy 예외 · Quota 초과 조건 |
| Consumer Lag | 파티션 단위 lag · Consumer Group 상태 · 오래된 checkpoint |
| Availability | Receiver 연결 상태 · Sender 연결 상태 · 오류율 추이 |
| Capture | Capture 활성 상태 · Storage write 실패 |
| Partition | Hot partition · 파티션 불균형 |
| Checkpoint | Checkpoint 갱신 지연 · Dead consumer 감지 |

---

## 🧰 Consumer Lag 탐지

Consumer Lag은 Event Hubs 환경에서 가장 중요한 운영 지표 중 하나입니다. `eh_diagnose`는 Azure Monitor Metrics에 직접 의존하지 않고 **Runtime + Checkpoint 기반 방식(Approach B)** 을 우선적으로 사용합니다.

### Approach A — Azure Monitor Consumer Lag Metric (제한사항)

AMQP consumer는 해당 consumer group에 **활성 receiver가 있을 때만** lag이 emit되고, Kafka consumer group은 마지막 offset commit이 **retention보다 오래되면** 더 이상 emit되지 않습니다. 즉 "lag metric 부재"가 곧 "lag 없음"이 아니라 "receiver가 죽었거나 commit이 오래됨"일 수 있습니다. metric 이름·가용성이 tier/시점별로 다를 수 있으므로 이 도구는 A를 하드코딩하지 않습니다.

### Approach B — Runtime + Checkpoint 계산 (권장)

`eh_diagnose`의 기본 방식입니다. Checkpoint Store가 제공되면 **실제 데이터 기반**으로 Consumer Lag을 계산합니다.

**계산식**

```text
lag = last_enqueued_sequence_number (데이터 평면)
    − checkpoint blob의 sequencenumber (Blob)
```
(파티션별로 계산)

**Checkpoint blob 경로**

`{fqdn}/{eventhub}/{consumer_group}/checkpoint/{partition_id}`  *(SDK가 소문자화)*

checkpoint store를 훑어 이 경로에 존재하는 **모든 (Event Hub × consumer group)** 조합을 자동으로 찾아 각각의 lag을 계산합니다. `--consumer-group`으로 특정 그룹만 필터링할 수 있습니다.

> [!TIP]
> metric이 사라지는 **dead/idle consumer** 상황도 잡아냅니다.

---

## 🧰 출력 스키마 (Output Schema)

`eh_diagnose`는 PostgreSQL 진단 도구(`pg_diagnose`)와 동일한 `category` + `severity` 스키마를 사용합니다.

### 저장 방식

`eh_diagnose`는 결과를 **표준출력(stdout)** 으로만 출력합니다(HTML·스냅샷 파일 없음).

| 모드 | 내용 |
|---|---|
| `--format table` (기본) | 사람이 읽기 쉬운 텍스트 테이블 |
| `--format json` | `checks[]` 스키마 JSON (SRE Agent / MCP 연동용) |

- `--exit-code` 지정 시 CI용 종료코드 반환(critical=2, warning=1, 그 외 0)
- 파일로 남기려면 리다이렉트하세요:
  ```powershell
  python eh_diagnose.py --resource-id <rid> --azure-auth --format json > result.json
  ```

> secret/PII/prompt-injection은 JSON 출력 시 자동 마스킹됩니다.

### Severity Levels

| Severity | 의미 |
|----------|------|
| `critical` | 즉시 조치 필요 |
| `warning` | 조사 및 최적화 권장 |
| `info` | 정보성 발견 |
| `ok` | 정상 / 이슈 없음 |

### 샘플 출력

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

## 🧰 MCP / Azure SRE Agent 통합

기존 `mcp_server.py`에 thin wrapper 한 줄로 추가됩니다 (pg/aks/adx와 동일 패턴, `__file__`-anchored path + `sys.executable`).

```python
# mcp_server.py (발췌)
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

Azure SRE Agent에서 "이 namespace가 throttle 나는데 왜?" 류 질의에 그대로 응답하는 진단 surface가 됩니다. Managed Identity를 SRE Agent에 부여하고 아래 RBAC role을 namespace/storage scope로 할당하면 됩니다.

- **Event Hubs Namespace**: `Azure Event Hubs Data Owner` 또는 `Data Receiver` / `Data Sender`
- **Azure Monitor**: `Monitoring Reader`
- **Checkpoint Storage**: `Storage Blob Data Reader`

---

## 정확성 주의

- 메트릭 REST 이름은 Microsoft Learn "Monitoring data reference for Azure Event Hubs" 기준입니다. 조직 namespace에서 `az monitor metrics list-definitions --resource <rid>`로 실제 노출 metric을 한 번 대조하기를 권장합니다.
- Azure Monitor metric은 90일 보관되며, 차트는 한 번에 30일까지만 시각화됩니다.
- partition 수 변경 가능 여부는 tier·시점별로 다르므로(Standard는 불변), 고객 회신 전 Learn에서 재확인하세요.
