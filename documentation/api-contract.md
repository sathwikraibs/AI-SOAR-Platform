# AI-SOAR Platform — API Contract

This document defines the exact request/response format for the alerts API.
All other modules (AI classifier, threat intel, frontend) must follow this contract.

## Base URL
http://localhost:8000

## 1. POST /alerts
Creates a new alert and saves it to the database.

### Request Body (JSON)
| Field       | Type            | Required | Notes                                |
|-------------|-----------------|----------|---------------------------------------|
| source      | string          | Yes      | Where the alert came from            |
| description | string          | Yes      | Description of the security event    |
| severity    | string or null  | No       | Ignored if sent — see note below     |
| status      | string          | No       | Defaults to "Open" if not provided   |
| ip          | string or null  | No       | Related IP address                   |
| hash        | string or null  | No       | Related file/hash value              |
| timestamp   | string (ISO 8601 datetime) | Yes | e.g. "2026-09-20T10:30:00"       |

**Severity is AI-assigned (Day 2 update):** the alert coming in is a *raw*
alert, so the caller should not need to know its severity in advance — the
AI classifier (`ai-model/`) scores every alert on arrival and the response
always carries the model's severity, not the request's. The `severity`
field is accepted for backward compatibility (and to keep the request body
self-describing) but any value sent in it is overwritten server-side.

### Example Request
```json
{
  "source": "Windows",
  "description": "Multiple failed login attempts detected",
  "status": "Open",
  "ip": "192.168.1.10",
  "hash": null,
  "timestamp": "2026-09-20T10:30:00"
}
```

### Example Response (200 OK)
```json
{
  "id": 1,
  "source": "Windows",
  "description": "Multiple failed login attempts detected",
  "severity": "High",
  "status": "Open",
  "ip": "192.168.1.10",
  "hash": null,
  "timestamp": "2026-09-20T10:30:00",
  "ip_reputation": "Suspicious",
  "hash_reputation": "Unknown",
  "threat_score": 27,
  "mitre_technique": "T1110 - Brute Force",
  "risk_score": 50,
  "response_action": "Credential / Brute-Force Response",
  "response_playbook": "[{\"action\": \"Lock affected user account\", \"auto\": false}, {\"action\": \"Block source IP at the firewall\", \"auto\": false}, {\"action\": \"Force password reset on next login\", \"auto\": false}, {\"action\": \"Notify SOC analyst\", \"auto\": true}]",
  "response_status": "pending_approval"
}
```

Note: `id` is generated automatically by the database and must not be sent in the request.
Note: `severity` in the response is the AI classifier's output — see the note above.
Note: `ip_reputation`, `hash_reputation`, `threat_score`, `mitre_technique`, `risk_score`, `response_action`, `response_playbook` and `response_status` are all assigned server-side (Day 3) — see the Threat Intelligence & Automated Response section below.

## 2. GET /alerts
Returns an array of all saved alerts, read directly from the database.

### Example Response (200 OK)
```json
[
  {
    "id": 1,
    "source": "Windows",
    "description": "Multiple failed login attempts detected",
    "severity": "High",
    "status": "Open",
    "ip": "192.168.1.10",
    "hash": null,
    "timestamp": "2026-09-20T10:30:00",
    "ip_reputation": "Suspicious",
    "hash_reputation": "Unknown",
    "threat_score": 27,
    "mitre_technique": "T1110 - Brute Force",
    "risk_score": 50,
    "response_action": "Credential / Brute-Force Response",
    "response_playbook": "[{\"action\": \"Lock affected user account\", \"auto\": false}, {\"action\": \"Block source IP at the firewall\", \"auto\": false}, {\"action\": \"Force password reset on next login\", \"auto\": false}, {\"action\": \"Notify SOC analyst\", \"auto\": true}]",
    "response_status": "pending_approval"
  }
]
```

## 3. POST /alerts/{alert_id}/approve
Human-in-the-loop step. Approves and "runs" (logs — simulated, see below) an
alert's destructive response steps that were held back at ingestion
(`auto: false` steps in `response_playbook`, e.g. isolate host, block IP,
lock account). Only valid while `response_status` is `"pending_approval"`.

### Response (200 OK)
```json
{ "alert_id": 1, "status": "approved_and_executed", "executed_steps": ["Lock affected user account", "Block source IP at the firewall", "Force password reset on next login"] }
```
- `404` if `alert_id` doesn't exist.
- `409` if the alert has nothing pending (already `auto_resolved`, `approved_and_executed`, or `rejected`).

## 4. POST /alerts/{alert_id}/reject
Analyst dismisses the pending destructive steps (e.g. confirmed false
positive) without running them. Sets `response_status` to `"rejected"`.
Same `404`/`409` rules as `/approve`.

### Response (200 OK)
```json
{ "alert_id": 1, "status": "rejected" }
```

## Severity values (fixed list)
- Low
- Medium
- High
- Critical

## Status values
- Open (default). Additional statuses may be agreed on later; document any new value here when added.

## Database
- Engine: SQLite
- File location: `database/soar.db`
- Table: `alerts`

## AI Classifier (Day 2)
- Code: `ai-model/` (`generate_dataset.py`'s output lives in `dataset/alerts_dataset.csv`, trained by `ai-model/train_classifier.py`, saved model at `ai-model/severity_model.joblib`)
- `backend/main.py` calls `ai-model/classifier.py:predict_severity()` on every `POST /alerts` and stores its result as `severity`
- If `ai-model/severity_model.joblib` is missing (e.g. not yet trained on a fresh checkout), the backend falls back to `severity = "Medium"` and prints a warning instead of failing the request

## Threat Intelligence & Automated Response (Day 3)
Pipeline order on every `POST /alerts`: **AI severity classifier -> threat-intel enrichment -> composite risk score -> automated response engine**.

- Code: `threat-intelligence/threat_intel.py` (`enrich_alert()`), `threat-intelligence/mitre_mapping.py`, `response-engine/response_engine.py` (`compute_risk_score()` / `decide_response()` / `execute_response()` / `approve_pending_steps()`), `response-engine/playbooks.py`
- `backend/main.py` calls `enrich_alert()` right after the severity classifier, then `compute_risk_score()` and `decide_response()`, and stores everything on the alert.
- New response fields (all server-assigned, ignore any client-sent value):
  | Field | Type | Notes |
  |---|---|---|
  | `ip_reputation` | string | `"Clean"` \| `"Suspicious"` \| `"Malicious"` \| `"Unknown"` (from AbuseIPDB, or a heuristic fallback if `ABUSEIPDB_API_KEY` isn't set) |
  | `hash_reputation` | string | same scale, from VirusTotal / heuristic fallback if `VIRUSTOTAL_API_KEY` isn't set |
  | `threat_score` | int | 0–100, `max(ip_score, hash_score)` |
  | `mitre_technique` | string | `"<ATT&CK id> - <name>"`, keyword-mapped from `source`/`description`; `"T1000-UNK - Unmapped / Needs Manual Triage"` if nothing matches |
  | `risk_score` | int | 0–100 composite score, 60% severity + 40% `threat_score` — a continuous priority ranking (Splunk-style "Risk-Based Alerting"), finer-grained than the 4-bucket `severity` alone. Sort by this on the dashboard's triage queue. |
  | `response_action` | string | Name of the playbook that fired (see `response-engine/playbooks.py`) |
  | `response_playbook` | string | JSON-encoded ordered list of `{"action": str, "auto": bool}` steps. `auto: true` steps (logging, watchlisting, notifying) already ran; `auto: false` steps (isolate host, block IP, lock account, quarantine, kill process) are destructive and were **not** run — they wait for analyst approval. All actions are simulated (logged) — nothing here touches a real firewall/EDR. |
  | `response_status` | string | `"auto_resolved"` (nothing destructive was needed) \| `"pending_approval"` (destructive steps waiting on an analyst) \| `"approved_and_executed"` \| `"rejected"` |
- **Why the approval gate:** real SOC teams don't let automation auto-isolate a production host or lock out a VIP account on an AI/threat-intel call that might be a false positive — the blast radius is too high. So only reversible, low-risk playbook steps run immediately; anything destructive sits in `pending_approval` until a human calls `/approve` or `/reject` (endpoints 3 and 4 below). This is what real SOAR products (Splunk SOAR, Palo Alto XSOAR) call a manual/analyst approval task in the playbook.
- **Why the risk score:** two `"High"` severity alerts aren't equally urgent — one against a clean IP and one AbuseIPDB already flags at 95% confidence are different risks. `risk_score` gives the dashboard a single sortable number instead of just 4 severity buckets.
- **IOC lookup caching:** `threat_intel.py` caches AbuseIPDB/VirusTotal results per IP/hash for 15 minutes (in-memory). AbuseIPDB's and VirusTotal's free tiers cap requests/day; a noisy IP or common malware hash can otherwise appear dozens of times an hour and burn the quota. Cache hits are logged nowhere (silent, sub-millisecond) — only misses hit the real API.
- API keys are optional. Set `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` in a `.env` file at the repo root (gitignored) to hit the real APIs; otherwise enrichment uses a deterministic heuristic so the pipeline still works end-to-end without any keys configured.
- `database/database.py:migrate_schema()` auto-adds these columns to an existing `database/soar.db` on startup, so pulling this change won't break a teammate's existing local DB.

## Changelog
- **Day 2 (Tejas):** `severity` changed from required to optional/ignored in the `POST /alerts` request body. It is now always assigned server-side by the AI classifier. Downstream stages (threat intel, frontend) should treat the `severity` returned by `GET`/`POST /alerts` as the source of truth.
- **Day 3 (Nanda):** Added `ip_reputation`, `hash_reputation`, `threat_score`, `mitre_technique`, `risk_score`, `response_action`, `response_playbook`, `response_status` to the alert response (all server-assigned — see section above), plus `POST /alerts/{id}/approve` and `POST /alerts/{id}/reject` for the human-in-the-loop approval workflow. Frontend/Docker stage (Sathwik): the dashboard should (a) sort/highlight by `risk_score`, (b) show an "Approve"/"Reject" action on alerts with `response_status == "pending_approval"` calling the new endpoints, and (c) render `response_playbook`'s `auto` steps vs. pending ones differently (e.g. checkmark vs. a button). Nothing about the existing request fields or Day 2 fields changed.