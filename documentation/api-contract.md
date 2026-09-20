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
  "timestamp": "2026-09-20T10:30:00"
}
```

Note: `id` is generated automatically by the database and must not be sent in the request.
Note: `severity` in the response is the AI classifier's output — see the note above.

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
    "timestamp": "2026-09-20T10:30:00"
  }
]
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

## Changelog
- **Day 2 (Tejas):** `severity` changed from required to optional/ignored in the `POST /alerts` request body. It is now always assigned server-side by the AI classifier. Downstream stages (threat intel, frontend) should treat the `severity` returned by `GET`/`POST /alerts` as the source of truth.