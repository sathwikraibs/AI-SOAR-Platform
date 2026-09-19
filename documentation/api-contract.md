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
| severity    | string          | Yes      | One of: Low, Medium, High, Critical  |
| status      | string          | No       | Defaults to "Open" if not provided   |
| ip          | string or null  | No       | Related IP address                   |
| hash        | string or null  | No       | Related file/hash value              |
| timestamp   | string (ISO 8601 datetime) | Yes | e.g. "2026-09-20T10:30:00"       |

### Example Request
```json
{
  "source": "Windows",
  "description": "Multiple failed login attempts detected",
  "severity": "High",
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