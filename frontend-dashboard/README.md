# SOAR Dashboard

Next.js/React dashboard for the AI-SOAR platform. Talks to the FastAPI
backend in `../backend/main.py`.

## Running

```bash
pnpm install   # or npm install
pnpm dev       # or npm run dev
```

Make sure the backend is running first (from the repo root):

```bash
uvicorn backend.main:app --reload
```

By default the dashboard calls `http://localhost:8000`. To point it
elsewhere, copy `.env.example` to `.env.local` and set
`NEXT_PUBLIC_API_BASE`.

## What's wired to the real backend vs. still a demo

| Tab | Status |
|---|---|
| Overview | Real — `GET /alerts`, `GET /incidents` |
| Alerts | Real — `GET /alerts` |
| Incidents | Real — `GET /incidents` |
| Investigations | Real — `GET /threat-intel/lookup` |
| Global Threat Map | Real — `GET /threat-intel/geo` |
| Assets | Real — `GET /assets` (alert-derived rows, registered assets and Sysmon endpoint-agent devices), refreshed every 5 s; the *Connected Endpoints* panel uses `GET /agents`, `GET /agents/{host}/events` and the monitoring ON/OFF switches (`GET/POST /settings/monitoring`, `POST /agents/{host}/monitoring`); the table has a MONITORING column |
| Playbooks | Real — `GET /playbooks` (the actual catalog from `response-engine/playbooks.py`, with real trigger counts from stored alerts) |
| Threat Intelligence (table) | Real — `GET /threat-intel/iocs` (every distinct IP/hash seen across stored alerts) |
| Response Center | Real — action tiles computed from `GET /alerts`; "Recent Actions" reads `GET /audit` filtered to approve/reject rows |
| Audit | Real — `GET /audit` (a real `audit_log` table, written on every alert ingestion and every approve/reject) |
| Integrations | Real — `GET /integrations/status` (whether `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` / `SOAR_SLACK_WEBHOOK_URL` are actually configured) |
| SSH / Sessions (connect form) | Real — `POST /ssh/connect` (runs a fixed, read-only diagnostic: `whoami` / `hostname` / `uptime` — see `backend/ssh_manager.py` for why it doesn't accept an arbitrary command) |
| IP Blocklist | Real — `GET /blocklist`, `GET /blocklist/check?ip=`, the auto-block switch (`GET/POST /settings/vpn-block`), the Add IP/range form (`GET/POST/DELETE /blocklist/custom`) and the live VPN/Tor activity table (`GET /vpn-activity`, every 5 s) |
| Ransomware | Real — `GET /ransomware/status` every 3 s; the same poll drives a red banner across all pages while an incident is recent |
| Reports | Real — `GET /reports` |
| Alert approve/reject (drawer) | Real — `POST /alerts/{id}/approve` / `/reject` |
| SSH / Sessions (session log table) | Real — `GET /ssh/sessions` (a real `ssh_sessions` table, written on every `/ssh/connect` attempt, success or failure) |
| Detection Rules | Real — `GET /detection-rules` / `POST /detection-rules/{key}/toggle`. These are the 10 actual detection points in `detection-agent/rules.py`, `rules_target.py` and `rules_ransomware.py` (tagged with a `rule_key` on every finding they produce). Toggling a rule writes to a shared `detection_rule_state` table; `detection-agent` (all three watcher variants — local, HTTP, remote-SSH) polls `GET /detection-rules` every few seconds via `detection-agent/rule_state.py` and skips disabled rules on its next cycle, so the switch genuinely turns detection on/off rather than just changing a UI label. |

Everything in the table above is real; there's nothing left that's UI-only demo data.

If a page's fetch fails (backend not running), it falls back to example
data and shows a small "Can't reach the backend" notice instead of going
blank.

The app polls `GET /alerts` every 5 s and refreshes Overview, Alerts and the sidebar badges only when something changed, so new alerts appear without reloading.
