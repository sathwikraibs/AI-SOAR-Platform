\# AI-Powered Security Orchestration, Automation and Response (SOAR) Platform



\*\*Problem Statement Number:\*\* PSAIAC\_173

\*\*Category:\*\* Software (Cyber Security)

\*\*SDG Mapping:\*\* SDG 16 – Peace, Justice and Strong Institutions



\## Problem Description

Security Orchestration, Automation, and Response (SOAR) — SOC analysts spend hours on repetitive alert triage. Industry needs a SOAR platform that automates enrichment, containment, and response playbooks for common security incidents.



\## Objective

To develop an AI-powered SOAR platform that collects security alerts from multiple sources, uses AI to classify and prioritize incidents, enriches them with threat intelligence, and automates containment and response playbooks — reducing manual SOC alert-triage workload and response time.



\## How it works



```

&#x20;target-app (Flask, vulnerable demo site)           your PC / servers

&#x20;  login, files, upload ──► logs ─┐                  processes, auth log

&#x20;                                 ▼                         │

&#x20;                       detection-agent (watcher) ◄─────────┘

&#x20;                         rules → findings

&#x20;                                 │  POST /alerts

&#x20;                                 ▼

&#x20;  backend (FastAPI + Uvicorn, SQLite)

&#x20;    1. AI classifier        → Low / Medium / High / Critical

&#x20;    2. Threat intelligence  → IP geolocation, IP/hash reputation, MITRE ATT\&CK technique

&#x20;    3. Risk scoring         → 0–100 score

&#x20;    4. Response engine      → playbook + auto / needs-approval decision (simulated)

&#x20;    5. Stored in the database, audit-logged

&#x20;                                 │  REST API

&#x20;                                 ▼

&#x20;  frontend-dashboard (Next.js)  +  report-generator (PDF reports)

```



\## Components



| Folder | What it is |

|---|---|

| `backend/` | FastAPI server (run with Uvicorn). Alerts, incidents, approve/reject, threat-intel lookups, assets, SSH diagnostics, audit log, admin accounts, detection-rule toggles, report downloads. Interactive API docs at `/docs`. |

| `target-app/` | Flask web app that is \*\*deliberately attackable\*\*: login page (brute force / credential stuffing), file download (path traversal) and file upload (suspicious files). It can run locally or be hosted on PythonAnywhere, and exposes a token-protected `/internal/logs` endpoint so a remote watcher can read its logs. |

| `detection-agent/` | Watchers and detection rules. Reads the target-app's activity and OS-level signals and posts findings to the backend. Variants: `watcher.py` (local), `watcher\_http.py` (target-app hosted on PythonAnywhere, polled over HTTPS), `watcher\_remote.py` (over SSH). |

| `ai-model/` | Random Forest severity classifier (TF-IDF text features), trained on a synthetic labelled dataset. |

| `dataset/` | Synthetic alert dataset generator and the generated CSV. |

| `threat-intelligence/` | IP geolocation (ip-api.com, free), IP/hash reputation (AbuseIPDB and VirusTotal when API keys are set, deterministic fallback otherwise) and a keyword-based MITRE ATT\&CK technique mapper. |

| `response-engine/` | Risk scoring, response decisions and playbooks. Response steps are \*\*simulated and logged\*\*, not executed on a real firewall. |

| `database/` | SQLAlchemy models and SQLite setup. |

| `report-generator/` | Builds PDF incident reports (charts, KPIs, summary, recommendations) and a 24-hour digest. |

| `frontend-dashboard/` | Next.js dashboard: Overview, Alerts, Incidents, Investigations, Playbooks, Runbook, Threat Intelligence, Global Threat Map (3D globe), Assets, Response Center, SSH Sessions, Audit, Reports, Detection Rules, Integrations, Admin Panel. |

| `documentation/` | API contract. |



\## Detections implemented



\- Brute-force login and credential stuffing against the target-app

\- Account lockout and automatic IP block after repeated path-traversal attempts

\- Path traversal attempts

\- Suspicious file upload (risky extensions → hash lookup, mapped to MITRE T1204)

\- Multi-stage correlation (several attack types from one IP)

\- OS-level: suspicious process spawn, SSH brute force on Linux, connections to known-bad IPs



\## Technology stack



\- \*\*Backend:\*\* Python, FastAPI, Uvicorn, SQLAlchemy, SQLite

\- \*\*AI/ML:\*\* scikit-learn (Random Forest + TF-IDF)

\- \*\*Threat intelligence:\*\* ip-api.com, AbuseIPDB and VirusTotal (optional keys), MITRE ATT\&CK

\- \*\*Target app:\*\* Flask (optionally hosted on PythonAnywhere)

\- \*\*Frontend:\*\* Next.js, React, TypeScript, react-simple-maps (globe)

\- \*\*Reports:\*\* ReportLab



\## Running it locally



One-time setup:



```

pip install -r requirements.txt

cd frontend-dashboard

npm install

```



Then, in four terminals from the project root:



```

python backend/main.py                 # backend API  → http://localhost:8000  (docs at /docs)

python target-app/app.py               # target app   → http://localhost:5000

python detection-agent/watcher.py      # detection agent (start before attacking)

cd frontend-dashboard \&\& npm run dev   # dashboard    → http://localhost:3000

```



If `ai-model/severity\_model.joblib` is missing, run `python ai-model/train\_classifier.py` once.

Optional: `python report-generator/generate\_report.py` (incremental PDFs) and `python report-generator/generate\_daily\_report.py` (24-hour digest).



\### Using a hosted target-app (PythonAnywhere)



Deploy `target-app/` to PythonAnywhere and set `INTERNAL\_LOGS\_TOKEN` there. Then run the watcher locally against it:



```

set SOAR\_TARGET\_URL=https://<your-username>.pythonanywhere.com

set SOAR\_LOGS\_TOKEN=<same value as INTERNAL\_LOGS\_TOKEN>

python detection-agent/watcher\_http.py

```



\### Optional configuration



\- `ABUSEIPDB\_API\_KEY`, `VIRUSTOTAL\_API\_KEY` — real reputation lookups (otherwise a deterministic fallback is used)

\- `SOAR\_SLACK\_WEBHOOK\_URL` — Slack notification for Critical alerts

\- `NEXT\_PUBLIC\_API\_BASE` — backend URL for the dashboard (default `http://localhost:8000`)



\## Notes and limitations



\- Response actions (block IP, isolate host, and so on) are simulated and logged; nothing touches a real firewall.

\- The severity model is trained on synthetic data because no real SIEM export was available.

\- MITRE mapping is keyword based, not a live MITRE API.

\- The target-app contains hard-coded demo credentials and intentional weaknesses. Never expose it outside a lab setting.



\## Team

| Roll Number | Name |

|---|---|

| 20231CCS0148 | Sathwik Rai B S |

|  |  |

|  |  |

|  |  |



\## Project Guide

\[Your supervisor's name]

