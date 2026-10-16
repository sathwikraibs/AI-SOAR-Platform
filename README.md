# AI-SOAR Platform

An AI-assisted Security Orchestration, Automation and Response (SOAR) platform. It watches a target application for attacks, scores each alert with a machine-learning classifier, enriches it with threat intelligence, and recommends or simulates a response, all from one dashboard.

**Course project:** CSE7102, Presidency University
**Problem statement:** PSAIAC_173 (Cyber Security)
**SDG:** 16, Peace, Justice and Strong Institutions

---

## The problem

SOC analysts spend much of their time on repetitive alert triage: looking up the same IPs, judging the same kinds of alerts, and running the same containment steps by hand. This project automates that loop. It collects alerts, ranks them by severity, adds context, and applies a response playbook, so an analyst only has to step in for decisions that need a human.

## How it works

```
 target-app (Flask demo site)            host machine / servers
   login, files, upload                    processes, auth logs, file store
            │                                      │
            └──────────────┬───────────────────────┘
                           ▼
                detection-agent (watcher)
                  rules turn activity into findings
                           │  POST /alerts
                           ▼
        backend (FastAPI + Uvicorn, SQLite)
          1. ML classifier       -> Low / Medium / High / Critical
          2. Threat intelligence -> geolocation, IP/hash reputation, MITRE ATT&CK
          3. Risk scoring        -> 0-100
          4. Response engine     -> playbook, auto-run or needs approval
          5. Database + audit log
                           │  REST API
                           ▼
        frontend-dashboard (Next.js)   report-generator (PDF)
```

## Features

- **Detection:** brute-force login, credential stuffing, path traversal, suspicious file upload, multi-stage attacks from one IP, suspicious processes, SSH brute force and connections to known-bad IPs
- **Ransomware detection:** watches the SCADA file store for mass encryption (new `.locked`-style extensions, files turning into random-looking bytes, ransom notes) and raises a Critical alert mapped to MITRE T1486
- **VPN / Tor / proxy blocking:** a pre-loaded blocklist of anonymizing networks. The target app refuses those IPs on arrival and the SOAR blocks them automatically, so an attacker cannot hide behind a VPN
- **AI triage:** a Random Forest model (TF-IDF features) assigns severity to every alert
- **Enrichment:** IP geolocation, IP and file-hash reputation, and a MITRE ATT&CK technique for each alert
- **Response:** risk score, recommended playbook, and an approve/reject flow for actions that need a human
- **Dashboard:** overview KPIs and charts, alerts, incidents, investigations, playbooks, a 3D threat globe, IP blocklist, assets, SSH sessions, audit log, detection-rule toggles, and an admin panel
- **Reporting:** PDF incident reports and a 24-hour digest

## Project structure

| Folder | Purpose |
|---|---|
| `backend/` | FastAPI server: alerts, incidents, approvals, threat-intel lookups, blocklist, assets, audit log, admin, reports. API docs at `/docs` |
| `target-app/` | Flask demo site for a power-grid operator (GridWatch) with intentional weaknesses (login, file download, file upload), used as the attack target |
| `detection-agent/` | Watchers, detection rules and the ransomware simulator that send findings to the backend |
| `ai-model/` | Severity classifier: training script and saved model |
| `dataset/` | Synthetic alert dataset and its generator |
| `threat-intelligence/` | Geolocation, reputation lookups, MITRE ATT&CK mapping, VPN/Tor/proxy blocklist |
| `response-engine/` | Risk scoring, response decisions and playbooks |
| `database/` | SQLAlchemy models and SQLite setup |
| `report-generator/` | PDF report builders |
| `frontend-dashboard/` | Next.js dashboard |
| `documentation/` | API contract |

## Tech stack

| Layer | Tools |
|---|---|
| Backend | Python, FastAPI, Uvicorn, SQLAlchemy, SQLite |
| Machine learning | scikit-learn (Random Forest, TF-IDF) |
| Threat intelligence | ip-api.com, AbuseIPDB, VirusTotal, MITRE ATT&CK |
| Target app | Flask |
| Frontend | Next.js, React, TypeScript, react-simple-maps |
| Reports | ReportLab |

## Getting started

### Prerequisites

- Python 3.10 or newer
- Node.js 20 or newer

### Install

```bash
pip install -r requirements.txt
cd frontend-dashboard
npm install
```

### Run

Open four terminals in the project root and start each service:

```bash
uvicorn backend.main:app --reload       # API        http://localhost:8000  (docs: /docs)
python target-app/app.py                # Target app http://localhost:5000
python detection-agent/watcher.py       # Detection agent
cd frontend-dashboard && npm run dev    # Dashboard  http://localhost:3000
```

Start the detection agent before you begin attacking the target app. If `ai-model/severity_model.joblib` is missing, train it once with `python ai-model/train_classifier.py`.

Optional report generators:

```bash
python report-generator/generate_report.py
python report-generator/generate_daily_report.py
```

## Demos

### Ransomware on the SCADA file store

With the backend and the detection agent running:

```bash
python detection-agent/simulate_ransomware.py attack     # creates demo SCADA files, then "encrypts" them
python detection-agent/simulate_ransomware.py restore    # decrypts them and removes the ransom note
python detection-agent/simulate_ransomware.py cleanup    # restore, then delete the demo files
```

Within about ten seconds of `attack` starting, a Critical ransomware alert appears in the dashboard. The simulator is reversible and only ever touches the demo files it creates itself inside `target-app/uploads/`.

### Blocking a VPN or Tor user

The shipped blocklist contains clearly labelled demo ranges. From a second terminal:

```bash
curl -i -H "X-Forwarded-For: 203.0.113.9" http://localhost:5000/login
```

The request is refused with `403`, even with the correct password, and an alert appears with the block already carried out. To load the real public Tor exit-node and VPN lists, run this once while you have internet:

```bash
python threat-intelligence/update_blocklist.py
```

The result is a local file, so blocking keeps working offline afterwards. Private and local addresses are never blocked.

### Hosting the target app on PythonAnywhere

Deploy `target-app/` to PythonAnywhere and set `INTERNAL_LOGS_TOKEN` there. To keep VPN/Tor blocking active, also copy `threat-intelligence/ip_blocklist.py` and `anonymizer_blocklist.txt` next to `app.py`. Then run the watcher on your own machine against it (Windows shown):

```bat
set SOAR_TARGET_URL=https://<your-username>.pythonanywhere.com
set SOAR_LOGS_TOKEN=<same value as INTERNAL_LOGS_TOKEN>
python detection-agent/watcher_http.py
```

## Configuration

All settings are optional.

| Variable | Effect |
|---|---|
| `ABUSEIPDB_API_KEY` | Real IP reputation lookups |
| `VIRUSTOTAL_API_KEY` | Real file-hash reputation lookups |
| `SOAR_SLACK_WEBHOOK_URL` | Slack message for Critical alerts |
| `NEXT_PUBLIC_API_BASE` | Backend URL used by the dashboard (default `http://localhost:8000`) |

Without the API keys, reputation lookups fall back to a deterministic local result.

## Limitations

- Response actions such as blocking an IP or isolating a host are simulated and logged. Nothing touches a real firewall. The VPN/Tor/proxy block is the one exception: the target app genuinely refuses those requests.
- The ransomware monitor reads a folder on the machine the watcher runs on, so it works with a local target app, not one hosted elsewhere. The simulator only imitates ransomware behaviour; no real malware is involved.
- The severity model is trained on synthetic data because no real SIEM export was available.
- MITRE ATT&CK mapping is keyword based, not a live lookup.
- A VPN blocklist also blocks legitimate people who use a VPN. Remove lines from the list files to allow them.
- The target app has hard-coded demo credentials and intentional vulnerabilities. Run it only in a lab and never expose it to the internet.

## Team

| Roll number | Name |
|---|---|
| 20231CCS0148 | Sathwik Rai B S |
|  |  |
|  |  |

**Project guide:** _your supervisor's name_
