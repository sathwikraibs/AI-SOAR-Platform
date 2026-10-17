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
- **VPN / Tor / proxy blocking:** a pre-loaded blocklist of anonymizing networks. With the dashboard switch **Block VPN/Tor automatically** ON, the target app refuses those IPs on arrival and the SOAR blocks them. With it OFF they can log in as normal, but every connection is still logged with its IP, provider and country. You can add your own VPN's IP or range from the dashboard
- **Endpoint protection (Sysmon):** an agent on each device reports Sysmon events to the dashboard (Assets tab shows online/offline devices and a live activity feed) and raises alerts for credential dumping, malicious PowerShell, persistence, ransomware precursors and connections to anonymizers. It also enforces an office-use policy (time on YouTube/social media/games, VPN clients, malicious websites), shows each owner's usage in Assets, and has ON/OFF monitoring switches per device and for all devices. See [`endpoint-agent/`](endpoint-agent/README.md)
- **AI triage:** a Random Forest model (TF-IDF features) assigns severity to every alert
- **Enrichment:** IP geolocation, IP and file-hash reputation, and a MITRE ATT&CK technique for each alert
- **Response:** risk score, recommended playbook, and an approve/reject flow for actions that need a human
- **Dashboard:** live-updating overview KPIs and charts, a Ransomware page with a red alert banner, VPN/Tor activity table, alerts, incidents, investigations, playbooks, a 3D threat globe, IP blocklist, assets, SSH sessions, audit log, detection-rule toggles, and an admin panel
- **Reporting:** PDF incident reports and a 24-hour digest

## Project structure

| Folder | Purpose |
|---|---|
| `backend/` | FastAPI server: alerts, incidents, approvals, threat-intel lookups, blocklist, assets, audit log, admin, reports. API docs at `/docs` |
| `target-app/` | Flask demo site for a power-grid operator (GridWatch) with intentional weaknesses (login, file download, file upload), used as the attack target |
| `detection-agent/` | Watchers, detection rules and the ransomware simulator that send findings to the backend |
| `endpoint-agent/` | Sysmon agent for the devices being protected, its detection rules, a simulator and a Sysmon config |
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

**Local target app** (backend, watcher and target app on one machine):

```bash
python detection-agent/simulate_ransomware.py attack     # creates demo SCADA files, then "encrypts" them
python detection-agent/simulate_ransomware.py restore    # decrypts them and removes the ransom note
python detection-agent/simulate_ransomware.py cleanup    # restore, then delete the demo files
```

**Target app hosted on PythonAnywhere:** the hosted app stages the same harmless attack on its own demo files and your local watcher notices through its protected file listing.

1. Upload `target-app/app.py` and `target-app/ransomware_demo.py` to PythonAnywhere, set `ENABLE_DEMO_ENDPOINTS=1` and `INTERNAL_LOGS_TOKEN=<secret>` in the WSGI file, and reload the web app.
2. On your PC (Windows): `set SOAR_TARGET_URL=https://<you>.pythonanywhere.com`, `set SOAR_LOGS_TOKEN=<secret>`, then `python detection-agent/watcher_http.py`.
3. In a second window with the same two variables: `python detection-agent/simulate_ransomware_remote.py attack` (then `restore`).

Within seconds a red **RANSOMWARE ACTIVITY DETECTED** banner appears across the dashboard, the **Ransomware** page lists the incident, and a Critical alert (MITRE T1486, containment playbook) shows in Alerts. The simulation is reversible and only touches the demo files it creates inside the uploads folder. No real malware is involved.

### Blocking a VPN or Tor user (with an ON/OFF switch)

On the dashboard, **IP Blocklist → Block VPN / Tor logins automatically** is the switch.

- **ON:** a login from a listed VPN, Tor or proxy address gets `403`, the SOAR blocks the IP, and the VPN/Tor activity table logs the address, provider and country (the VPN's exit country).
- **OFF:** the same user logs in normally, and the same row is still logged and geolocated, marked *Detected (allowed)*.

The switch reaches the hosted target app within a few seconds (the local watcher pushes it). Live demo with a real tool:

- **Tor Browser** is the most reliable: its exit nodes are on the public list. Run `python threat-intelligence/update_blocklist.py` once (with internet), then browse to the target app through Tor.
- **Proton VPN or any other VPN:** connect, open a what-is-my-IP page, and add that address (or its /24) in **IP Blocklist → Add an IP or range**. Then open the target app and watch it get blocked.
- **Without any VPN:** `curl -i -H "X-Forwarded-For: 203.0.113.9" http://localhost:5000/login`

Private and local addresses are never blocked, and ranges larger than /8 are refused. The shipped list does not guarantee every Proton or other VPN address is covered.

### Protecting a device with Sysmon

```bash
python endpoint-agent/sysmon_agent.py --simulate --hostname DEMO-PC-1 --owner "Priya Sharma" --attack all
```

The device appears under **Assets → Connected Endpoints** within seconds with its owner, today's usage bars and a live activity feed, and each attack or policy breach raises an alert. Use the **Monitoring** switches there to pause one device or all devices. Real Sysmon setup for your team's laptops is in [`endpoint-agent/README.md`](endpoint-agent/README.md).

### Hosting the target app on PythonAnywhere

Deploy `target-app/` to PythonAnywhere and set `INTERNAL_LOGS_TOKEN` there. To keep VPN/Tor blocking active, also copy `threat-intelligence/ip_blocklist.py` and `anonymizer_blocklist.txt` next to `app.py`. Then run the watcher on your own machine against it (Windows shown); it also keeps the hosted app's blocking switch and blocklist in step with the dashboard:

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
| `SOAR_AGENT_TOKEN` | Shared secret the endpoint agents must send (`X-Agent-Token`); unset = open |
| `ENABLE_DEMO_ENDPOINTS` | On the hosted target app: `1` allows the remote ransomware demo |
| `INTERNAL_LOGS_TOKEN` / `SOAR_LOGS_TOKEN` | Shared secret between the hosted target app and your local watcher |
| `SOAR_TARGET_URL` | Address of the hosted target app, for the watcher |

Without the API keys, reputation lookups fall back to a deterministic local result.

## Limitations

- Response actions such as blocking an IP or isolating a host are simulated and logged. Nothing touches a real firewall. The VPN/Tor/proxy block is the one exception: the target app genuinely refuses those requests.
- The ransomware demo imitates ransomware behaviour on demo files only; no real malware is involved. For a hosted target app the watcher sees file names, sizes, times and entropy through a token-protected listing, not file contents.
- VPN/Tor blocking covers the addresses on the list. A VPN address that is not listed is not caught until you add it (dashboard → IP Blocklist). The country shown is the VPN's exit country, not the user's real location.
- Employee monitoring sees domains and program names only, estimates time online, and is bypassed by encrypted DNS in browsers. Monitor only with the users' knowledge and consent.
- The Sysmon agent was tested with simulated events and sample XML, not against a live Sysmon install. It reports only; it does not isolate devices.
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
