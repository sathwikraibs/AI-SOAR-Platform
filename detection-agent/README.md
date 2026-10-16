# Live Detection Agent

Watches this machine in real time and automatically calls the existing
`POST /alerts` API when it sees something malicious happen — so the full
AI-SOAR pipeline (classify → enrich → score → respond) reacts to a real
action on the box instead of only to manually-submitted alerts.

The watcher talks to the backend only through the existing `POST /alerts`
API; every alert it sends goes through the same classify, enrich, score,
respond pipeline as a hand-submitted one.

## What it detects

| Rule | How | File |
|---|---|---|
| Suspicious process spawn | Polls running processes, matches command lines against reverse-shell / download-and-execute / dropper patterns (`/dev/tcp/`, `nc -e`, `curl \| bash`, base64-piped-to-shell, etc.) | `rules.py: check_suspicious_processes()` |
| Brute-force login | Tails `/var/log/auth.log` (or `/var/log/secure`) for repeated failed logins from the same IP within 60s | `rules.py: check_brute_force()` |
| Connection to known-bad IP | Polls active network connections, flags any to an IP in `KNOWN_BAD_IPS` | `rules.py: check_bad_ip_connections()` |

Plus more rules in `rules_target.py`, watching `target-app/`'s own
login and file-upload activity (login brute force, credential stuffing,
path traversal, suspicious file upload, cross-signal multi-stage
correlation, and VPN / Tor / proxy blocking) — see that file's docstring
for details.

| Rule | How | File |
|---|---|---|
| Ransomware / mass file encryption | Compares the target app's file store (`target-app/uploads/`) with the previous scan: new `.locked`-style extensions, files rewritten from readable data into random-looking bytes (entropy jump), ransom notes. Raised as a Critical alert, MITRE T1486 | `rules_ransomware.py: check_ransomware()` |
| VPN / Tor / proxy IP block | The target app refuses requests from IPs on `threat-intelligence/anonymizer_blocklist.txt` and logs `ANONYMIZER_BLOCKED`; this rule turns that into an alert | `rules_target.py` |

## Turning a rule on/off from the dashboard

Every finding above is tagged with a `rule_key` (e.g. `"login_brute_force"`,
`"path_traversal"`) that's forwarded straight through to `POST /alerts`
and stored on the alert. The dashboard's **Detection Rules** tab reads
`GET /detection-rules` (backed by a real `detection_rule_state` table) and
flips a rule's enabled state with `POST /detection-rules/{key}/toggle`.

Since this watcher has no database access of its own, it stays in sync by
polling that same `GET /detection-rules` endpoint every few seconds
(`rule_state.py`, cached for `REFRESH_SECONDS`) and skipping any rule
whose key comes back disabled — so toggling it off in the dashboard
genuinely stops that rule from firing here, not just from displaying.
This also fails *open*: if the backend is briefly unreachable, every rule
is treated as enabled rather than detection silently going dark. This
same mechanism is shared by `watcher.py`, `watcher_http.py`, and
`watcher_remote.py`, since all three call into `rules.py` / `rules_target.py`.

## Setup

```bash
pip install -r ../requirements.txt   # adds psutil to the existing deps
```

## Running it for the demo

1. Start the backend as usual: `uvicorn backend.main:app --reload` (from repo root)
2. Start the watcher: `python3 detection-agent/watcher.py`
   - Leave its terminal visible — it prints every alert it sends, which
     makes the "detected in real time" claim visible to invigilators.
3. Have your guide (or you) run one of the demo triggers:
   ```bash
   ./detection-agent/simulate_attack.sh process     # suspicious process pattern
   ./detection-agent/simulate_attack.sh network      # connection to a known-bad IP
   ./detection-agent/simulate_attack.sh bruteforce   # prints instructions (needs sshd running)
   ```
4. Within ~3 seconds (`POLL_INTERVAL_SECONDS` in `watcher.py`), a new alert
   appears in `GET /alerts` / the dashboard, already classified, enriched,
   risk-scored, and with a response playbook attached — with zero manual
   `POST /alerts` call.

## Demo: ransomware on the SCADA file store

With the backend and `watcher.py` running (watch the watcher's terminal):

```bash
python3 detection-agent/simulate_ransomware.py attack    # creates demo SCADA files, then "encrypts" them
python3 detection-agent/simulate_ransomware.py restore   # decrypts them again and removes the ransom note
python3 detection-agent/simulate_ransomware.py cleanup   # restore, then delete the demo files
```

Within about 10 seconds of `attack` starting (it first waits 6 seconds so the watcher records the normal state), a **Critical**
"Ransomware encryption activity" alert appears, mapped to T1486 and given the ransomware containment
playbook. The simulator only ever touches the demo files it created itself, inside `target-app/uploads/`,
and is fully reversible (use `restore` to repeat the demo). The rule re-arms once the encrypted files and
the note are gone. It reads a folder on the machine the watcher runs on, so it works with `watcher.py`
(local target app), not with a target app hosted on PythonAnywhere.

## Demo: blocking a VPN / Tor user

The shipped blocklist contains clearly-labelled demo ranges (`203.0.113.0/24` VPN, `198.51.100.0/24` Tor,
`192.0.2.0/24` proxy). The target app trusts the `X-Forwarded-For` header, so from a second terminal:

```bash
curl -i -H "X-Forwarded-For: 203.0.113.9" http://localhost:5000/login
```

returns `403 Access denied`, even with the correct password, and within seconds an alert for
the blocked connection appears with the "Anonymizer Network Block" playbook already executed.
To load the real public Tor exit-node and VPN lists (once, with internet; the result is a local file and
works offline afterwards): `python3 threat-intelligence/update_blocklist.py`.

## Before presenting

- `KNOWN_BAD_IPS` in `rules.py` is a static demo list. If you want to
  demo against a specific IP, add it there.
- The process-spawn patterns are intentionally broad for demo reliability.
  If you test this on a machine that's also running other dev tools with
  similar command-line patterns, you may see extra unrelated alerts —
  harmless, but worth a quick dry run before you're in front of invigilators.
- Brute-force detection needs `sshd` actually running and logging to
  `/var/log/auth.log` or `/var/log/secure`. If the demo machine doesn't
  have SSH enabled, skip that scenario and lead with `process` and `network`.
