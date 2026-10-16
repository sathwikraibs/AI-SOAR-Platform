# Live Detection Agent

Watches this machine in real time and automatically calls the existing
`POST /alerts` API when it sees something malicious happen — so the full
AI-SOAR pipeline (classify → enrich → score → respond) reacts to a real
action on the box instead of only to manually-submitted alerts.

This does **not** change `backend/`, `ai-model/`, `threat-intelligence/`,
or `response-engine/` at all. It's just a new client of the API that
already exists.

## What it detects

| Rule | How | File |
|---|---|---|
| Suspicious process spawn | Polls running processes, matches command lines against reverse-shell / download-and-execute / dropper patterns (`/dev/tcp/`, `nc -e`, `curl \| bash`, base64-piped-to-shell, etc.) | `rules.py: check_suspicious_processes()` |
| Brute-force login | Tails `/var/log/auth.log` (or `/var/log/secure`) for repeated failed logins from the same IP within 60s | `rules.py: check_brute_force()` |
| Connection to known-bad IP | Polls active network connections, flags any to an IP in `KNOWN_BAD_IPS` | `rules.py: check_bad_ip_connections()` |

Plus five more rules in `rules_target.py`, watching `target-app/`'s own
login and file-upload activity (login brute force, credential stuffing,
path traversal, suspicious file upload, and cross-signal multi-stage
correlation) — see that file's docstring for details.

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
