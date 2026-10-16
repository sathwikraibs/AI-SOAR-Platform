"""
Watcher variant for the cloud-target-server setup: target app runs on a
public cloud VM, everything else (this watcher, the backend, reports)
stays private on your own PC.

Difference from watcher.py: uses rules_target_remote.py (SSH-pull) instead
of rules_target.py's local-file version for the target-app rules. The
OS-level rules (rules.py -- process spawn, local SSH brute-force, bad-IP
connections) still watch YOUR PC, which is separate from watching the
cloud target app; keep both if you still want your PC's own activity
monitored, or comment out `ALL_RULES` below if you only care about the
cloud target for this demo.

Before running: set the SOAR_SSH_* environment variables (see
rules_target_remote.py's docstring) to point at your Oracle Cloud VM.

Usage:
    export SOAR_SSH_HOST=<vm public ip>
    export SOAR_SSH_KEY_PATH=/path/to/your-key.key
    python3 detection-agent/watcher_remote.py
    (backend must already be running locally at http://localhost:8000)
"""

import sys
import time
from datetime import datetime, timezone

import requests

from rules import ALL_RULES, prime_auth_log_position
from rules_target_remote import ALL_REMOTE_TARGET_RULES, prime_remote_log_position

API_URL = "http://localhost:8000/alerts"
POLL_INTERVAL_SECONDS = 3
REQUEST_TIMEOUT = 5


def post_alert(finding: dict) -> None:
    payload = {
        "source": finding["source"],
        "description": finding["description"],
        "ip": finding.get("ip"),
        "hash": finding.get("hash"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_key": finding.get("rule_key"),
    }
    try:
        resp = requests.post(API_URL, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        alert = resp.json()
        print(
            f"[detection-agent] ALERT SENT -> id={alert.get('id')} "
            f"severity={alert.get('severity')} risk_score={alert.get('risk_score')} "
            f"response_status={alert.get('response_status')}"
        )
        print(f"[detection-agent]   {finding['description']}")
    except requests.RequestException as exc:
        print(f"[detection-agent] WARNING: failed to POST alert to {API_URL} ({exc}). Is the backend running?")


def main():
    print(f"[detection-agent] Starting REMOTE watcher -- polling every {POLL_INTERVAL_SECONDS}s")
    print("[detection-agent] Watching: this PC (process/SSH-brute-force/bad-IP) + cloud target app (via SSH pull)")
    print(f"[detection-agent] Posting findings to {API_URL}")

    prime_auth_log_position()
    prime_remote_log_position()

    try:
        while True:
            for rule in ALL_RULES + ALL_REMOTE_TARGET_RULES:
                for finding in rule():
                    post_alert(finding)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[detection-agent] Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
