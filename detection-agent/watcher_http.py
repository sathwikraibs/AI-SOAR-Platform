"""
Watcher variant for the PythonAnywhere setup: target app runs on a public
PythonAnywhere URL, everything else (this watcher, the backend, reports)
stays private on your own PC. Uses HTTPS polling (rules_target_http.py)
instead of reading a local file or SSHing into a VM.

Setup:
    export SOAR_TARGET_URL=https://yourname.pythonanywhere.com
    export SOAR_LOGS_TOKEN=<same value you set as INTERNAL_LOGS_TOKEN on PythonAnywhere>
    python3 detection-agent/watcher_http.py
    (backend must already be running locally at http://localhost:8000)

The OS-level rules (rules.py -- process spawn, local SSH brute-force,
bad-IP connections) still watch YOUR PC as before; this just adds the
deployed target app as an additional thing being watched.
"""

import sys
import time
from datetime import datetime, timezone

import requests

from rules import ALL_RULES, prime_auth_log_position
from rules_target_http import ALL_HTTP_TARGET_RULES, prime_http_log_position
from rules_ransomware_http import ALL_REMOTE_RANSOMWARE_RULES, prime_remote_ransomware_state
from target_sync import ALL_SYNC_RULES, start_background_sync

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
    print(f"[detection-agent] Starting HTTP watcher -- polling every {POLL_INTERVAL_SECONDS}s")
    print("[detection-agent] Watching: this PC (process/SSH-brute-force/bad-IP) + deployed target app (via HTTPS poll: logins, uploads, VPN/Tor, ransomware file store)")
    print(f"[detection-agent] Posting findings to {API_URL}")

    prime_auth_log_position()
    prime_http_log_position()
    prime_remote_ransomware_state()
    start_background_sync()

    try:
        while True:
            for rule in ALL_RULES + ALL_HTTP_TARGET_RULES + ALL_REMOTE_RANSOMWARE_RULES + ALL_SYNC_RULES:
                for finding in rule():
                    post_alert(finding)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[detection-agent] Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
