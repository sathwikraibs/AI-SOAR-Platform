"""
Live detection agent.

Polls the machine (processes, network connections, auth log -- see
rules.py) every POLL_INTERVAL_SECONDS. Whenever a rule fires, this posts
the finding straight to the existing backend API (POST /alerts) -- nothing
about backend/main.py, the AI classifier, threat intel, or the response
engine changes. This is just a new caller of the same pipeline that already
handles manually-submitted alerts, so a real action on this machine now
flows automatically through classify -> enrich -> score -> respond.

Usage:
    python3 detection-agent/watcher.py
    (backend must already be running, default http://localhost:8000)

For the demo: start this BEFORE performing the "attack" so it's already
polling. Alerts typically show up in GET /alerts within one poll interval
(default 3s) of the triggering action.
"""

import sys
import time
from datetime import datetime, timezone

import requests

from rules import ALL_RULES, prime_auth_log_position
from rules_target import ALL_TARGET_RULES, prime_target_log_position
from rules_ransomware import ALL_RANSOMWARE_RULES, prime_ransomware_state
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
    print(f"[detection-agent] Starting live watcher -- polling every {POLL_INTERVAL_SECONDS}s")
    print(f"[detection-agent] Posting findings to {API_URL}")
    print(
        "[detection-agent] Rules active: suspicious process spawn, OS brute-force login, "
        "known-bad-IP connection, target-app login brute-force, target-app file upload "
        "(VirusTotal via existing pipeline), cross-signal correlation, "
        "ransomware file-encryption monitor, VPN/Tor/proxy IP block"
    )

    prime_auth_log_position()
    prime_target_log_position()
    prime_ransomware_state()
    start_background_sync()

    try:
        while True:
            for rule in ALL_RULES + ALL_TARGET_RULES + ALL_RANSOMWARE_RULES + ALL_SYNC_RULES:
                for finding in rule():
                    post_alert(finding)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\n[detection-agent] Stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
