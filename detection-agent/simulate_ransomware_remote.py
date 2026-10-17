"""
Ransomware demo against a target app hosted online (PythonAnywhere).

simulate_ransomware.py changes files on this machine; this one asks the
*deployed* target app to stage the same harmless, reversible attack on its own
demo SCADA files (see target-app/ransomware_demo.py): it "encrypts" them one by
one (renamed to *.locked), then drops a ransom note. Meanwhile
detection-agent/watcher_http.py polls the server's file store, sees the
encryption, and the dashboard raises a Critical ransomware alert.

    python3 detection-agent/simulate_ransomware_remote.py attack    # create demo files, then "encrypt" them
    python3 detection-agent/simulate_ransomware_remote.py restore   # decrypt, rename back, remove the note
    python3 detection-agent/simulate_ransomware_remote.py cleanup   # restore, then delete the demo files
    python3 detection-agent/simulate_ransomware_remote.py status

Needs the same settings as the watcher:
    SOAR_TARGET_URL=https://yourname.pythonanywhere.com
    SOAR_LOGS_TOKEN=<INTERNAL_LOGS_TOKEN on the server>
and on the server (PythonAnywhere -> Web -> WSGI file or environment):
    ENABLE_DEMO_ENDPOINTS=1
with target-app/ransomware_demo.py uploaded next to app.py. Start watcher_http.py
first. It only touches the demo files it creates itself, inside the uploads folder.
"""

import os
import sys
import time

import requests

TARGET_URL = os.getenv("SOAR_TARGET_URL", "").rstrip("/")
LOGS_TOKEN = os.getenv("SOAR_LOGS_TOKEN", "")
DELAY_BETWEEN_FILES = 0.4
WARMUP_SECONDS = 6
REQUEST_TIMEOUT = 20


def call(action: str) -> dict:
    try:
        resp = requests.post(
            f"{TARGET_URL}/internal/demo/ransomware",
            params={"token": LOGS_TOKEN},
            json={"action": action},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        sys.exit(f"Could not reach {TARGET_URL} ({exc})")
    if resp.status_code == 403 and "Demo endpoints are off" in resp.text:
        sys.exit("The server has demo endpoints switched off. Set ENABLE_DEMO_ENDPOINTS=1 on it and upload ransomware_demo.py next to app.py.")
    if resp.status_code == 403:
        sys.exit("Refused (403): SOAR_LOGS_TOKEN does not match INTERNAL_LOGS_TOKEN on the server.")
    if resp.status_code == 404:
        sys.exit("The server has no demo endpoint yet. Upload the new target-app/app.py and ransomware_demo.py.")
    if resp.status_code != 200:
        sys.exit(f"Server answered {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def attack() -> int:
    result = call("prepare")
    print(result.get("message"))
    if not result.get("ok"):
        return 1
    print(f"Waiting {WARMUP_SECONDS}s so the watcher records the normal state first...")
    time.sleep(WARMUP_SECONDS)
    print("Encrypting...")
    while True:
        step = call("encrypt_next")
        if step.get("encrypted"):
            print(f"  encrypted {step['encrypted']}")
            time.sleep(DELAY_BETWEEN_FILES)
        if not step.get("remaining"):
            break
    print(call("note").get("message"))
    print("Done. The SOAR should raise a Critical ransomware alert within a few seconds.")
    print("To undo: python3 detection-agent/simulate_ransomware_remote.py restore")
    return 0


def simple(action: str) -> int:
    result = call(action)
    if action == "status":
        files = result.get("files") or {}
        if not files:
            print("No simulation in progress.")
        for name, state in files.items():
            print(f"  {name}: {state}")
    else:
        print(result.get("message"))
    return 0


if __name__ == "__main__":
    commands = {"attack", "restore", "cleanup", "status"}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        print(__doc__)
        sys.exit(2)
    if not (TARGET_URL and LOGS_TOKEN):
        sys.exit("Set SOAR_TARGET_URL and SOAR_LOGS_TOKEN first (see the top of this file).")
    sys.exit(attack() if sys.argv[1] == "attack" else simple(sys.argv[1]))
