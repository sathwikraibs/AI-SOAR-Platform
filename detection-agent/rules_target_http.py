"""
HTTP-poll version of the target-app watcher, for hosts (like PythonAnywhere's
free tier) that give you a public URL but no SSH/shell access.

Every poll, this makes a normal HTTPS request to the deployed target app's
GET /internal/logs?since=<offset> endpoint (see target-app/app.py) and
hands whatever new lines come back to rules_target.py's process_new_lines()
-- the exact same brute-force/file-upload/correlation detection logic as
the local and SSH versions, just fed differently.

This is a plain outbound web request, same as visiting a website in a
browser -- nothing about your PC is exposed, and it works through normal
home/college WiFi with no port forwarding or firewall changes needed.

Setup: after deploying target-app to PythonAnywhere, set:

    SOAR_TARGET_URL=https://yourname.pythonanywhere.com
    SOAR_LOGS_TOKEN=<same value as INTERNAL_LOGS_TOKEN on the server>

Tested against a local Flask instance of target-app (see this repo's dev
notes) -- the HTTP call itself is plain requests.get(), so it will behave
identically against the real PythonAnywhere URL, but run
detection-agent/watcher_http.py once against your actual deployment before
the demo to confirm the token and URL are both right.
"""

import os

import requests

from rules_target import process_new_lines

TARGET_URL = os.getenv("SOAR_TARGET_URL", "").rstrip("/")
LOGS_TOKEN = os.getenv("SOAR_LOGS_TOKEN", "")
REQUEST_TIMEOUT = 8

_http_log_pos = 0
_config_warned = False


def _is_configured() -> bool:
    global _config_warned
    if TARGET_URL and LOGS_TOKEN:
        return True
    if not _config_warned:
        _config_warned = True
        print(
            "[detection-agent] SOAR_TARGET_URL / SOAR_LOGS_TOKEN not set -- "
            "rules_target_http is inactive. Set them once your target app is "
            "deployed (see rules_target_http.py's module docstring)."
        )
    return False


def prime_http_log_position():
    """
    Call once at startup: finds the current size of the deployed app's log
    so the watcher only reacts to activity from now on, not the app's
    entire history (e.g. earlier testing before the real demo).
    """
    global _http_log_pos
    if not _is_configured():
        return

    try:
        resp = requests.get(
            f"{TARGET_URL}/internal/logs",
            params={"since": 0, "token": LOGS_TOKEN},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 403:
            print("[detection-agent] ERROR: SOAR_LOGS_TOKEN doesn't match the server's INTERNAL_LOGS_TOKEN.")
            return
        resp.raise_for_status()
        _http_log_pos = int(resp.headers.get("X-Log-Size", "0"))
        print(f"[detection-agent] Remote log primed at offset {_http_log_pos} bytes on {TARGET_URL}")
    except requests.RequestException as exc:
        print(f"[detection-agent] WARNING: could not prime remote log position ({exc}). Starting from 0.")
        _http_log_pos = 0


def check_target_app_http() -> list[dict]:
    """Fetches new log bytes from the deployed target app over HTTPS and runs the shared detection logic."""
    global _http_log_pos

    if not _is_configured():
        return []

    try:
        resp = requests.get(
            f"{TARGET_URL}/internal/logs",
            params={"since": _http_log_pos, "token": LOGS_TOKEN},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        print(f"[detection-agent] WARNING: could not reach {TARGET_URL} ({exc}) -- skipping this cycle.")
        return []

    if resp.status_code == 403:
        print("[detection-agent] ERROR: SOAR_LOGS_TOKEN rejected by server -- check it matches INTERNAL_LOGS_TOKEN.")
        return []
    if resp.status_code != 200:
        print(f"[detection-agent] WARNING: {TARGET_URL} returned {resp.status_code} -- skipping this cycle.")
        return []

    chunk = resp.content
    if not chunk:
        return []

    _http_log_pos += len(chunk)
    new_lines = chunk.decode(errors="ignore").splitlines(keepends=True)
    return process_new_lines(new_lines)


ALL_HTTP_TARGET_RULES = [check_target_app_http]
