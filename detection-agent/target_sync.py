"""
Keeps the target app in step with the SOAR dashboard.

Two things are pushed to the target app (see /internal/config in
target-app/app.py):

  * the "Block VPN/Tor automatically" switch from the IP Blocklist tab, and
  * the SOAR's full VPN / Tor / proxy blocklist (including addresses added
    from the dashboard),

so a target app hosted somewhere else (PythonAnywhere) blocks, or lets
through, exactly what the dashboard says, within a few seconds. It works the
same for a local target app.

The target app is reached with the same address and shared secret the
log-polling already uses:

    SOAR_TARGET_URL   e.g. https://yourname.pythonanywhere.com
                      (default for a local app: http://localhost:5000)
    SOAR_LOGS_TOKEN   the INTERNAL_LOGS_TOKEN set on the server
                      (default: the target app's built-in default)

Used as a "rule" by the watchers: it never produces findings, it just
syncs when called, at most once every SYNC_INTERVAL_SECONDS. Every failure is
printed once and retried quietly; nothing here can stop the watcher.
"""

import os
import time

import requests

API_BASE = os.getenv("SOAR_API_BASE", "http://localhost:8000").rstrip("/")
TARGET_URL = (os.getenv("SOAR_TARGET_URL") or "http://localhost:5000").rstrip("/")
LOGS_TOKEN = os.getenv("SOAR_LOGS_TOKEN") or "change-me-before-deploying"
SYNC_INTERVAL_SECONDS = 1.5
PUSH_RETRY_SECONDS = 60      # after a failed push, wait this long before sending the (large) list again
REQUEST_TIMEOUT = 8

_last_run = 0.0
_last_push_failed_at = 0.0
_warned: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        print(f"[detection-agent] {message}")


def _clear_warning(key: str) -> None:
    _warned.discard(key)


def sync_target_config() -> list[dict]:
    """Pushes the dashboard's VPN-block switch and blocklist to the target app when they differ. Returns no findings."""
    global _last_run, _last_push_failed_at
    now = time.time()
    if now - _last_run < SYNC_INTERVAL_SECONDS:
        return []
    _last_run = now

    try:
        wanted = requests.get(f"{API_BASE}/target-config", timeout=REQUEST_TIMEOUT)
        wanted.raise_for_status()
        wanted = wanted.json()
        _clear_warning("backend")
    except (requests.RequestException, ValueError):
        _warn_once("backend", f"WARNING: target sync can't reach the SOAR backend at {API_BASE}; will keep retrying.")
        return []

    try:
        current = requests.get(f"{TARGET_URL}/internal/config", params={"token": LOGS_TOKEN}, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        _warn_once("target", f"WARNING: target sync can't reach the target app at {TARGET_URL} ({exc}); will keep retrying.")
        return []
    if current.status_code == 403:
        _warn_once("token", "ERROR: target sync was refused (403). SOAR_LOGS_TOKEN must equal INTERNAL_LOGS_TOKEN on the target app.")
        return []
    if current.status_code == 404:
        _warn_once("old-app", f"WARNING: {TARGET_URL} has no /internal/config. Upload the new target-app/app.py (and ransomware_demo.py) to enable VPN-block sync.")
        return []
    if current.status_code != 200:
        _warn_once("target", f"WARNING: target app returned {current.status_code} for /internal/config; will keep retrying.")
        return []
    _clear_warning("target")
    _clear_warning("token")
    _clear_warning("old-app")
    try:
        current = current.json()
    except ValueError:
        return []

    want_block = bool(wanted.get("auto_block", True))
    want_sha = str(wanted.get("blocklist_sha", ""))
    payload: dict = {}
    if bool(current.get("auto_block", True)) != want_block:
        payload["auto_block"] = want_block
    list_stale = want_sha and str(current.get("blocklist_sha", "")) != want_sha
    if list_stale and now - _last_push_failed_at >= PUSH_RETRY_SECONDS:
        try:
            export = requests.get(f"{API_BASE}/blocklist/export", timeout=REQUEST_TIMEOUT * 3)
            export.raise_for_status()
            export = export.json()
            payload["blocklist_text"] = export["text"]
            payload["blocklist_sha"] = export["sha"]
        except (requests.RequestException, ValueError, KeyError):
            _last_push_failed_at = now
            return []
    if not payload:
        return []

    try:
        resp = requests.post(f"{TARGET_URL}/internal/config", params={"token": LOGS_TOKEN}, json=payload, timeout=REQUEST_TIMEOUT * 3)
        resp.raise_for_status()
    except requests.RequestException as exc:
        _last_push_failed_at = now
        _warn_once("push", f"WARNING: couldn't push settings to the target app ({exc}); will retry.")
        return []
    _clear_warning("push")
    parts = []
    if "auto_block" in payload:
        parts.append(f"automatic VPN/Tor blocking {'ON' if want_block else 'OFF'}")
    if "blocklist_text" in payload:
        parts.append(f"blocklist ({len(payload['blocklist_text'].splitlines())} entries)")
    print(f"[detection-agent] Target app updated: {', '.join(parts)}")
    return []


ALL_SYNC_RULES: list = []   # sync runs in its own thread (see below), not in the slow rule loop


def start_background_sync() -> None:
    """
    Runs the sync on its own thread, so a flipped switch reaches the target app
    within a couple of seconds even when the watcher's other rules (process and
    network scans) take a while per cycle.
    """
    import threading

    def loop():
        while True:
            try:
                sync_target_config()
            except Exception as exc:  # noqa: BLE001 - never let the sync thread die
                _warn_once("crash", f"WARNING: target sync hit an error ({exc}); will keep retrying.")
            time.sleep(1.0)

    threading.Thread(target=loop, name="target-sync", daemon=True).start()
