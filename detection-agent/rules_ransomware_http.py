"""
Ransomware detection for a target app hosted somewhere else (PythonAnywhere).

rules_ransomware.py watches a folder on the machine the watcher runs on, which
cannot see an online server's files. This module asks the target app for a
snapshot of its uploads folder (GET /internal/files in target-app/app.py: file
name, size, modified time, entropy, and whether it looks like a ransom note)
and runs the very same detection on it (rules_ransomware.evaluate_changes):
new encrypted-extension files, files that turn into random-looking bytes, a
ransom note appearing.

Setup is the same as rules_target_http.py:
    SOAR_TARGET_URL=https://yourname.pythonanywhere.com
    SOAR_LOGS_TOKEN=<INTERNAL_LOGS_TOKEN on the server>

A failed poll is skipped (never treated as "all files deleted"), so a network
hiccup cannot cause a false alert.
"""

import os

import requests

import rules_ransomware as core

TARGET_URL = os.getenv("SOAR_TARGET_URL", "").rstrip("/")
LOGS_TOKEN = os.getenv("SOAR_LOGS_TOKEN", "")
REQUEST_TIMEOUT = 8

_snapshot: dict = {}
_primed = False
_warned: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key not in _warned:
        _warned.add(key)
        print(f"[detection-agent] {message}")


def _fetch():
    """Returns (state, note_paths) from the target app, or None if it could not be read this time."""
    if not (TARGET_URL and LOGS_TOKEN):
        _warn_once("config", "SOAR_TARGET_URL / SOAR_LOGS_TOKEN not set -- remote ransomware monitor is inactive.")
        return None
    try:
        resp = requests.get(f"{TARGET_URL}/internal/files", params={"token": LOGS_TOKEN}, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        _warn_once("net", f"WARNING: remote ransomware monitor can't reach {TARGET_URL} ({exc}); skipping.")
        return None
    if resp.status_code == 404:
        _warn_once("old", f"WARNING: {TARGET_URL} has no /internal/files. Upload the new target-app/app.py to enable the remote ransomware monitor.")
        return None
    if resp.status_code != 200:
        _warn_once("status", f"WARNING: {TARGET_URL}/internal/files returned {resp.status_code}; skipping.")
        return None
    try:
        files = resp.json()["files"]
        state = {f["path"]: (f["mtime"], f["size"], f.get("entropy")) for f in files}
        notes = {f["path"] for f in files if f.get("note")}
    except (ValueError, KeyError, TypeError):
        return None
    for key in ("net", "status", "old"):
        _warned.discard(key)
    return state, notes


def prime_remote_ransomware_state() -> None:
    """Take the 'before' picture of the server's file store."""
    global _snapshot, _primed
    fetched = _fetch()
    if fetched is None:
        return
    _snapshot = fetched[0]
    _primed = True
    print(f"[detection-agent] Remote ransomware monitor primed: {len(_snapshot)} files on {TARGET_URL}")


def check_ransomware_remote() -> list[dict]:
    global _snapshot, _primed
    fetched = _fetch()
    if fetched is None:
        return []
    current, notes = fetched
    if not _primed:
        _snapshot = current
        _primed = True
        return []
    previous = _snapshot
    _snapshot = current
    return core.evaluate_changes(
        current,
        previous,
        is_note=lambda path: path in notes,
        rel=lambda path: path,
        last_ip=lambda: None,    # a remote snapshot has no source IP
    )


ALL_REMOTE_RANSOMWARE_RULES = [check_ransomware_remote]
