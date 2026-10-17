"""
Ransomware detection for the target app's file store (the GridWatch SCADA
data in target-app/uploads/).

Real ransomware gives itself away in a few ways, and this rule watches for
the same ones by comparing the folder with how it looked on the last scan:

  1. Encrypted-file extensions appearing: report.csv -> report.csv.locked
     (.locked, .encrypted, .crypt, .wncry, .lockbit, ... see RANSOM_EXTENSIONS).
  2. Files rewritten in place from readable data into random-looking bytes.
     Encrypted data has very high Shannon entropy (close to 8 bits per byte),
     ordinary CSV / JSON / text sits around 4-5. A file that jumps from low to
     high entropy was almost certainly encrypted.
  3. A ransom note dropping into the folder (README_DECRYPT.txt and friends),
     recognised by its file name or by ransom-style wording inside it.

An alert fires when a ransom note appears alongside at least one encrypted
file, or when MIN_ENCRYPTED_FILES or more files get encrypted within
WINDOW_SECONDS. It fires once per incident; once the encrypted files and the
note are gone (restored from backup, or cleaned up) the rule re-arms.

The alert goes to the normal POST /alerts pipeline, so classification, MITRE
mapping (T1486 Data Encrypted for Impact), risk scoring and the Critical
malware / ransomware containment playbook all happen exactly as for every
other alert.

This watches a folder on the machine the watcher runs on, so it works with
watcher.py (local target app). It cannot see inside a target app hosted on
another machine such as PythonAnywhere.

Environment: SOAR_RANSOMWARE_WATCH_DIR overrides the folder (used for testing).
"""

import math
import os
import re
import time
from collections import deque

from rule_state import is_enabled

RULE_KEY_RANSOMWARE = "ransomware_activity"

_HERE = os.path.dirname(os.path.abspath(__file__))
TARGET_APP_DIR = os.path.join(_HERE, "..", "target-app")
WATCH_DIR = os.path.abspath(os.environ.get("SOAR_RANSOMWARE_WATCH_DIR") or os.path.join(TARGET_APP_DIR, "uploads"))
ACCESS_LOG_PATH = os.path.join(TARGET_APP_DIR, "logs", "access.log")

# Extensions that ransomware families append to encrypted files, plus the
# generic ones. Matched against the final extension only.
RANSOM_EXTENSIONS = {
    ".locked", ".lock", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".cry",
    ".locky", ".cerber", ".wncry", ".wcry", ".ryk", ".conti", ".akira", ".lockbit",
}

# Words that mark a file name as a ransom note, and the formats notes use.
_NOTE_NAME_TOKENS = (
    "decrypt", "ransom", "recover_your", "restore_your", "your_files", "files_encrypted",
    "encrypted_files", "how_to_recover", "how_to_restore", "please_read_me",
)
_NOTE_EXTENSIONS = {".txt", ".html", ".htm", ".hta", ".rtf"}
# Wording found inside notes; two or more hits in a small text file marks it as a note.
_NOTE_CONTENT_WORDS = ("bitcoin", "btc", "monero", "decrypt", "ransom", "your files", "wallet", "encrypted")

# Entropy thresholds (bits per byte, max 8.0).
HIGH_ENTROPY = 7.5
LOW_ENTROPY = 6.5
MIN_BYTES_FOR_ENTROPY = 128
ENTROPY_SAMPLE_BYTES = 65536
MAX_FILES_PER_SCAN = 500

MIN_ENCRYPTED_FILES = 3
WINDOW_SECONDS = 30

# path -> (mtime, size, entropy or None)
_snapshot: dict[str, tuple] = {}
_primed = False
_recent_encrypted: deque = deque()   # (timestamp, relative path) of files seen encrypted recently
_incident_active = False


def _canon(rel_path: str) -> str:
    """report.csv.locked -> report.csv, so one file seen under both names counts once."""
    base, ext = os.path.splitext(rel_path)
    return base if ext.lower() in RANSOM_EXTENSIONS else rel_path


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _file_entropy(path: str) -> float | None:
    try:
        with open(path, "rb") as f:
            data = f.read(ENTROPY_SAMPLE_BYTES)
    except OSError:
        return None
    return _entropy(data) if len(data) >= MIN_BYTES_FOR_ENTROPY else None


def _scan() -> dict[str, tuple]:
    """Current state of the watched folder: path -> (mtime, size, entropy|None)."""
    state: dict[str, tuple] = {}
    if not os.path.isdir(WATCH_DIR):
        return state
    for root, _dirs, files in os.walk(WATCH_DIR):
        for name in files:
            if name.startswith("."):
                continue
            if len(state) >= MAX_FILES_PER_SCAN:
                return state
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            prev = _snapshot.get(path)
            if prev and prev[0] == st.st_mtime and prev[1] == st.st_size:
                state[path] = prev  # unchanged: reuse, no need to re-read the file
            else:
                state[path] = (st.st_mtime, st.st_size, _file_entropy(path))
    return state


def _looks_like_ransom_note(path: str) -> bool:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    if ext not in _NOTE_EXTENSIONS:
        return False
    if any(token in name for token in _NOTE_NAME_TOKENS):
        return True
    try:
        if os.path.getsize(path) > 8192:
            return False
        with open(path, "r", errors="ignore") as f:
            text = f.read(8192).lower()
    except OSError:
        return False
    return sum(1 for w in _NOTE_CONTENT_WORDS if w in text) >= 2


def _last_active_ip() -> str | None:
    """
    Ransomware on a disk has no source IP of its own. The closest honest
    answer is who was last active against the app, so take the IP of the
    most recent login or upload from the access log (read-only).
    """
    try:
        with open(ACCESS_LOG_PATH, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 16384))
            lines = f.read().decode("utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[1] in ("LOGIN_SUCCESS", "FILE_UPLOADED", "SUSPICIOUS_FILE_UPLOADED"):
            m = re.search(r"\bip=(\S+)", parts[2])
            if m:
                return m.group(1)
    return None


def prime_ransomware_state() -> None:
    """Take the 'before' picture, so files already in the folder at startup aren't treated as an attack."""
    global _snapshot, _primed
    _snapshot = _scan()
    _primed = True


def check_ransomware() -> list[dict]:
    """Local version: scans the watched folder on this machine and evaluates what changed since the last scan."""
    global _snapshot
    if not _primed:
        prime_ransomware_state()
        return []

    current = _scan()
    previous = _snapshot
    _snapshot = current
    return evaluate_changes(
        current,
        previous,
        is_note=_looks_like_ransom_note,
        rel=lambda path: os.path.relpath(path, WATCH_DIR),
        last_ip=_last_active_ip,
    )


def evaluate_changes(current: dict, previous: dict, is_note, rel, last_ip) -> list[dict]:
    """
    The detection itself, shared by the local folder scan above and the remote
    snapshot poll in rules_ransomware_http.py (for a target app hosted elsewhere).

    current / previous: path -> (mtime, size, entropy or None)
    is_note(path) -> bool       does this file look like a ransom note?
    rel(path) -> str            the file's name relative to the watched folder
    last_ip() -> str | None     who was last active against the app, if known
    """
    global _incident_active
    now = time.time()

    encrypted_now: list[str] = []
    notes_now: list[str] = []
    ransom_artifacts_present = False

    for path, (_mtime, _size, entropy) in current.items():
        ext = os.path.splitext(path)[1].lower()
        is_new = path not in previous
        has_ransom_ext = ext in RANSOM_EXTENSIONS
        if has_ransom_ext:
            ransom_artifacts_present = True
        if is_note(path):
            ransom_artifacts_present = True
            if is_new:
                notes_now.append(path)

        if is_new and has_ransom_ext:
            encrypted_now.append(path)                      # report.csv -> report.csv.locked
        elif not is_new and previous[path][2] is not None:
            was, now_e = previous[path][2], entropy
            if now_e is not None and was < LOW_ENTROPY and now_e >= HIGH_ENTROPY:
                encrypted_now.append(path)                  # rewritten in place into random-looking bytes

    # Back to a clean folder: re-arm for the next incident.
    if _incident_active and not ransom_artifacts_present:
        _incident_active = False
        _recent_encrypted.clear()

    for path in encrypted_now:
        _recent_encrypted.append((now, _canon(rel(path))))
    while _recent_encrypted and now - _recent_encrypted[0][0] > WINDOW_SECONDS:
        _recent_encrypted.popleft()

    if _incident_active or not is_enabled(RULE_KEY_RANSOMWARE):
        return []

    note_present = bool(notes_now) or any(is_note(p) for p in current)
    count = len({name for _, name in _recent_encrypted})
    if not ((note_present and count >= 1) or count >= MIN_ENCRYPTED_FILES):
        return []

    _incident_active = True
    names = sorted({name for _, name in _recent_encrypted})
    sample = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
    note_names = sorted(os.path.basename(p) for p in current if is_note(p))
    note_text = f", ransom note '{note_names[0]}' dropped in the folder" if note_names else ""
    return [
        {
            "source": "Endpoint",
            "description": (
                f"Ransomware encryption activity detected on the target app file store "
                f"(GridWatch SCADA data): {count} files encrypted within {WINDOW_SECONDS}s "
                f"({sample}){note_text}, mass file rename observed"
                + (" -- attacker demanding payment to restore the files" if note_names else "")
            ),
            "ip": last_ip(),
            "hash": None,
            "rule_key": RULE_KEY_RANSOMWARE,
        }
    ]


ALL_RANSOMWARE_RULES = [check_ransomware]
