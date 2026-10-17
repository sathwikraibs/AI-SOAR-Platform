"""
Target server for the live-detection demo.

Purpose: give the SOAR something real to protect, with enough surface area
that an "attack" has an actual objective, not just "log in wrong a few
times." It has:
  - a login form (two accounts, so credential stuffing across users is a
    distinct, demonstrable pattern from single-account brute force)
  - a "customer records" page and a file-storage area behind login -- the
    thing an attacker is notionally after
  - an upload endpoint that flags suspicious file extensions
  - a download endpoint that detects (and safely blocks) path-traversal
    attempts instead of actually being exploitable
  - a simple app-layer lockout after repeated failed logins

Every one of those emits a structured, line-per-event access log that
detection-agent/rules_target.py reads and turns into alerts through the
existing pipeline -- this file's only job is realistic, loggable behavior,
not a real vulnerable app: the traversal guard actually blocks the read
(it detects the attempt and refuses it), it doesn't create a real hole.

Run locally: python3 target-app/app.py   (listens on http://localhost:5000)

Deployed on PythonAnywhere (no SSH available there), the watcher on your
own PC can't read this server's log file directly off disk. Instead, this
app exposes GET /internal/logs -- a small authenticated endpoint that
returns raw log bytes from a given offset onward, same idea as `tail -c`.
detection-agent/rules_target_http.py polls this over plain HTTPS.

It's protected by a shared secret so a stranger can't read your logs just
because the app is public: set INTERNAL_LOGS_TOKEN as an environment
variable (PythonAnywhere: Web tab -> your app -> WSGI config file), and
pass the same value as SOAR_LOGS_TOKEN on the watcher side.
"""

import hashlib
import json
import math
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
LOG_PATH = os.path.join(BASE_DIR, "logs", "access.log")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

app = Flask(__name__)
app.secret_key = "demo-only-not-for-production"

# Shared secret for GET /internal/logs (see module docstring). Falls back to
# a default so local testing works without setting anything -- CHANGE THIS
# (via the environment variable) before deploying somewhere public.
INTERNAL_LOGS_TOKEN = os.environ.get("INTERNAL_LOGS_TOKEN", "change-me-before-deploying")

# Two demo accounts -- this is a target server for a security demo, not a
# real product, so hardcoded credentials are intentional and fine here.
# Two accounts (not one) matter for the detection side: failed logins
# against a *single* username from one IP is classic brute force, but
# failed logins spread across *multiple* usernames from one IP is
# credential stuffing -- a distinct, separately-flagged pattern (see
# detection-agent/rules_target.py's _failed_usernames_by_ip tracking).
# Framed as GridWatch grid-operator accounts (see templates/) but the
# usernames/passwords themselves are unchanged -- detection-agent's rules
# key off these exact values.
VALID_USERS = {
    "admin": "SoarDemo2026",
    "manager": "Manager@2026",
}

# --- fake "objective" data behind the login, so an attacker has something
# to actually go after instead of just proving they can log in --
# GridWatch scenario: a regional power-grid operator's substation roster,
# instead of a generic SaaS customer list. Field names changed to match
# (region/load_status/last_inspection instead of email/plan) -- this is
# display data only, nothing here feeds detection logic.
FAKE_CUSTOMER_RECORDS = [
    {"id": 1, "name": "Substation Alpha-7", "region": "North Grid", "load_status": "Normal", "last_inspection": "2026-03-14"},
    {"id": 2, "name": "Substation Delta-3", "region": "East Grid", "load_status": "High Load", "last_inspection": "2026-02-02"},
    {"id": 3, "name": "Substation Omega-1", "region": "Central Grid", "load_status": "Critical", "last_inspection": "2025-11-20"},
    {"id": 4, "name": "Substation Kilo-9", "region": "West Grid", "load_status": "Normal", "last_inspection": "2026-01-08"},
]

# --- app-layer account lockout (separate from, and complementary to, the
# detection-agent's own brute-force *detection*: this is the target app
# actually defending itself, so the demo can show the SOAR catching the
# attack before this lockout even kicks in) ---
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 300
LOCKOUT_DURATION_SECONDS = 120
_failed_attempts: dict[str, deque] = defaultdict(deque)  # username -> deque[timestamp]
_locked_until: dict[str, float] = {}

# --- app-layer IP block for repeated path-traversal attempts (same idea as
# the account lockout above, but keyed by IP instead of username, since a
# traversal attempt isn't tied to a logged-in identity the same way) ---
TRAVERSAL_BLOCK_THRESHOLD = 5
TRAVERSAL_BLOCK_WINDOW_SECONDS = 300
TRAVERSAL_BLOCK_DURATION_SECONDS = 120
_traversal_attempts: dict[str, deque] = defaultdict(deque)  # ip -> deque[timestamp]
_ip_blocked_until: dict[str, float] = {}

# File extensions flagged as high-risk on upload -- logged as a distinct
# event so the watcher can raise a finding before the hash is even checked
# against VirusTotal.
SUSPICIOUS_EXTENSIONS = {".exe", ".php", ".sh", ".bat", ".dll", ".jar", ".ps1", ".js"}


def log_event(event_type: str, **fields) -> None:
    """
    Appends one structured line to logs/access.log, e.g.:
    2026-09-22T10:15:03+00:00 LOGIN_FAILED ip=127.0.0.1 username=admin
    2026-09-22T10:15:12+00:00 FILE_UPLOADED ip=127.0.0.1 filename=eicar.txt sha256=...

    detection-agent/rules_target.py parses exactly this format.
    """
    ts = datetime.now(timezone.utc).isoformat()
    field_str = " ".join(f"{k}={v}" for k, v in fields.items())
    with open(LOG_PATH, "a") as f:
        f.write(f"{ts} {event_type} {field_str}\n")


def client_ip() -> str:
    # Respect a proxy header if present (harmless for this demo, and a
    # realistic touch), otherwise the direct remote address.
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")


# --- anonymizer (VPN / Tor / open-proxy) blocklist ---------------------------
# Requests from a listed network are refused before they reach any page, so
# an attacker hiding behind a VPN or Tor never gets as far as the login form.
# The list lives in threat-intelligence/ (shared with the SOAR backend). When
# this app is deployed on its own (e.g. PythonAnywhere), copy ip_blocklist.py
# and anonymizer_blocklist.txt next to this file and they are used instead.
# If neither is found the app runs exactly as before, just without this check.
ip_blocklist = None
for _bl_dir in (BASE_DIR, os.path.join(BASE_DIR, "..", "threat-intelligence")):
    if os.path.exists(os.path.join(_bl_dir, "ip_blocklist.py")):
        sys.path.append(os.path.abspath(_bl_dir))
        try:
            import ip_blocklist  # noqa: E402
            break
        except Exception as _exc:  # noqa: BLE001 - a broken blocklist must never take the app down
            print(f"[target-app] WARNING: could not load ip_blocklist ({_exc}); anonymizer blocking is off")
            ip_blocklist = None

# These stay reachable even from a listed IP: the health check, and the
# /internal/ endpoints the SOAR watcher uses (each has its own token).
_ANON_EXEMPT_PATHS = {"/health", "/internal/logs"}
ANON_LOG_INTERVAL_SECONDS = 30  # log a repeat visitor at most this often, so a flood doesn't flood the log
_anon_last_logged: dict[tuple, float] = {}

# --- settings the SOAR pushes to this app ---------------------------------------
# The detection watcher keeps two things in sync (detection-agent/target_sync.py):
#   auto_block  -- the dashboard's "Block VPN/Tor automatically" switch. On: listed
#                  visitors get a 403. Off: they are let through, but still logged
#                  (ANONYMIZER_ALLOWED) so the SOAR can alert, geolocate and show them.
#   the list    -- the SOAR's full blocklist, saved next to this file so a copy hosted
#                  elsewhere (PythonAnywhere) blocks exactly what the dashboard shows.
# Defaults (blocking on, no pushed list) apply until the watcher connects, so the app
# behaves exactly as before if nothing is ever pushed.
CONFIG_PATH = os.path.join(BASE_DIR, "runtime_config.json")
SYNCED_LIST_PATH = os.path.join(BASE_DIR, "anonymizer_blocklist_synced.txt")
_config_cache: dict = {"mtime": "unset", "data": {"auto_block": True, "blocklist_sha": ""}}

if ip_blocklist is not None:
    try:
        ip_blocklist.add_extra_file(SYNCED_LIST_PATH)
    except Exception as _exc:  # noqa: BLE001
        print(f"[target-app] WARNING: could not register the pushed blocklist ({_exc})")


def get_config() -> dict:
    """Current pushed settings; re-read when the file changes (works with several worker processes)."""
    try:
        mtime = os.path.getmtime(CONFIG_PATH)
    except OSError:
        mtime = None
    if mtime != _config_cache["mtime"]:
        data = {"auto_block": True, "blocklist_sha": ""}
        if mtime is not None:
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    data["auto_block"] = bool(loaded.get("auto_block", True))
                    data["blocklist_sha"] = str(loaded.get("blocklist_sha", ""))
            except (OSError, ValueError):
                pass
        _config_cache["mtime"] = mtime
        _config_cache["data"] = data
    return _config_cache["data"]


def save_config(data: dict) -> None:
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"auto_block": bool(data.get("auto_block", True)), "blocklist_sha": str(data.get("blocklist_sha", ""))}, f)
    os.replace(tmp, CONFIG_PATH)


@app.before_request
def block_anonymizer_networks():
    if ip_blocklist is None or request.path in _ANON_EXEMPT_PATHS or request.path.startswith("/internal/"):
        return None
    match = ip_blocklist.lookup(client_ip())
    if match is None:
        return None

    blocking = bool(get_config().get("auto_block", True))
    event = "ANONYMIZER_BLOCKED" if blocking else "ANONYMIZER_ALLOWED"
    ip = match["ip"]
    now = time.time()
    if now - _anon_last_logged.get((event, ip), 0.0) >= ANON_LOG_INTERVAL_SECONDS:
        _anon_last_logged[(event, ip)] = now
        log_event(
            event,
            ip=ip,
            category=match["category"],
            label=match["label"].replace(" ", "_"),
            path=request.path.replace(" ", "_"),
        )
    if blocking:
        return "Access denied: connections from anonymizing networks (VPN, Tor, open proxies) are not permitted.", 403
    return None  # auto-block is off: let them through (logged above)


def _is_locked(username: str) -> bool:
    until = _locked_until.get(username)
    return until is not None and time.time() < until


def _record_failed_login(username: str) -> bool:
    """
    Tracks a failed login for `username` and returns True the moment this
    attempt pushes it over LOCKOUT_THRESHOLD within the window (i.e. the
    instant the account transitions to locked -- used so ACCOUNT_LOCKED is
    logged exactly once per lockout, not on every attempt after).
    """
    now = time.time()
    window = _failed_attempts[username]
    window.append(now)
    while window and now - window[0] > LOCKOUT_WINDOW_SECONDS:
        window.popleft()
    if len(window) >= LOCKOUT_THRESHOLD and not _is_locked(username):
        _locked_until[username] = now + LOCKOUT_DURATION_SECONDS
        return True
    return False


def _is_ip_blocked(ip: str) -> bool:
    until = _ip_blocked_until.get(ip)
    return until is not None and time.time() < until


def _record_traversal_attempt(ip: str) -> bool:
    """
    Same shape as _record_failed_login() above, but keyed by IP: tracks a
    path-traversal attempt for `ip` and returns True the instant this
    attempt pushes it over TRAVERSAL_BLOCK_THRESHOLD within the window --
    used so IP_BLOCKED is logged exactly once per block, not on every
    attempt after.
    """
    now = time.time()
    window = _traversal_attempts[ip]
    window.append(now)
    while window and now - window[0] > TRAVERSAL_BLOCK_WINDOW_SECONDS:
        window.popleft()
    if len(window) >= TRAVERSAL_BLOCK_THRESHOLD and not _is_ip_blocked(ip):
        _ip_blocked_until[ip] = now + TRAVERSAL_BLOCK_DURATION_SECONDS
        return True
    return False


def _is_safe_upload_path(filename: str) -> str | None:
    """
    Resolves `filename` against UPLOAD_DIR and returns the safe absolute
    path only if it's actually still inside UPLOAD_DIR. Returns None for
    anything that would escape it (e.g. `../../etc/passwd`) -- the caller
    logs that as PATH_TRAVERSAL_ATTEMPT and refuses the request. This is a
    real, working guard (the read genuinely happens or genuinely doesn't),
    not a simulated check.
    """
    candidate = os.path.abspath(os.path.join(UPLOAD_DIR, filename))
    upload_root = os.path.abspath(UPLOAD_DIR)
    if candidate == upload_root or not candidate.startswith(upload_root + os.sep):
        return None
    return candidate


@app.route("/")
def index():
    if session.get("logged_in"):
        return render_template("dashboard.html", username=session.get("username"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = client_ip()

        if _is_locked(username):
            log_event("LOGIN_BLOCKED", ip=ip, username=username)
            error = "This account is temporarily locked due to repeated failed logins. Try again later."
            return render_template("login.html", error=error)

        if username in VALID_USERS and VALID_USERS[username] == password:
            session["logged_in"] = True
            session["username"] = username
            log_event("LOGIN_SUCCESS", ip=ip, username=username)
            return redirect(url_for("index"))

        log_event("LOGIN_FAILED", ip=ip, username=username)
        if _record_failed_login(username):
            log_event("ACCOUNT_LOCKED", ip=ip, username=username, threshold=LOCKOUT_THRESHOLD)
        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/records")
def records():
    """The 'objective' data behind the login -- a fake customer table."""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("records.html", records=FAKE_CUSTOMER_RECORDS, username=session.get("username"))


@app.route("/files")
def files_list():
    """Lists uploaded files with links to download each one."""
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    try:
        names = sorted(os.listdir(UPLOAD_DIR))
    except FileNotFoundError:
        names = []
    return render_template("files.html", filenames=names, username=session.get("username"))


@app.route("/files/<path:requested_name>")
def download_file(requested_name):
    """
    Serves a file from uploads/ -- but only if it actually resolves inside
    uploads/. A request like /files/../../etc/passwd or an absolute path
    is *meant* to be detected and logged as PATH_TRAVERSAL_ATTEMPT and
    refused (403), not silently sandboxed and forgotten -- the point is
    for the SOAR to see and alert on the attempt.

    In practice, a ".." payload in the URL PATH itself (this route) never
    reaches this function at all: Werkzeug's dev server (and effectively
    every real HTTP server/WSGI layer, per RFC 3986) resolves dot-segments
    in the path before Flask's router even sees the request, so
    /files/../../etc/passwd -- or its %2e%2e-encoded form -- collapses to
    /etc/passwd at the HTTP layer and just 404s on "no matching route",
    never running _is_safe_upload_path() below. This route still exists
    for legitimate downloads (real filenames never contain ".." anyway),
    but see download_file_query() below for the endpoint that can actually
    be used to demonstrate/detect a traversal attempt.
    """
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    ip = client_ip()
    if _is_ip_blocked(ip):
        log_event("IP_BLOCKED_REQUEST", ip=ip, username=session.get("username"))
        abort(403)

    safe_path = _is_safe_upload_path(requested_name)
    if safe_path is None:
        log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            ip=ip,
            username=session.get("username"),
            requested=requested_name.replace(" ", "_"),
        )
        if _record_traversal_attempt(ip):
            log_event("IP_BLOCKED", ip=ip, username=session.get("username"), threshold=TRAVERSAL_BLOCK_THRESHOLD)
        abort(403)
    if not os.path.isfile(safe_path):
        abort(404)

    return send_file(safe_path, as_attachment=True)


@app.route("/files/download")
def download_file_query():
    """
    Same safety check and logging as download_file() above, but takes the
    filename from a query parameter (?path=...) instead of a URL path
    segment -- e.g. /files/download?path=../../etc/passwd.

    This is what actually lets a traversal attempt reach
    _is_safe_upload_path() and get blocked/logged/alerted on: a query
    string isn't subject to the server's own path dot-segment resolution
    (that only applies to the URL PATH, per RFC 3986), so "../" survives
    here exactly as typed. It's also the more realistic shape of a real
    path-traversal bug in the wild -- a filename read from user input
    (a query param, a form field, a JSON body), not a raw routed URL
    segment.
    """
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    ip = client_ip()
    if _is_ip_blocked(ip):
        log_event("IP_BLOCKED_REQUEST", ip=ip, username=session.get("username"))
        abort(403)

    requested_name = request.args.get("path", "")
    safe_path = _is_safe_upload_path(requested_name)
    if safe_path is None:
        log_event(
            "PATH_TRAVERSAL_ATTEMPT",
            ip=ip,
            username=session.get("username"),
            requested=requested_name.replace(" ", "_"),
        )
        if _record_traversal_attempt(ip):
            log_event("IP_BLOCKED", ip=ip, username=session.get("username"), threshold=TRAVERSAL_BLOCK_THRESHOLD)
        abort(403)
    if not os.path.isfile(safe_path):
        abort(404)

    return send_file(safe_path, as_attachment=True)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            filename = uploaded.filename.replace("/", "_").replace("\\", "_")
            dest_path = os.path.join(UPLOAD_DIR, filename)
            uploaded.save(dest_path)

            with open(dest_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()

            ext = os.path.splitext(filename)[1].lower()
            ip = client_ip()
            username = session.get("username")

            if ext in SUSPICIOUS_EXTENSIONS:
                # Logged as its own event, phrased so the platform's
                # existing keyword->MITRE mapping (mitre_mapping.py) picks
                # it up as potential malware delivery even before the hash
                # comes back from VirusTotal.
                log_event(
                    "SUSPICIOUS_FILE_UPLOADED",
                    ip=ip,
                    username=username,
                    filename=filename,
                    extension=ext,
                    sha256=sha256,
                )

            log_event(
                "FILE_UPLOADED",
                ip=ip,
                username=username,
                filename=filename,
                sha256=sha256,
            )
            message = f"Uploaded '{filename}' (sha256={sha256[:16]}...)"

    return render_template("upload.html", message=message)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/internal/logs")
def internal_logs():
    """
    Returns raw log bytes starting at ?since=<byte offset>, as plain text.
    Requires ?token=<INTERNAL_LOGS_TOKEN> (or an X-Internal-Token header) --
    wrong/missing token gets a 403, same as if this endpoint didn't exist.

    This is the HTTPS equivalent of `tail -c +offset` for hosts (like
    PythonAnywhere's free tier) that don't give you SSH access to fetch the
    file directly. detection-agent/rules_target_http.py is the client for
    this endpoint.
    """
    token = request.args.get("token") or request.headers.get("X-Internal-Token")
    if token != INTERNAL_LOGS_TOKEN:
        abort(403)

    since = request.args.get("since", default=0, type=int)
    if since < 0:
        since = 0

    if not os.path.exists(LOG_PATH):
        return "", 200, {"Content-Type": "text/plain", "X-Log-Size": "0"}

    with open(LOG_PATH, "rb") as f:
        f.seek(since)
        chunk = f.read()

    total_size = os.path.getsize(LOG_PATH)
    return chunk, 200, {"Content-Type": "text/plain", "X-Log-Size": str(total_size)}


def _internal_auth() -> None:
    """Same shared secret as /internal/logs. Wrong or missing token = 403, as if the page didn't exist."""
    token = request.args.get("token") or request.headers.get("X-Internal-Token")
    if token != INTERNAL_LOGS_TOKEN:
        abort(403)


@app.route("/internal/config", methods=["GET", "POST"])
def internal_config():
    """
    GET returns the settings this app is running with. POST (from the SOAR's
    watcher) updates them: {"auto_block": bool, "blocklist_text": str,
    "blocklist_sha": str} -- every key optional.
    """
    _internal_auth()
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
        cfg = dict(get_config())
        if "auto_block" in body:
            cfg["auto_block"] = bool(body["auto_block"])
        text = body.get("blocklist_text")
        if isinstance(text, str):
            if len(text) > 8_000_000:
                abort(413)
            tmp = SYNCED_LIST_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
            os.replace(tmp, SYNCED_LIST_PATH)
            cfg["blocklist_sha"] = str(body.get("blocklist_sha") or "")
        save_config(cfg)
    cfg = get_config()
    return jsonify({"auto_block": cfg["auto_block"], "blocklist_sha": cfg["blocklist_sha"]})


# --- file-store snapshot, for ransomware detection on a hosted copy -----------
# The detection watcher cannot read this server's disk when the app runs on
# PythonAnywhere, so it asks for a snapshot of the SCADA file store instead and
# runs the same ransomware checks on it (detection-agent/rules_ransomware.py).
_RANSOM_NOTE_EXTENSIONS = {".txt", ".html", ".htm", ".hta", ".rtf"}
_RANSOM_NOTE_NAME_TOKENS = (
    "decrypt", "ransom", "recover_your", "restore_your", "your_files", "files_encrypted",
    "encrypted_files", "how_to_recover", "how_to_restore", "please_read_me",
)
_RANSOM_NOTE_CONTENT_WORDS = ("bitcoin", "btc", "monero", "decrypt", "ransom", "your files", "wallet", "encrypted")
_SNAPSHOT_MAX_FILES = 500
_SNAPSHOT_ENTROPY_BYTES = 65536
_SNAPSHOT_MIN_BYTES = 128
_entropy_memo: dict[str, tuple] = {}   # path -> (mtime, size, entropy)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _snapshot_entropy(path: str, mtime: float, size: int):
    memo = _entropy_memo.get(path)
    if memo and memo[0] == mtime and memo[1] == size:
        return memo[2]
    try:
        with open(path, "rb") as f:
            data = f.read(_SNAPSHOT_ENTROPY_BYTES)
    except OSError:
        return None
    value = _shannon_entropy(data) if len(data) >= _SNAPSHOT_MIN_BYTES else None
    _entropy_memo[path] = (mtime, size, value)
    return value


def _snapshot_is_note(path: str, name: str, size: int) -> bool:
    low = name.lower()
    if os.path.splitext(low)[1] not in _RANSOM_NOTE_EXTENSIONS:
        return False
    if any(token in low for token in _RANSOM_NOTE_NAME_TOKENS):
        return True
    if size > 8192:
        return False
    try:
        with open(path, "r", errors="ignore") as f:
            text = f.read(8192).lower()
    except OSError:
        return False
    return sum(1 for w in _RANSOM_NOTE_CONTENT_WORDS if w in text) >= 2


@app.route("/internal/files")
def internal_files():
    """State of the uploads folder: name, size, modified time, entropy, and whether it looks like a ransom note."""
    _internal_auth()
    files = []
    for root, _dirs, names in os.walk(UPLOAD_DIR):
        for name in names:
            if name.startswith("."):
                continue
            if len(files) >= _SNAPSHOT_MAX_FILES:
                break
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            files.append({
                "path": os.path.relpath(path, UPLOAD_DIR).replace(os.sep, "/"),
                "mtime": st.st_mtime,
                "size": st.st_size,
                "entropy": _snapshot_entropy(path, st.st_mtime, st.st_size),
                "note": _snapshot_is_note(path, name, st.st_size),
            })
    return jsonify({"files": files})


# --- demo-only ransomware trigger -----------------------------------------------
# Lets detection-agent/simulate_ransomware_remote.py stage a (harmless, reversible)
# ransomware attack on this server's demo files. Off unless ENABLE_DEMO_ENDPOINTS=1.
DEMO_STATE_PATH = os.path.join(BASE_DIR, ".ransomware_demo_state.json")
try:
    from ransomware_demo import Demo as _RansomwareDemo
except ImportError:  # the module wasn't copied next to app.py
    _RansomwareDemo = None


@app.route("/internal/demo/ransomware", methods=["POST"])
def internal_demo_ransomware():
    _internal_auth()
    if os.environ.get("ENABLE_DEMO_ENDPOINTS") != "1" or _RansomwareDemo is None:
        return jsonify({"ok": False, "message": "Demo endpoints are off. Set ENABLE_DEMO_ENDPOINTS=1 on the server and make sure ransomware_demo.py is next to app.py."}), 403
    body = request.get_json(silent=True) or {}
    action = body.get("action") or request.args.get("action")
    demo = _RansomwareDemo(UPLOAD_DIR, DEMO_STATE_PATH)
    handlers = {
        "prepare": demo.prepare,
        "encrypt_next": demo.encrypt_next,
        "note": demo.drop_note,
        "restore": demo.restore,
        "cleanup": demo.cleanup,
        "status": demo.status,
    }
    if action not in handlers:
        return jsonify({"ok": False, "message": f"Unknown action. Use one of: {', '.join(handlers)}"}), 400
    return jsonify(handlers[action]())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
