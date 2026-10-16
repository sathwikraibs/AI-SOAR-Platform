"""
Detection rules for the target-app/ demo server (login form + file upload).

Reads target-app/logs/access.log (written by target-app/app.py) and turns
suspicious activity into findings, same shape as rules.py's rules, so
watcher.py can treat them identically -- POST each to the existing
/alerts pipeline and let the already-built classify -> enrich (incl. the
VirusTotal hash check) -> score -> respond flow take over.

Three things happen here:
  1. Brute-force detection on the target app's own login (separate from
     rules.py's OS-level SSH brute-force rule -- this one is app-specific).
  2. Every uploaded file is submitted as an alert with its sha256 in the
     `hash` field. backend/main.py's existing pipeline calls
     threat_intel.py:enrich_alert() on every alert, which already checks
     the hash against VirusTotal (or the heuristic fallback) -- so this
     rule does NOT call VirusTotal itself, it just hands the hash to the
     pipeline that already knows how.
  3. Cross-signal correlation: if the SAME source IP triggers 2+ distinct
     finding types (e.g. a login brute-force AND a file upload) within a
     short window, that's raised as its own higher-priority "multi-stage
     attack" finding -- a small step toward "autonomous investigation"
     rather than just forwarding raw events one at a time.
"""

import os
import re
import time
from collections import defaultdict, deque

from rule_state import is_enabled

RULE_KEY_LOGIN_BRUTE_FORCE = "login_brute_force"
RULE_KEY_CREDENTIAL_STUFFING = "credential_stuffing"
RULE_KEY_PATH_TRAVERSAL = "path_traversal"
RULE_KEY_SUSPICIOUS_FILE_UPLOAD = "suspicious_file_upload"
RULE_KEY_MULTI_STAGE_CORRELATION = "multi_stage_correlation"
RULE_KEY_ANONYMIZER_BLOCK = "anonymizer_ip_block"

TARGET_APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target-app")
ACCESS_LOG_PATH = os.path.join(TARGET_APP_DIR, "logs", "access.log")

_LOG_LINE_RE = re.compile(
    r"^(?P<ts>\S+) (?P<event>\S+) (?P<fields>.*)$"
)

_access_log_pos = 0

# --- brute-force state ---
_failed_logins: dict[str, deque] = defaultdict(deque)
_login_brute_alerted: set[str] = set()
LOGIN_BRUTE_THRESHOLD = 3
LOGIN_BRUTE_WINDOW_SECONDS = 60

# --- credential-stuffing state: same as brute-force above, but tracks how
# many *distinct usernames* have failed from one IP, not just how many
# failures -- 5 failed attempts against one account is brute force, 2+
# failed attempts spread across different accounts from the same IP is
# credential stuffing, a separately meaningful pattern for an analyst. ---
_failed_usernames_by_ip: dict[str, deque] = defaultdict(deque)  # ip -> deque[(timestamp, username)]
_stuffing_alerted: set[str] = set()
CRED_STUFFING_DISTINCT_USERS = 2
CRED_STUFFING_WINDOW_SECONDS = 60

# --- correlation state: source IP -> set of finding kinds seen recently ---
_ip_activity: dict[str, deque] = defaultdict(deque)  # ip -> deque[(timestamp, kind)]
_correlated_alerted: set[str] = set()
CORRELATION_WINDOW_SECONDS = 120

# --- anonymizer-block state: the target app logs ANONYMIZER_BLOCKED at most
# every 30s per IP already; this is a second guard so a long-lived visitor
# produces one alert per cooldown, not one per log line. ---
_anon_alerted_at: dict[str, float] = {}
ANON_ALERT_COOLDOWN_SECONDS = 120


def _parse_fields(field_str: str) -> dict:
    return dict(pair.split("=", 1) for pair in field_str.split(" ") if "=" in pair)


def prime_target_log_position():
    global _access_log_pos
    if os.path.exists(ACCESS_LOG_PATH):
        _access_log_pos = os.path.getsize(ACCESS_LOG_PATH)


def _record_ip_activity(ip: str, kind: str, now: float):
    """Tracks recent finding kinds per IP for the correlation rule below."""
    window = _ip_activity[ip]
    window.append((now, kind))
    while window and now - window[0][0] > CORRELATION_WINDOW_SECONDS:
        window.popleft()


def _check_correlation(ip: str, now: float) -> dict | None:
    if not is_enabled(RULE_KEY_MULTI_STAGE_CORRELATION):
        return None
    if ip in _correlated_alerted:
        return None
    kinds = {kind for _, kind in _ip_activity[ip]}
    if len(kinds) >= 2:
        _correlated_alerted.add(ip)
        return {
            "source": "SOAR-Correlation",
            "description": (
                f"Multi-stage attack pattern detected from {ip}: this IP triggered "
                f"{len(kinds)} distinct attack types within {CORRELATION_WINDOW_SECONDS}s "
                f"({', '.join(sorted(kinds))}) -- escalating beyond individual findings, "
                f"consistent with a single actor probing then acting rather than unrelated noise."
            ),
            "ip": ip,
            "hash": None,
            "rule_key": RULE_KEY_MULTI_STAGE_CORRELATION,
        }
    return None


def process_new_lines(new_lines: list[str]) -> list[dict]:
    """
    The actual detection logic, independent of HOW the log lines were
    obtained. check_target_app() (below) feeds this from a local file;
    rules_target_remote.py feeds it from an SSH pull against a cloud VM.
    Keeping this shared means the brute-force/upload/correlation logic
    only exists once, whether the target app is on this machine or a
    public server elsewhere.
    """
    findings = []
    now = time.time()

    for line in new_lines:
        match = _LOG_LINE_RE.match(line.strip())
        if not match:
            continue
        event = match.group("event")
        fields = _parse_fields(match.group("fields"))
        ip = fields.get("ip", "unknown")

        if event == "LOGIN_FAILED":
            username = fields.get("username", "unknown")

            window = _failed_logins[ip]
            window.append(now)
            while window and now - window[0] > LOGIN_BRUTE_WINDOW_SECONDS:
                window.popleft()
            if len(window) >= LOGIN_BRUTE_THRESHOLD and ip not in _login_brute_alerted:
                _login_brute_alerted.add(ip)
                if is_enabled(RULE_KEY_LOGIN_BRUTE_FORCE):
                    _record_ip_activity(ip, "login_bruteforce", now)
                    findings.append(
                        {
                            "source": "Target-App",
                            "description": (
                                f"Brute-force login attempt on target app: {len(window)} failed logins "
                                f"from {ip} within {LOGIN_BRUTE_WINDOW_SECONDS}s (username tried: {username})"
                            ),
                            "ip": ip,
                            "hash": None,
                            "rule_key": RULE_KEY_LOGIN_BRUTE_FORCE,
                        }
                    )
                    correlated = _check_correlation(ip, now)
                    if correlated:
                        findings.append(correlated)

            # Credential stuffing: distinct from the single-account
            # brute-force check above -- this fires when the SAME ip has
            # failed logins against 2+ DIFFERENT usernames within the
            # window, which brute-force alone doesn't capture (brute-force
            # only counts total failures, regardless of which account).
            stuff_window = _failed_usernames_by_ip[ip]
            stuff_window.append((now, username))
            while stuff_window and now - stuff_window[0][0] > CRED_STUFFING_WINDOW_SECONDS:
                stuff_window.popleft()
            distinct_users = {u for _, u in stuff_window}
            if len(distinct_users) >= CRED_STUFFING_DISTINCT_USERS and ip not in _stuffing_alerted:
                _stuffing_alerted.add(ip)
                if is_enabled(RULE_KEY_CREDENTIAL_STUFFING):
                    _record_ip_activity(ip, "credential_stuffing", now)
                    findings.append(
                        {
                            "source": "Target-App",
                            "description": (
                                f"Credential stuffing detected on target app: failed logins against "
                                f"{len(distinct_users)} different accounts ({', '.join(sorted(distinct_users))}) "
                                f"from {ip} within {CRED_STUFFING_WINDOW_SECONDS}s"
                            ),
                            "ip": ip,
                            "hash": None,
                            "rule_key": RULE_KEY_CREDENTIAL_STUFFING,
                        }
                    )
                    correlated = _check_correlation(ip, now)
                    if correlated:
                        findings.append(correlated)

        elif event == "ACCOUNT_LOCKED":
            # The target app's own app-layer lockout just tripped -- the
            # SOAR should already have alerted on the brute-force pattern
            # before this point, but this confirms the account is now
            # genuinely locked, which matters for the analyst's response.
            if is_enabled(RULE_KEY_LOGIN_BRUTE_FORCE):
                _record_ip_activity(ip, "account_locked", now)
                findings.append(
                    {
                        "source": "Target-App",
                        "description": (
                            f"Account '{fields.get('username', 'unknown')}' was locked by the target app "
                            f"after repeated failed logins from {ip} -- application-layer defense triggered"
                        ),
                        "ip": ip,
                        "hash": None,
                        "rule_key": RULE_KEY_LOGIN_BRUTE_FORCE,
                    }
                )

        elif event == "PATH_TRAVERSAL_ATTEMPT":
            if is_enabled(RULE_KEY_PATH_TRAVERSAL):
                _record_ip_activity(ip, "path_traversal", now)
                findings.append(
                    {
                        "source": "Target-App",
                        "description": (
                            f"Path traversal attempt on target app from {ip}: requested "
                            f"'{fields.get('requested', 'unknown')}' -- request was blocked by the app, "
                            f"consistent with an attempt to read files outside the upload directory"
                        ),
                        "ip": ip,
                        "hash": None,
                        "rule_key": RULE_KEY_PATH_TRAVERSAL,
                    }
                )
                correlated = _check_correlation(ip, now)
                if correlated:
                    findings.append(correlated)

        elif event == "IP_BLOCKED":
            # Mirrors the ACCOUNT_LOCKED handling above: the target app's
            # own app-layer defense just blocked this IP outright after
            # repeated path-traversal attempts. The individual attempts
            # already raised PATH_TRAVERSAL_ATTEMPT findings above -- this
            # is a confirmatory, higher-priority alert that the app itself
            # has now cut the IP off, which matters for the analyst's
            # response (e.g. no need to manually block it).
            if is_enabled(RULE_KEY_PATH_TRAVERSAL):
                _record_ip_activity(ip, "ip_blocked", now)
                findings.append(
                    {
                        "source": "Target-App",
                        "description": (
                            f"IP {ip} was blocked by the target app after repeated path-traversal "
                            f"attempts (threshold: {fields.get('threshold', 'unknown')}) -- "
                            f"application-layer defense triggered"
                        ),
                        "ip": ip,
                        "hash": None,
                        "rule_key": RULE_KEY_PATH_TRAVERSAL,
                    }
                )

        elif event == "IP_BLOCKED_REQUEST":
            # A request from an already-blocked IP -- routine noise once
            # IP_BLOCKED has already fired once for this IP, so this is
            # intentionally not turned into its own alert (it would just
            # spam one alert per rejected request from a known-blocked IP).
            pass

        elif event == "ANONYMIZER_BLOCKED":
            # The target app refused this request on arrival because the
            # source IP is on the VPN / Tor / proxy blocklist (see
            # threat-intelligence/ip_blocklist.py). The block already
            # happened -- this raises the alert so an analyst can see that
            # someone tried to reach the app while hiding their identity.
            # (Switching this rule off only silences the alert; the app
            # keeps blocking.)
            if is_enabled(RULE_KEY_ANONYMIZER_BLOCK) and now - _anon_alerted_at.get(ip, 0.0) >= ANON_ALERT_COOLDOWN_SECONDS:
                _anon_alerted_at[ip] = now
                category = fields.get("category", "unknown").upper()
                label = fields.get("label", "unlabelled").replace("_", " ")
                findings.append(
                    {
                        "source": "Target-App",
                        "description": (
                            f"Connection from an anonymizing network blocked immediately: {ip} is on the "
                            f"{category} blocklist ({label}) and its request to {fields.get('path', '/')} was "
                            f"refused before reaching the application -- the visitor was hiding their real "
                            f"identity behind a VPN, Tor or proxy"
                        ),
                        "ip": ip,
                        "hash": None,
                        "rule_key": RULE_KEY_ANONYMIZER_BLOCK,
                    }
                )

        elif event == "SUSPICIOUS_FILE_UPLOADED":
            if is_enabled(RULE_KEY_SUSPICIOUS_FILE_UPLOAD):
                filename = fields.get("filename", "unknown")
                sha256 = fields.get("sha256")
                # Recorded under the SAME correlation kind as the plain
                # FILE_UPLOADED handler below ("file_upload"), not its own
                # "suspicious_upload" kind. target-app/app.py always logs a
                # FILE_UPLOADED line right after this one for the very same
                # upload (see its upload() view) -- if these used different
                # kind strings, one single risky-extension upload would, on
                # its own, produce two distinct "kinds" for this IP and
                # immediately (and wrongly) trip the multi-stage-correlation
                # rule below, which is meant to catch two genuinely
                # different attack types, not one action logged twice.
                _record_ip_activity(ip, "file_upload", now)
                findings.append(
                    {
                        "source": "Target-App",
                        "description": (
                            f"Suspicious file extension uploaded to target app: '{filename}' "
                            f"({fields.get('extension', 'unknown')}) by {fields.get('username', 'unknown')} "
                            f"from {ip} -- treat as potential malware delivery pending hash verdict"
                        ),
                        "ip": ip,
                        "hash": sha256,
                        "rule_key": RULE_KEY_SUSPICIOUS_FILE_UPLOAD,
                    }
                )
                correlated = _check_correlation(ip, now)
                if correlated:
                    findings.append(correlated)

        elif event == "LOGIN_SUCCESS":
            if ip in _login_brute_alerted:
                if is_enabled(RULE_KEY_LOGIN_BRUTE_FORCE):
                    findings.append(
                        {
                            "source": "Target-App",
                            "description": (
                                f"Successful login from {ip} immediately following a brute-force pattern "
                                f"on the target app -- treat the account as potentially compromised"
                            ),
                            "ip": ip,
                            "hash": None,
                            "rule_key": RULE_KEY_LOGIN_BRUTE_FORCE,
                        }
                    )
                _login_brute_alerted.discard(ip)  # allow a fresh burst to re-alert later

        elif event == "FILE_UPLOADED":
            filename = fields.get("filename", "unknown")
            sha256 = fields.get("sha256")
            _record_ip_activity(ip, "file_upload", now)
            findings.append(
                {
                    "source": "Target-App",
                    "description": (
                        f"File uploaded to target app: '{filename}' by {fields.get('username', 'unknown')} "
                        f"from {ip} -- submitting hash for threat-intel reputation check"
                    ),
                    "ip": ip,
                    "hash": sha256,
                }
            )
            correlated = _check_correlation(ip, now)
            if correlated:
                findings.append(correlated)

    return findings


def check_target_app() -> list[dict]:
    """Local-file version: reads target-app/logs/access.log directly off this machine's disk."""
    global _access_log_pos

    if not os.path.exists(ACCESS_LOG_PATH):
        return []  # target app not running / hasn't logged anything yet

    try:
        with open(ACCESS_LOG_PATH, "r", errors="ignore") as f:
            f.seek(_access_log_pos)
            new_lines = f.readlines()
            _access_log_pos = f.tell()
    except (FileNotFoundError, PermissionError):
        return []

    return process_new_lines(new_lines)


ALL_TARGET_RULES = [check_target_app]
