"""
Detection rules for the live watcher (watcher.py).

Each rule looks at machine state (running processes, active network
connections, the auth log) and returns a list of "finding" dicts when it
sees something worth raising as an alert. A finding maps directly onto the
existing POST /alerts request body (documentation/api-contract.md) --
watcher.py just adds the timestamp and does the HTTP call.

These rules are deliberately simple and pattern-based (not a full EDR) --
this exists to demonstrate the AI-SOAR pipeline reacting to *real* activity
on the machine in real time, not to be a production intrusion detection
system. The whole point: something bad happens on the box -> a finding
fires here -> backend/main.py's existing classify -> enrich -> score ->
respond pipeline takes it from there unchanged.
"""

import re
import time
from collections import defaultdict, deque

import psutil

from rule_state import is_enabled

# ---------------------------------------------------------------------------
# Rule 1: suspicious process spawn (reverse shells, download-and-execute,
# encoded/obfuscated shell invocations -- classic LOLBin / post-exploitation
# patterns). Matches against a process's full command line.
# ---------------------------------------------------------------------------

_SUSPICIOUS_CMDLINE_PATTERNS = [
    (re.compile(r"/dev/tcp/"), "Reverse shell via /dev/tcp redirection"),
    (re.compile(r"\bnc\b.*-e\s"), "Netcat reverse shell (-e flag spawning a shell)"),
    (re.compile(r"\b(bash|sh)\s+-i\b"), "Interactive shell spawned suspiciously (bash -i)"),
    (re.compile(r"(curl|wget).*(\||&&).*\b(sh|bash)\b"), "Download-and-execute pipeline (curl/wget piped to a shell)"),
    (re.compile(r"base64\s+-d.*\|\s*(sh|bash)"), "Base64-decoded payload piped directly to a shell"),
    (re.compile(r"python[0-9.]*\s+-c\s+.*socket\.socket"), "Python one-liner opening a raw socket (reverse-shell pattern)"),
    (re.compile(r"chmod\s+\+x\s+/tmp/"), "Making a file in /tmp executable (common dropper behavior)"),
]

_seen_pids: set[int] = set()


RULE_KEY_SUSPICIOUS_PROCESS = "suspicious_process"


def check_suspicious_processes() -> list[dict]:
    if not is_enabled(RULE_KEY_SUSPICIOUS_PROCESS):
        return []
    findings = []
    for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
        try:
            pid = proc.info["pid"]
            if pid in _seen_pids:
                continue
            cmdline = " ".join(proc.info["cmdline"] or [])
            if not cmdline:
                continue
            for pattern, label in _SUSPICIOUS_CMDLINE_PATTERNS:
                if pattern.search(cmdline):
                    _seen_pids.add(pid)
                    findings.append(
                        {
                            "source": "Endpoint",
                            "description": f"{label}: `{cmdline.strip()[:200]}` (pid={pid}, user={proc.info.get('username')})",
                            "ip": None,
                            "hash": None,
                            "rule_key": RULE_KEY_SUSPICIOUS_PROCESS,
                        }
                    )
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return findings


# ---------------------------------------------------------------------------
# Rule 2: brute-force login attempts. Tails the system auth log for repeated
# "Failed password" lines from the same source IP within a short window.
# ---------------------------------------------------------------------------

AUTH_LOG_CANDIDATES = ["/var/log/auth.log", "/var/log/secure"]
_FAILED_RE = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
_ACCEPTED_RE = re.compile(r"Accepted password.*from (\d+\.\d+\.\d+\.\d+)")

_auth_log_path = None
_auth_log_pos = 0
_failed_attempts: dict[str, deque] = defaultdict(deque)
_brute_force_alerted: set[str] = set()

BRUTE_FORCE_THRESHOLD = 4       # failed attempts...
BRUTE_FORCE_WINDOW_SECONDS = 60  # ...within this many seconds triggers an alert


def _find_auth_log():
    global _auth_log_path
    if _auth_log_path is not None:
        return _auth_log_path
    import os

    for candidate in AUTH_LOG_CANDIDATES:
        if os.path.exists(candidate):
            _auth_log_path = candidate
            return candidate
    return None


RULE_KEY_LINUX_SSH_BRUTE_FORCE = "linux_ssh_brute_force"


def check_brute_force() -> list[dict]:
    global _auth_log_pos

    if not is_enabled(RULE_KEY_LINUX_SSH_BRUTE_FORCE):
        return []

    path = _find_auth_log()
    if path is None:
        return []  # no auth log on this system (e.g. sandboxed container) -- rule is a no-op

    findings = []
    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(_auth_log_pos)
            new_lines = f.readlines()
            _auth_log_pos = f.tell()
    except (FileNotFoundError, PermissionError):
        return []

    now = time.time()
    for line in new_lines:
        failed_match = _FAILED_RE.search(line)
        if failed_match:
            ip = failed_match.group(1)
            window = _failed_attempts[ip]
            window.append(now)
            while window and now - window[0] > BRUTE_FORCE_WINDOW_SECONDS:
                window.popleft()
            if len(window) >= BRUTE_FORCE_THRESHOLD and ip not in _brute_force_alerted:
                _brute_force_alerted.add(ip)
                findings.append(
                    {
                        "source": "Linux-Auth",
                        "description": f"Brute-force login attempt detected: {len(window)} failed SSH logins from {ip} within {BRUTE_FORCE_WINDOW_SECONDS}s",
                        "ip": ip,
                        "hash": None,
                        "rule_key": RULE_KEY_LINUX_SSH_BRUTE_FORCE,
                    }
                )
            continue

        accepted_match = _ACCEPTED_RE.search(line)
        if accepted_match:
            ip = accepted_match.group(1)
            if ip in _brute_force_alerted:
                findings.append(
                    {
                        "source": "Linux-Auth",
                        "description": f"Successful login from {ip} immediately after a brute-force pattern was detected -- possible compromised credential",
                        "ip": ip,
                        "hash": None,
                        "rule_key": RULE_KEY_LINUX_SSH_BRUTE_FORCE,
                    }
                )
                _brute_force_alerted.discard(ip)  # reset so a fresh brute-force burst can alert again

    return findings


def prime_auth_log_position():
    """
    Call once at startup so the watcher only reacts to NEW log lines written
    after it started, not the machine's entire login history.
    """
    global _auth_log_pos
    path = _find_auth_log()
    if path is None:
        return
    import os

    _auth_log_pos = os.path.getsize(path)


# ---------------------------------------------------------------------------
# Rule 3: outbound connection to a known-bad IP. Uses a small static
# watchlist for demo purposes -- in a real deployment this would be a live
# threat-intel feed, but the point here is showing the pipeline react to a
# real connection the demo machine actually makes.
# ---------------------------------------------------------------------------

# Add whatever IP you'll actually connect out to during the demo (e.g. an
# EC2 box you control, or a public "known bad" test IP) before presenting.
KNOWN_BAD_IPS = {
    "45.155.205.233",   # example malicious IP already used in threat_intel.py's own demo
    "185.220.101.1",    # example Tor exit node -- commonly flagged
}

_seen_connections: set[tuple] = set()


RULE_KEY_MALICIOUS_IP_CONNECTION = "malicious_ip_connection"


def check_bad_ip_connections() -> list[dict]:
    if not is_enabled(RULE_KEY_MALICIOUS_IP_CONNECTION):
        return []
    findings = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # Needs elevated privileges on some systems (esp. macOS/root-only Linux
        # configs) to see other users' sockets -- run the watcher with sudo
        # if this rule needs to see system-wide connections.
        return []

    for conn in connections:
        if not conn.raddr:
            continue
        remote_ip = conn.raddr.ip
        if remote_ip not in KNOWN_BAD_IPS:
            continue
        key = (conn.pid, remote_ip, conn.raddr.port)
        if key in _seen_connections:
            continue
        _seen_connections.add(key)

        proc_name = "unknown"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        findings.append(
            {
                "source": "Network",
                "description": f"Outbound connection from process '{proc_name}' (pid={conn.pid}) to known-malicious IP {remote_ip}:{conn.raddr.port}",
                "ip": remote_ip,
                "hash": None,
                "rule_key": RULE_KEY_MALICIOUS_IP_CONNECTION,
            }
        )
    return findings


ALL_RULES = [check_suspicious_processes, check_brute_force, check_bad_ip_connections]
