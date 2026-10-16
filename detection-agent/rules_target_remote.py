"""
Remote (cloud) version of the target-app watcher.

Use this instead of rules_target.py's check_target_app() when the target
app is deployed on a separate cloud VM (e.g. Oracle Cloud) with a public
URL, and your SOAR backend/watcher stay private on your own PC.

How it works: every poll, this SSHes into the cloud VM and runs a single
`tail -c +<offset>` command to fetch only the log bytes written since the
last check, using your machine's normal `ssh` client (no new Python
dependency, no exposed port on your end -- your PC only makes OUTBOUND
connections to the VM, nothing reaches in). The fetched lines are handed
to rules_target.py's process_new_lines(), so the actual detection logic
(brute-force, file-upload-to-VirusTotal, correlation) is identical to the
local version -- only how the log lines are obtained differs.

Setup: fill in the four settings below (or set them as environment
variables of the same names) once your Oracle Cloud VM is up and the
target app is deployed and running on it.

    SOAR_SSH_HOST=<vm public ip>
    SOAR_SSH_USER=ubuntu
    SOAR_SSH_KEY_PATH=/path/to/your-private-key.key
    SOAR_REMOTE_LOG_PATH=/home/ubuntu/AI-SOAR-Platform/target-app/logs/access.log

Not tested against a real VM yet (this was built before your Oracle Cloud
instance existed) -- the SSH command itself is standard and simple, but
run detection-agent/watcher_remote.py once against your actual VM and
confirm alerts show up before relying on it for the demo.
"""

import os
import subprocess

from rules_target import process_new_lines

SSH_HOST = os.getenv("SOAR_SSH_HOST", "")
SSH_USER = os.getenv("SOAR_SSH_USER", "ubuntu")
SSH_KEY_PATH = os.getenv("SOAR_SSH_KEY_PATH", "")
SSH_PORT = os.getenv("SOAR_SSH_PORT", "22")
REMOTE_LOG_PATH = os.getenv(
    "SOAR_REMOTE_LOG_PATH", "/home/ubuntu/AI-SOAR-Platform/target-app/logs/access.log"
)

SSH_TIMEOUT_SECONDS = 8

_remote_log_pos = 0
_config_warned = False


def _ssh_base_args() -> list[str]:
    return [
        "ssh",
        "-i", SSH_KEY_PATH,
        "-p", str(SSH_PORT),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={SSH_TIMEOUT_SECONDS}",
        "-o", "BatchMode=yes",  # never hang waiting for a password prompt
        f"{SSH_USER}@{SSH_HOST}",
    ]


def _is_configured() -> bool:
    global _config_warned
    if SSH_HOST and SSH_KEY_PATH:
        return True
    if not _config_warned:
        _config_warned = True
        print(
            "[detection-agent] SOAR_SSH_HOST / SOAR_SSH_KEY_PATH not set -- "
            "rules_target_remote is inactive. Set them once your cloud VM is up "
            "(see rules_target_remote.py's module docstring)."
        )
    return False


def prime_remote_log_position():
    """
    Call once at startup: finds the current size of the remote log file so
    the watcher only reacts to lines written AFTER it started, not the
    server's entire history (e.g. from earlier testing).
    """
    global _remote_log_pos
    if not _is_configured():
        return

    try:
        result = subprocess.run(
            _ssh_base_args() + [f"wc -c < {REMOTE_LOG_PATH} 2>/dev/null || echo 0"],
            capture_output=True,
            text=True,
            timeout=SSH_TIMEOUT_SECONDS,
        )
        _remote_log_pos = int(result.stdout.strip() or 0)
        print(f"[detection-agent] Remote log primed at offset {_remote_log_pos} bytes on {SSH_HOST}")
    except (subprocess.TimeoutExpired, ValueError, FileNotFoundError) as exc:
        print(f"[detection-agent] WARNING: could not prime remote log position ({exc}). Starting from 0.")
        _remote_log_pos = 0


def check_target_app_remote() -> list[dict]:
    """Fetches new log bytes from the cloud VM over SSH and runs the shared detection logic."""
    global _remote_log_pos

    if not _is_configured():
        return []

    try:
        # tail -c +N is 1-indexed and means "starting at byte N" -- so +offset+1
        # gives everything written since we last read `offset` bytes.
        result = subprocess.run(
            _ssh_base_args() + [f"tail -c +{_remote_log_pos + 1} {REMOTE_LOG_PATH} 2>/dev/null"],
            capture_output=True,
            timeout=SSH_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"[detection-agent] WARNING: SSH to {SSH_HOST} timed out -- skipping this cycle.")
        return []
    except FileNotFoundError:
        print("[detection-agent] WARNING: 'ssh' command not found on this machine.")
        return []

    if result.returncode != 0:
        stderr = result.stderr.decode(errors="ignore").strip()
        print(f"[detection-agent] WARNING: SSH to {SSH_HOST} failed (exit {result.returncode}): {stderr}")
        return []

    raw_bytes = result.stdout
    if not raw_bytes:
        return []

    _remote_log_pos += len(raw_bytes)
    new_lines = raw_bytes.decode(errors="ignore").splitlines(keepends=True)
    return process_new_lines(new_lines)


ALL_REMOTE_TARGET_RULES = [check_target_app_remote]
