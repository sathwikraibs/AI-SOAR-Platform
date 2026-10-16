"""
Backs POST /ssh/connect in main.py -- the dashboard's "SSH / Sessions"
panel.

Runs a real SSH connection via paramiko, but deliberately does NOT accept
an arbitrary command string from the request body and exec it. This
endpoint is reachable from a browser tab with no auth in front of it (see
main.py's CORS comment), so turning it into "type any shell command into
a text box and run it over the network" would be a self-inflicted RCE
hole in a project that's supposed to be defending against exactly that
class of bug. Instead it runs one fixed, read-only diagnostic command set
and returns the combined output -- enough to prove the connection really
works without becoming an attack surface.
"""

import socket

import paramiko

CONNECT_TIMEOUT = 6  # seconds

# Fixed, read-only diagnostic commands -- see module docstring for why
# these aren't user-supplied.
DIAGNOSTIC_COMMANDS = ["whoami", "hostname", "uptime"]


def run_diagnostics(host: str, port: int, username: str, password: str | None = None) -> dict:
    """
    Connects to host:port over SSH and runs DIAGNOSTIC_COMMANDS.

    Returns {"connected": True, "output": "<combined output>"} on success,
    or {"connected": False, "error": "<human-readable reason>"} on any
    failure (auth, timeout, unreachable host, ...) -- never raises, so the
    route calling this can turn a failure straight into an HTTP response
    without a try/except of its own.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=CONNECT_TIMEOUT,
            banner_timeout=CONNECT_TIMEOUT,
            auth_timeout=CONNECT_TIMEOUT,
        )
    except paramiko.AuthenticationException:
        return {"connected": False, "error": "Authentication failed -- check the username/password."}
    except (socket.timeout, TimeoutError):
        return {"connected": False, "error": f"Connection to {host}:{port} timed out."}
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return {"connected": False, "error": f"Could not reach {host}:{port} ({exc})."}
    except paramiko.SSHException as exc:
        return {"connected": False, "error": f"SSH negotiation failed ({exc})."}

    try:
        lines = []
        for cmd in DIAGNOSTIC_COMMANDS:
            _stdin, stdout, stderr = client.exec_command(cmd, timeout=CONNECT_TIMEOUT)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            lines.append(f"$ {cmd}")
            if out:
                lines.append(out)
            if err:
                lines.append(f"[stderr] {err}")
            lines.append("")
        return {"connected": True, "output": "\n".join(lines).strip()}
    except Exception as exc:  # noqa: BLE001 - connected fine, but a command failed; report, don't crash
        return {"connected": True, "output": "", "error": f"Connected, but running diagnostics failed ({exc})."}
    finally:
        client.close()
