"""
Reading Sysmon events on Windows and turning them into plain Python dicts.

Sysmon (Microsoft Sysinternals) writes what happens on a machine -- every
process started, network connection opened, file dropped, registry key set --
into the Windows event log "Microsoft-Windows-Sysmon/Operational". This module
reads new events from that log with the built-in `wevtutil` tool (no extra
Python packages needed) and parses the XML into:

    {
        "event_id":  1,                       # Sysmon event ID (1 = process created, 3 = network, ...)
        "record_id": 48213,                   # Windows event record number, used to resume where we left off
        "time":      datetime (UTC),
        "computer":  "DESKTOP-ABC",
        "data":      {"Image": "C:\\...\\powershell.exe", "CommandLine": "...", ...},
    }

Reading the Sysmon log needs an elevated (Administrator) prompt.

The same dict shape is produced by simulator.py, so the detection rules
cannot tell a simulated event from a real one.
"""

import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_EVENT_RE = re.compile(r"<Event[ >].*?</Event>", re.S)
_CREATE_NO_WINDOW = 0x08000000  # keeps a console window from flashing on Windows


class SysmonReadError(RuntimeError):
    """Raised with a message a person can act on (not installed, not admin, not Windows)."""


def _parse_time(system_time: str | None) -> datetime:
    """'2026-10-16T12:34:56.789012300Z' (7 fractional digits) -> aware UTC datetime."""
    if not system_time:
        return datetime.now(timezone.utc)
    text = system_time.strip().rstrip("Z")
    match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?", text)
    if not match:
        return datetime.now(timezone.utc)
    base, frac = match.group(1), (match.group(2) or "0")[:6].ljust(6, "0")
    return datetime.fromisoformat(f"{base}.{frac}").replace(tzinfo=timezone.utc)


def parse_event_xml(xml_text: str) -> dict | None:
    """Parses one <Event>...</Event> element from the Windows event log. None if it isn't usable."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    system = root.find(f"{_NS}System")
    if system is None:
        return None
    event_id = system.findtext(f"{_NS}EventID")
    record_id = system.findtext(f"{_NS}EventRecordID")
    time_el = system.find(f"{_NS}TimeCreated")
    data = {}
    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for item in event_data.findall(f"{_NS}Data"):
            name = item.get("Name")
            if name:
                data[name] = item.text or ""
    try:
        return {
            "event_id": int(event_id),
            "record_id": int(record_id) if record_id else None,
            "time": _parse_time(time_el.get("SystemTime") if time_el is not None else None),
            "computer": system.findtext(f"{_NS}Computer") or "",
            "data": data,
        }
    except (TypeError, ValueError):
        return None


def parse_events(xml_text: str) -> list[dict]:
    """`wevtutil ... /f:xml` prints one <Event> element per event with no wrapper; split and parse them."""
    events = []
    for chunk in _EVENT_RE.findall(xml_text or ""):
        ev = parse_event_xml(chunk)
        if ev:
            events.append(ev)
    return events


def _run_wevtutil(args: list[str]) -> str:
    if platform.system() != "Windows":
        raise SysmonReadError("Reading Sysmon needs Windows. On another system use --simulate.")
    try:
        result = subprocess.run(
            ["wevtutil", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            creationflags=_CREATE_NO_WINDOW,
        )
    except FileNotFoundError as exc:
        raise SysmonReadError("wevtutil.exe was not found (it ships with Windows).") from exc
    except subprocess.TimeoutExpired as exc:
        raise SysmonReadError("wevtutil timed out reading the Sysmon log.") from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        if "denied" in message.lower():
            raise SysmonReadError("Access denied reading the Sysmon log. Run this window as Administrator.")
        if "not found" in message.lower() or "channel" in message.lower():
            raise SysmonReadError(
                "The Sysmon log was not found. Is Sysmon installed? "
                "(see endpoint-agent/README.md), or use --simulate."
            )
        raise SysmonReadError(f"wevtutil failed: {message[:300]}")
    return result.stdout


def sysmon_installed() -> bool:
    """True if the Sysmon event log exists on this machine."""
    try:
        _run_wevtutil(["gl", SYSMON_LOG])
        return True
    except SysmonReadError:
        return False


def latest_record_id() -> int:
    """Record number of the newest Sysmon event (0 if the log is empty) -- where to start so history isn't replayed."""
    out = _run_wevtutil(["qe", SYSMON_LOG, "/c:1", "/rd:true", "/f:xml"])
    events = parse_events(out)
    return events[0]["record_id"] or 0 if events else 0


def read_new_events(after_record_id: int, max_events: int = 500) -> list[dict]:
    """Events with a record number above `after_record_id`, oldest first."""
    query = f"*[System[(EventRecordID>{int(after_record_id)})]]"
    out = _run_wevtutil(["qe", SYSMON_LOG, f"/q:{query}", "/f:xml", f"/c:{int(max_events)}"])
    return parse_events(out)


def read_recent_events(count: int) -> list[dict]:
    """The last `count` events, oldest first (used by --backfill)."""
    out = _run_wevtutil(["qe", SYSMON_LOG, f"/c:{int(count)}", "/rd:true", "/f:xml"])
    return list(reversed(parse_events(out)))
