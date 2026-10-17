"""
Detection rules for Sysmon events.

analyze(event) does two jobs for every event the agent reads:

  1. Builds a one-line activity item for the device's feed on the dashboard
     ("Process started: powershell.exe ...") -- so the Assets tab reflects
     what the device is doing, not only what is malicious.
  2. Checks the event against the rules below and returns findings for
     anything suspicious. The agent posts each finding to the normal
     POST /alerts pipeline (AI severity, MITRE, risk score, playbook).

Rules (each has a rule_key that can be switched on/off in the dashboard's
Detection Rules tab):

  sysmon_suspicious_process   encoded / download-and-run PowerShell, certutil and
                              bitsadmin downloads, mshta / regsvr32 / rundll32 abuse,
                              Office apps spawning shells, Mimikatz
  sysmon_credential_dumping   a non-system process opening LSASS with memory-read
                              rights, procdump / comsvcs MiniDump against LSASS
  sysmon_autorun_persistence  Run / RunOnce keys pointing at temp or user-writable
                              folders or script hosts, files dropped into the Startup folder
  sysmon_malicious_network    a connection to an address on the VPN/Tor/proxy blocklist,
                              or a script host / Office app talking to a remote address
  sysmon_ransomware           a burst of files with ransomware extensions, and
                              shadow-copy / recovery deletion commands
  sysmon_policy_violation     (sysmon_policy.py) too long on streaming / social media /
                              games, or a VPN / Tor client started
  sysmon_malicious_website    (sysmon_policy.py) a DNS lookup of a known-malicious domain

The finding text is worded so the platform's keyword-based MITRE mapping picks
the right technique (see threat-intelligence/mitre_mapping.py).
"""

import ipaddress
import ntpath
import re
import time
from collections import deque

# -- rule keys -------------------------------------------------------------
RULE_PROCESS = "sysmon_suspicious_process"
RULE_CREDENTIALS = "sysmon_credential_dumping"
RULE_AUTORUN = "sysmon_autorun_persistence"
RULE_NETWORK = "sysmon_malicious_network"
RULE_RANSOMWARE = "sysmon_ransomware"

COOLDOWN_SECONDS = 60          # the same finding about the same device is raised at most once per minute
RANSOM_FILE_THRESHOLD = 5      # this many ransomware-extension files ...
RANSOM_WINDOW_SECONDS = 30     # ... inside this window is a ransomware burst

RANSOM_EXTENSIONS = {
    ".locked", ".lock", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".cry",
    ".locky", ".cerber", ".wncry", ".wcry", ".ryk", ".conti", ".akira", ".lockbit",
}
RANSOM_NOTE_TOKENS = ("decrypt", "ransom", "recover_your", "restore_your", "your_files", "how_to_recover")

OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe"}
SHELLS_AND_SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
SCRIPT_HOSTS_NETWORK = {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"}

# Processes that legitimately read LSASS. Anything else asking for memory-read rights is suspect.
LSASS_TRUSTED_SOURCES = {
    "wininit.exe", "csrss.exe", "services.exe", "svchost.exe", "lsass.exe", "smss.exe", "lsm.exe",
    "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "vmtoolsd.exe", "wmiprvse.exe",
}
LSASS_DANGEROUS_ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x1f1fff", "0x1f0fff"}

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "224.0.0.0/4", "0.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]
_RISKY_AUTORUN_TARGET = re.compile(
    r"\\appdata\\|\\temp\\|\\users\\public\\|\\programdata\\|\\downloads\\|powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|\.(ps1|vbs|js|bat|hta)\b",
    re.I,
)


def base(path: str | None) -> str:
    """'C:\\Windows\\System32\\cmd.exe' -> 'cmd.exe' (lower case)."""
    return ntpath.basename(path or "").lower()


def is_remote(ip: str | None) -> bool:
    """True for an address that is not loopback / link-local / private LAN / multicast."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return not any(addr.version == n.version and addr in n for n in _PRIVATE_NETS)


def _clip(text: str, n: int = 160) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


# -- process creation patterns ---------------------------------------------
# (rule_key, regex-tester, finding-text) in priority order; the first match wins per event.

def _process_findings(data: dict) -> list[tuple[str, str]]:
    image = base(data.get("Image"))
    parent = base(data.get("ParentImage"))
    cmd = (data.get("CommandLine") or "")
    low = cmd.lower()
    original = (data.get("OriginalFileName") or "").lower()
    shown = _clip(cmd)
    found: list[tuple[str, str]] = []

    # Credential-theft tools
    if "mimikatz" in image or "mimikatz" in original or "mimikatz" in low or "sekurlsa::" in low or "lsadump::" in low:
        found.append((RULE_PROCESS, f"Credential dumping tool Mimikatz executed on endpoint: {shown}"))
    if ("procdump" in image or "procdump" in low) and "lsass" in low:
        found.append((RULE_CREDENTIALS, f"Credential dumping attempt: ProcDump used against LSASS memory ({shown})"))
    if "comsvcs.dll" in low and "minidump" in low:
        found.append((RULE_CREDENTIALS, f"Credential dumping attempt: rundll32 comsvcs.dll MiniDump of LSASS memory ({shown})"))

    # Ransomware preparation: wiping backups and recovery options
    if (
        (image == "vssadmin.exe" and "delete" in low and "shadows" in low)
        or (image == "wmic.exe" and "shadowcopy" in low and "delete" in low)
        or (image == "wbadmin.exe" and "delete" in low and any(w in low for w in ("catalog", "backup", "systemstatebackup")))
        or (image == "bcdedit.exe" and any(w in low for w in ("recoveryenabled no", "ignoreallfailures")))
    ):
        found.append((RULE_RANSOMWARE, f"Ransomware precursor: shadow copy and recovery deletion command run on endpoint ({shown})"))

    # PowerShell abuse
    if image in ("powershell.exe", "pwsh.exe"):
        if re.search(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[a-z0-9+/=]{20,}", low):
            found.append((RULE_PROCESS, f"Suspicious process on endpoint: encoded PowerShell command launched by {parent or 'unknown parent'} ({shown})"))
        elif re.search(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|net\.webclient|start-bitstransfer", low):
            found.append((RULE_PROCESS, f"Suspicious process on endpoint: PowerShell download-and-execute command launched by {parent or 'unknown parent'} ({shown})"))
        elif ("hidden" in low and ("-w " in low or "-windowstyle" in low)) and ("-nop" in low or "-noprofile" in low or "bypass" in low):
            found.append((RULE_PROCESS, f"Suspicious process on endpoint: hidden PowerShell window with profile or policy bypass ({shown})"))

    # Living-off-the-land binaries
    if image == "certutil.exe" and re.search(r"-urlcache|-decode|-encode|-verifyctl", low):
        found.append((RULE_PROCESS, f"Suspicious process on endpoint: certutil used to download or decode a file ({shown})"))
    if image == "bitsadmin.exe" and "/transfer" in low:
        found.append((RULE_PROCESS, f"Suspicious process on endpoint: bitsadmin used to download a file ({shown})"))
    if image == "mshta.exe" and re.search(r"https?://|vbscript:|javascript:", low):
        found.append((RULE_PROCESS, f"Suspicious process on endpoint: mshta executing remote or inline script ({shown})"))
    if image == "regsvr32.exe" and re.search(r"/i:https?://|scrobj\.dll", low):
        found.append((RULE_PROCESS, f"Suspicious process on endpoint: regsvr32 loading a remote script ({shown})"))
    if image == "rundll32.exe" and "javascript:" in low:
        found.append((RULE_PROCESS, f"Suspicious process on endpoint: rundll32 executing inline script ({shown})"))

    # Office application launching a shell or script host
    if parent in OFFICE_APPS and image in SHELLS_AND_SCRIPT_HOSTS:
        found.append((RULE_PROCESS, f"Malicious Microsoft Office application spawned {image}, suspicious command execution on the endpoint: {parent} -> {image} ({shown})"))

    return found


def _is_ransom_note(path: str) -> bool:
    name = base(path)
    return name.endswith((".txt", ".html", ".htm", ".hta")) and any(t in name for t in RANSOM_NOTE_TOKENS)


class SysmonAnalyzer:
    """
    Stateful (cooldowns and the ransomware burst counter), so keep one instance
    per agent. `check_ip(ip)` returns a blocklist match dict or None -- supplied
    by the agent (it asks the backend); `is_enabled(rule_key)` likewise.
    """

    def __init__(self, check_ip=None, is_enabled=None, tracker=None):
        self._check_ip = check_ip or (lambda ip: None)
        self._is_enabled = is_enabled or (lambda key: True)
        self._tracker = tracker      # PolicyTracker (sysmon_policy.py) or None
        self._last_raised: dict[tuple, float] = {}
        self._ransom_files: deque = deque()   # (monotonic time, path)
        self._ransom_alerted_until = 0.0

    # -- helpers -----------------------------------------------------------
    def _cooldown_ok(self, key: tuple) -> bool:
        now = time.monotonic()
        if now - self._last_raised.get(key, -1e9) < COOLDOWN_SECONDS:
            return False
        self._last_raised[key] = now
        return True

    def _finding(self, rule_key: str, description: str, ip: str | None = None, dedupe: str = "") -> dict | None:
        if not self._is_enabled(rule_key):
            return None
        if not self._cooldown_ok((rule_key, dedupe or description[:80])):
            return None
        return {"rule_key": rule_key, "description": description, "ip": ip}

    # -- main entry point ----------------------------------------------------
    def analyze(self, event: dict) -> tuple[dict | None, list[dict]]:
        """Returns (activity_item_or_None, findings). The activity item has 'flagged' set if anything fired."""
        eid = event.get("event_id")
        d = event.get("data", {})
        findings: list[dict] = []
        activity: dict | None = None
        ts = event["time"].isoformat().replace("+00:00", "Z")

        # Leave out the agent's own footprint and pure noise, so the activity feed shows what the user did:
        # the wevtutil calls it makes to read the log, Sysmon's own reverse-DNS lookups, and "process
        # terminated" events (id 5). None of these are used by any detection rule.
        if eid == 5:
            return None, []
        if eid == 1 and (base(d.get("Image")) == "wevtutil.exe" or base(d.get("ParentImage")) == "wevtutil.exe"):
            return None, []
        if eid == 22 and (base(d.get("Image")) in ("sysmon64.exe", "sysmon.exe")
                          or (d.get("QueryName") or "").rstrip(".").lower().endswith(".arpa")):
            return None, []

        if eid == 1:
            image, parent = base(d.get("Image")), base(d.get("ParentImage"))
            activity = {"event_type": "Process", "summary": f"Process started: {image} ← {parent or '?'}  {_clip(d.get('CommandLine'), 130)}"}
            for rule_key, text in _process_findings(d):
                f = self._finding(rule_key, text, dedupe=f"{image}|{_clip(d.get('CommandLine'), 60)}")
                if f:
                    findings.append(f)
            if self._tracker is not None:
                for rule_key, text in self._tracker.observe_process(event["time"], image):
                    f = self._finding(rule_key, text, dedupe=text[:90])
                    if f:
                        findings.append(f)

        elif eid == 3:
            image = base(d.get("Image"))
            dest, port = d.get("DestinationIp", ""), d.get("DestinationPort", "")
            if str(d.get("Initiated", "true")).lower() == "false" or not is_remote(dest):
                return None, []     # inbound or local-network chatter: not interesting for the feed
            activity = {"event_type": "Network", "summary": f"Network: {image} → {dest}:{port} ({d.get('Protocol', 'tcp')})"}
            match = self._check_ip(dest)
            if match:
                f = self._finding(
                    RULE_NETWORK,
                    f"Malicious endpoint connection to an anonymizing network address ({match['category'].upper()}, {match['label']}): "
                    f"{image} -> {dest}:{port}, suspicious outbound traffic",
                    ip=dest, dedupe=f"anon|{dest}",
                )
                if f:
                    findings.append(f)
            elif image in SCRIPT_HOSTS_NETWORK or image in OFFICE_APPS:
                kind = "Microsoft Office application" if image in OFFICE_APPS else "Script host"
                f = self._finding(
                    RULE_NETWORK,
                    f"{kind} {image} made an outbound connection from the endpoint to {dest}:{port}",
                    ip=dest, dedupe=f"host|{image}|{dest}",
                )
                if f:
                    findings.append(f)

        elif eid == 10:
            source, target = d.get("SourceImage", ""), d.get("TargetImage", "")
            access = (d.get("GrantedAccess") or "").lower()
            activity = {"event_type": "Access", "summary": f"Process access: {base(source)} opened {base(target)} (access {access})"}
            if base(target) == "lsass.exe" and base(source) not in LSASS_TRUSTED_SOURCES and access in LSASS_DANGEROUS_ACCESS:
                f = self._finding(
                    RULE_CREDENTIALS,
                    f"Credential dumping attempt: {base(source)} opened LSASS memory with access {access}",
                    dedupe=f"lsass|{base(source)}",
                )
                if f:
                    findings.append(f)

        elif eid == 11:
            path = d.get("TargetFilename", "")
            image = base(d.get("Image"))
            activity = {"event_type": "File", "summary": f"File created: {_clip(path, 120)} by {image}"}
            ext = ntpath.splitext(path)[1].lower()
            low_path = path.lower()
            if ext in RANSOM_EXTENSIONS or _is_ransom_note(path):
                now = time.monotonic()
                self._ransom_files.append((now, path))
                while self._ransom_files and now - self._ransom_files[0][0] > RANSOM_WINDOW_SECONDS:
                    self._ransom_files.popleft()
                if len(self._ransom_files) >= RANSOM_FILE_THRESHOLD and now > self._ransom_alerted_until:
                    names = [ntpath.basename(p) for _, p in list(self._ransom_files)[:3]]
                    f = self._finding(
                        RULE_RANSOMWARE,
                        f"Ransomware activity on endpoint: {len(self._ransom_files)} files with ransomware extensions "
                        f"created within {RANSOM_WINDOW_SECONDS}s by {image} (for example {', '.join(names)}), mass file rename observed",
                        dedupe="burst",
                    )
                    if f:
                        self._ransom_alerted_until = now + 120
                        findings.append(f)
            elif "\\start menu\\programs\\startup\\" in low_path and ext in (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk"):
                f = self._finding(
                    RULE_AUTORUN,
                    f"Suspicious executable dropped into the user autorun folder, malicious script on the endpoint: {ntpath.basename(path)}",
                    dedupe=f"startup|{path}",
                )
                if f:
                    findings.append(f)

        elif eid in (12, 13, 14):
            target = d.get("TargetObject", "")
            details = d.get("Details", "")
            image = base(d.get("Image"))
            activity = {"event_type": "Registry", "summary": f"Registry {d.get('EventType', 'change')}: {_clip(target[-90:], 90)}  {_clip(details, 70)}"}
            if eid == 13 and re.search(r"\\currentversion\\run(once)?\\", target, re.I) and _RISKY_AUTORUN_TARGET.search(details):
                runkey = target.split("CurrentVersion", 1)[-1].lstrip(chr(92))
                f = self._finding(
                    RULE_AUTORUN,
                    f"Malicious autorun registry key set to launch a suspicious program: {_clip(runkey, 70)} -> {_clip(details, 80)} (by {image})",
                    dedupe=f"run|{target}",
                )
                if f:
                    findings.append(f)

        elif eid == 22:
            domain, program = d.get("QueryName", ""), base(d.get("Image"))
            tag = ""
            if self._tracker is not None:
                label, found = self._tracker.observe_domain(event["time"], domain, program)
                if label:
                    tag = f"  [{label}]"
                for rule_key, text in found:
                    f = self._finding(rule_key, text, dedupe=text[:90])
                    if f:
                        findings.append(f)
            activity = {"event_type": "DNS", "summary": f"DNS query: {domain or '?'} ({program}){tag}"}

        else:
            activity = {"event_type": "Other", "summary": f"Sysmon event {eid}"}

        activity.update({"timestamp": ts, "event_id": eid, "flagged": bool(findings)})
        return activity, findings
