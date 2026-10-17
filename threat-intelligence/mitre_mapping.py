"""
Lightweight keyword -> MITRE ATT&CK technique mapper.

This is intentionally simple (no ML, no external calls): it scans the
alert's source + description for keywords and returns the best-matching
ATT&CK technique. Good enough for a SOC-triage demo; a real deployment
would use a proper NLP/CTI mapping service.

Reference: https://attack.mitre.org/techniques/enterprise/
"""

# Ordered so more-specific patterns are checked before generic ones.
# Each entry: (keywords, technique_id, technique_name)
_RULES = [
    # Endpoint (Sysmon) acceptable-use findings: first on purpose, because their text
    # can contain a domain name or program name with words like "malware" in it.
    (["acceptable-use policy", "acceptable use policy"], "POLICY-AUP", "Acceptable-Use Policy Violation"),
    (["malicious website", "known-malicious domain"], "T1189", "Drive-by Compromise"),
    (["ransomware", "encrypt", "mass file rename"], "T1486", "Data Encrypted for Impact"),
    (["phishing", "malicious attachment", "malicious link"], "T1566", "Phishing"),
    # NOTE: this used to be ["brute force", "failed login attempts", ...],
    # which never actually matched either brute-force rule's real wording
    # ("Brute-force login attempt", "failed SSH logins", "failed logins")
    # -- every brute-force alert in the platform was silently falling
    # through to UNKNOWN_TECHNIQUE. "brute-force" (hyphen) and "failed
    # login" (no "attempts") match the phrasing rules.py and
    # rules_target.py actually generate.
    (["brute force", "brute-force", "failed login", "credential stuffing"], "T1110", "Brute Force"),
    (["successful login", "unusual login", "impossible travel"], "T1078", "Valid Accounts"),
    (["port scan", "network scan", "reconnaissance"], "T1595", "Active Scanning"),
    (["lateral movement", "psexec", "remote service"], "T1021", "Remote Services"),
    (["privilege escalation", "token manipulation", "elevated"], "T1068", "Exploitation for Privilege Escalation"),
    (["powershell", "encoded command", "obfuscated script"], "T1059", "Command and Scripting Interpreter"),
    (["persistence", "scheduled task", "registry run key", "startup"], "T1053", "Scheduled Task/Job"),
    (["exfiltrat", "data transfer to", "large upload"], "T1041", "Exfiltration Over C2 Channel"),
    (["command and control", "c2 beacon", "beaconing", "callback"], "T1071", "Application Layer Protocol"),
    (["dns tunnel", "unusual dns"], "T1071.004", "Application Layer Protocol: DNS"),
    (["malware", "trojan", "backdoor"], "T1204", "User Execution"),
    # Endpoint (Sysmon) findings. Placed before the broad "dos" keyword below so
    # a command line that happens to contain those letters can't hijack them.
    (["credential dumping", "lsass", "mimikatz", "sekurlsa"], "T1003", "OS Credential Dumping"),
    (["autorun registry key", "autorun folder"], "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
    (["office application"], "T1204.002", "User Execution: Malicious File"),
    (["mshta", "regsvr32", "rundll32"], "T1218", "System Binary Proxy Execution"),
    (["wscript", "cscript"], "T1059", "Command and Scripting Interpreter"),
    (["certutil", "bitsadmin"], "T1105", "Ingress Tool Transfer"),
    (["dos", "denial of service", "flood"], "T1498", "Network Denial of Service"),
    (["sql injection", "xss", "web attack", "path traversal", "directory traversal"], "T1190", "Exploit Public-Facing Application"),
    # Last on purpose: only labels alerts nothing above matched, so a brute
    # force that happens to come from a Tor exit node stays T1110.
    (["anonymizing network", "anonymizer", "tor exit"], "T1090", "Proxy"),
]

UNKNOWN_TECHNIQUE = ("T1000-UNK", "Unmapped / Needs Manual Triage")


def map_to_mitre(source: str, description: str):
    """
    Returns (technique_id, technique_name) best matching the alert text.
    Falls back to UNKNOWN_TECHNIQUE when nothing matches, so downstream
    code never has to special-case None.
    """
    text = f"{source or ''} {description or ''}".lower()

    for keywords, technique_id, technique_name in _RULES:
        if any(kw in text for kw in keywords):
            return technique_id, technique_name

    return UNKNOWN_TECHNIQUE


if __name__ == "__main__":
    samples = [
        ("Endpoint", "Ransomware encryption activity detected on WEB-SRV02, mass file rename observed"),
        ("Firewall", "Multiple failed login attempts detected for user jdoe followed by a successful login"),
        ("IDS", "Port scan detected from internal host DB-SRV01"),
        ("SIEM", "Informational: password changed successfully for user asmith"),
    ]
    for source, description in samples:
        tid, tname = map_to_mitre(source, description)
        print(f"{tid:12s} {tname:40s} <- {description}")
