"""
Playbook definitions for the automated response engine.

Each playbook is a named, ordered list of response steps. These are
*simulated* actions (this is a student SOC-demo project, not something
wired to a real firewall/EDR) -- response_engine.py logs what *would* run
and returns the plan; nothing here actually touches a network device.

Each step is tagged "auto": True | False:
  - auto=True   steps are low-risk (logging, watchlisting, notifying) and
                execute immediately, no human needed.
  - auto=False  steps are destructive/business-impacting (isolating a host,
                blocking an IP, locking an account, killing a process) and
                are only *proposed* -- they sit in "pending_approval" until
                a SOC analyst approves them via POST /alerts/{id}/approve.

This mirrors how real SOAR platforms (Splunk SOAR, Palo Alto XSOAR, etc.)
are actually run in production: full auto-response sounds great until the
AI/threat-intel is wrong and auto-isolates a production server, so
high-blast-radius actions keep a human in the loop while cheap, reversible
ones run immediately. It also directly reduces analyst alert fatigue,
since only the actions that truly need a decision reach them.
"""

PLAYBOOKS = {
    "critical_malware": {
        "name": "Critical Malware / Ransomware Containment",
        "steps": [
            {"action": "Isolate affected host from the network", "auto": False},
            {"action": "Kill malicious process", "auto": False},
            {"action": "Quarantine associated file hash", "auto": False},
            {"action": "Block related IP(s) at the firewall", "auto": False},
            {"action": "Page on-call SOC analyst (P1)", "auto": True},
        ],
    },
    "credential_attack": {
        "name": "Credential / Brute-Force Response",
        "steps": [
            {"action": "Lock affected user account", "auto": False},
            {"action": "Block source IP at the firewall", "auto": False},
            {"action": "Force password reset on next login", "auto": False},
            {"action": "Notify SOC analyst", "auto": True},
        ],
    },
    "network_recon": {
        "name": "Reconnaissance / Scanning Response",
        "steps": [
            {"action": "Add source IP to watchlist", "auto": True},
            {"action": "Rate-limit traffic from source IP", "auto": True},
            {"action": "Log event for correlation", "auto": True},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration Containment",
        "steps": [
            {"action": "Isolate affected host from the network", "auto": False},
            {"action": "Block outbound traffic to destination IP", "auto": False},
            {"action": "Snapshot host for forensics", "auto": True},
            {"action": "Page on-call SOC analyst (P1)", "auto": True},
        ],
    },
    "web_attack_response": {
        "name": "Web Application Attack Response",
        "steps": [
            {"action": "Block source IP at the WAF/firewall", "auto": False},
            {"action": "Add source IP to watchlist", "auto": True},
            {"action": "Notify SOC analyst", "auto": True},
        ],
    },
    "anonymizer_block": {
        "name": "Anonymizer Network Block (VPN / Tor / Proxy)",
        "steps": [
            {"action": "Block source IP immediately -- matched anonymizer blocklist", "auto": True},
            {"action": "Add IP to the permanent deny list (identity-masking network)", "auto": True},
            {"action": "Notify SOC analyst", "auto": True},
        ],
    },
    "anonymizer_detected": {
        "name": "Anonymizer Network Detected (not blocked)",
        "steps": [
            {"action": "Log the VPN / Tor / proxy access with the exit-node location", "auto": True},
            {"action": "Notify SOC analyst", "auto": True},
            {"action": "Block source IP -- awaiting approval (automatic VPN/Tor blocking is switched off)", "auto": False},
        ],
    },
    "policy_violation": {
        "name": "Acceptable-Use Policy Violation",
        "steps": [
            {"action": "Log the activity against the acceptable-use policy", "auto": True},
            {"action": "Notify the employee's manager", "auto": True},
            {"action": "Send the employee a policy reminder -- awaiting approval", "auto": False},
            {"action": "Review the device's recent activity -- awaiting approval", "auto": False},
        ],
    },
    "endpoint_malicious_site": {
        "name": "Malicious Website Visited (endpoint)",
        "steps": [
            {"action": "Log the visit and notify SOC analyst", "auto": True},
            {"action": "Block the domain at DNS / web filter -- awaiting approval", "auto": False},
            {"action": "Isolate the device pending review -- awaiting approval", "auto": False},
            {"action": "Run a malware scan on the device -- awaiting approval", "auto": False},
        ],
    },
    "standard_triage": {
        "name": "Standard Analyst Triage",
        "steps": [
            {"action": "Log event for SOC review", "auto": True},
            {"action": "Add to daily triage queue", "auto": True},
        ],
    },
    "monitor_only": {
        "name": "Monitor Only",
        "steps": [
            {"action": "No automated action -- log for visibility", "auto": True},
        ],
    },
}
