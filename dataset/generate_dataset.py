"""
Synthetic alert dataset generator for the AI-SOAR severity classifier.

Why synthetic: the team has no real SIEM export to train on yet, so this
script builds a labeled dataset that mimics the alert shape defined in
documentation/api-contract.md (source, description, ip, hash, timestamp)
plus the ground-truth `severity` label the model is trained to predict.

Run:
    python3 dataset/generate_dataset.py

Output:
    dataset/alerts_dataset.csv
"""

import csv
import ipaddress
import os
import random
from datetime import datetime, timedelta

random.seed(42)

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerts_dataset.csv")

SOURCES = ["Windows", "Linux", "Firewall", "IDS", "SIEM", "Wazuh", "Sysmon", "Suricata", "Zeek", "Cloud", "Email", "Endpoint"]

HOSTS = ["WIN-DC01", "WEB-SRV02", "DB-SRV01", "HR-LAPTOP07", "FIN-WKSTN14", "MAIL-GW01", "VPN-GW01", "APP-SRV03"]
USERS = ["jdoe", "asmith", "svc_backup", "admin", "r.patel", "k.nguyen", "guest", "svc_sql"]

# Each template: (description format, requires_ip, requires_hash)
CRITICAL_TEMPLATES = [
    ("Ransomware encryption activity detected on host {host}, mass file rename observed", False, True),
    ("Data exfiltration detected: large outbound transfer from {host} to external IP {ip}", True, False),
    ("Privilege escalation to SYSTEM detected on {host} followed by lateral movement attempt", False, False),
    ("Malicious PowerShell Empire C2 beacon detected communicating with {ip}", True, False),
    ("Critical CVE exploitation attempt succeeded against {host}, remote code execution confirmed", False, False),
    ("Domain controller {host} compromised, Mimikatz credential dumping activity detected", False, True),
    ("Known ransomware hash {hash} executed on {host}", False, True),
]

HIGH_TEMPLATES = [
    ("Multiple failed login attempts detected for user {user} followed by a successful login", False, False),
    ("Suspicious outbound connection from {host} to known malicious IP {ip}", True, False),
    ("Malware signature {hash} detected by antivirus on {host}", False, True),
    ("Brute force attack detected against SSH service on {host} from {ip}", True, False),
    ("Unauthorized access attempt to sensitive file share on {host} by user {user}", False, False),
    ("Suspicious PowerShell script execution detected on {host}", False, False),
    ("Phishing email with malicious attachment hash {hash} delivered to {user}", False, True),
]

MEDIUM_TEMPLATES = [
    ("Port scan detected from internal host {host}", False, False),
    ("Unusual process spawned by Office application on {host}", False, False),
    ("Login for user {user} observed from a new geographic location", False, False),
    ("Outdated software vulnerability detected on {host}, no known active exploit", False, False),
    ("Suspicious email attachment quarantined for user {user}", False, False),
    ("Repeated DNS requests to newly registered domain from {host}", False, False),
    ("Firewall blocked unusual outbound traffic from {host} to {ip}", True, False),
]

LOW_TEMPLATES = [
    ("Informational: password changed successfully for user {user}", False, False),
    ("Scheduled antivirus scan completed on {host} with no threats found", False, False),
    ("New device registered on the corporate network from {ip}", True, False),
    ("Successful VPN login for user {user} from {ip}", True, False),
    ("System patch applied successfully on {host}", False, False),
    ("Routine configuration change applied on {host} by {user}", False, False),
    ("User {user} logged out after normal session on {host}", False, False),
]

SEVERITY_TEMPLATES = {
    "Critical": CRITICAL_TEMPLATES,
    "High": HIGH_TEMPLATES,
    "Medium": MEDIUM_TEMPLATES,
    "Low": LOW_TEMPLATES,
}

# Roughly realistic SOC volume: far more low/medium noise than true criticals.
SEVERITY_WEIGHTS = {"Low": 0.35, "Medium": 0.32, "High": 0.22, "Critical": 0.11}

START_TIME = datetime(2026, 1, 1)
END_TIME = datetime(2026, 9, 1)


def random_ip():
    return str(ipaddress.IPv4Address(random.randint(0x0A000001, 0xDF000000)))


def random_hash():
    return "".join(random.choice("0123456789abcdef") for _ in range(64))


def random_timestamp():
    delta = END_TIME - START_TIME
    seconds = random.randint(0, int(delta.total_seconds()))
    return (START_TIME + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S")


def build_row(true_severity):
    template, needs_ip, needs_hash = random.choice(SEVERITY_TEMPLATES[true_severity])
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    ip = random_ip() if (needs_ip or random.random() < 0.3) else None
    file_hash = random_hash() if (needs_hash or random.random() < 0.15) else None

    description = template.format(host=host, ip=ip or random_ip(), hash=(file_hash or random_hash())[:16], user=user)
    source = random.choice(SOURCES)

    # Label noise: ~6% of rows get bumped one level up or down to mimic
    # real-world ambiguity and keep the model from overfitting to keywords.
    label = true_severity
    if random.random() < 0.06:
        order = ["Low", "Medium", "High", "Critical"]
        idx = order.index(true_severity)
        shift = random.choice([-1, 1])
        idx = max(0, min(len(order) - 1, idx + shift))
        label = order[idx]

    return {
        "source": source,
        "description": description,
        "severity": label,
        "status": "Open",
        "ip": ip,
        "hash": file_hash,
        "timestamp": random_timestamp(),
    }


def generate(n_rows=4000):
    severities = list(SEVERITY_WEIGHTS.keys())
    weights = list(SEVERITY_WEIGHTS.values())
    rows = []
    for _ in range(n_rows):
        true_severity = random.choices(severities, weights=weights, k=1)[0]
        rows.append(build_row(true_severity))
    return rows


def main():
    rows = generate()
    fieldnames = ["source", "description", "severity", "status", "ip", "hash", "timestamp"]
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
