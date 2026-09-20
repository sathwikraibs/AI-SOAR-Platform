"""
Automated response engine.

This is the last stage of the pipeline:
  raw alert -> AI severity classifier -> threat-intel enrichment -> **response engine**

backend/main.py calls decide_response(severity, enrichment) with the AI's
severity and the threat-intel enrichment dict (see
threat-intelligence/threat_intel.py:enrich_alert) and gets back which
playbook fired, a composite risk score, and the plan split into steps that
already ran (auto) and steps waiting on analyst sign-off (pending_approval).
Nothing here is sent to a real firewall/EDR -- see playbooks.py for why.
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from playbooks import PLAYBOOKS  # noqa: E402

# MITRE technique IDs that should always be treated as high-urgency,
# regardless of what the AI classifier said, because the technique itself
# implies active compromise (defense-in-depth against a classifier miss).
_EXFIL_TECHNIQUES = {"T1041", "T1071", "T1071.004"}
_CREDENTIAL_TECHNIQUES = {"T1110", "T1078"}
_RECON_TECHNIQUES = {"T1595"}
_MALWARE_TECHNIQUES = {"T1486", "T1204"}

# Weight given to the AI classifier's severity label when computing the
# composite risk score below (0-100 scale, same as threat_score).
_SEVERITY_WEIGHT = {
    "Critical": 90,
    "High": 65,
    "Medium": 35,
    "Low": 10,
}
_SEVERITY_SHARE = 0.6  # vs. 0.4 for the threat-intel score -- see compute_risk_score()


def _technique_id(enrichment: dict) -> str:
    # enrichment["mitre_technique"] looks like "T1110 - Brute Force"
    return (enrichment.get("mitre_technique") or "").split(" - ")[0]


def compute_risk_score(severity: str, enrichment: dict) -> int:
    """
    Combines the AI's severity label with the threat-intel score into a
    single 0-100 risk score, instead of relying on the 4-bucket severity
    label alone for prioritization.

    Why: two "High" alerts are not equally urgent -- one against a clean,
    never-seen-before IP and one against an IP AbuseIPDB already has at
    95% confidence are very different risks. This is the same idea as
    Splunk's Risk-Based Alerting (RBA): a continuous score an analyst can
    sort/triage by, rather than a coarse label. Weighted 60% severity /
    40% threat-intel score, since the AI classifier sees the full alert
    text while threat-intel only sees the IP/hash.
    """
    severity_score = _SEVERITY_WEIGHT.get(severity, _SEVERITY_WEIGHT["Medium"])
    threat_score = enrichment.get("threat_score", 0)
    score = _SEVERITY_SHARE * severity_score + (1 - _SEVERITY_SHARE) * threat_score
    return max(0, min(100, round(score)))


def decide_response(severity: str, enrichment: dict):
    """
    Picks the playbook to run for this alert.

    Returns (playbook_key: str, playbook: dict) where playbook has
    "name" and "steps" (list of {"action": str, "auto": bool}, see
    playbooks.py).
    """
    technique_id = _technique_id(enrichment)
    hash_reputation = enrichment.get("hash_reputation", "Unknown")

    if severity == "Critical" or hash_reputation == "Malicious" or technique_id in _MALWARE_TECHNIQUES:
        playbook_key = "critical_malware"
    elif technique_id in _EXFIL_TECHNIQUES:
        playbook_key = "data_exfiltration"
    elif technique_id in _CREDENTIAL_TECHNIQUES:
        playbook_key = "credential_attack"
    elif technique_id in _RECON_TECHNIQUES:
        playbook_key = "network_recon"
    elif severity in ("High", "Medium"):
        playbook_key = "standard_triage"
    else:
        playbook_key = "monitor_only"

    return playbook_key, PLAYBOOKS[playbook_key]


def execute_response(playbook_key: str, playbook: dict, alert_context: dict | None = None):
    """
    "Executes" only the playbook's auto=True steps now (logs them -- no
    real containment action is taken, see module docstring). auto=False
    steps are NOT run here; they are left for approve_pending_steps() once
    an analyst signs off. Returns (status, executed_steps, pending_steps):
      status is "auto_resolved" if every step was auto (nothing pending),
      else "pending_approval".
    """
    context = alert_context or {}
    print(f"[response-engine] Playbook triggered: {playbook['name']} ({playbook_key})")

    executed_steps = []
    pending_steps = []
    for i, step in enumerate(playbook["steps"], start=1):
        if step["auto"]:
            print(f"[response-engine]   Step {i}: {step['action']} (auto, simulated)" + (f" -- context={context}" if context else ""))
            executed_steps.append(step["action"])
        else:
            print(f"[response-engine]   Step {i}: {step['action']} (HELD -- requires analyst approval)")
            pending_steps.append(step["action"])

    status = "pending_approval" if pending_steps else "auto_resolved"
    return status, executed_steps, pending_steps


def approve_pending_steps(playbook: dict, alert_context: dict | None = None):
    """
    Called from POST /alerts/{id}/approve once an analyst signs off: "runs"
    (logs) the playbook's auto=False steps that execute_response() held
    back. Returns the list of step names just executed.
    """
    context = alert_context or {}
    approved_steps = [step["action"] for step in playbook["steps"] if not step["auto"]]
    for i, action in enumerate(approved_steps, start=1):
        print(f"[response-engine]   Approved step {i}: {action} (simulated)" + (f" -- context={context}" if context else ""))
    return approved_steps


def response_steps_json(playbook: dict) -> str:
    """Serializes the full playbook (action + auto flag) for storage in a single DB column."""
    return json.dumps(playbook["steps"])


if __name__ == "__main__":
    # Quick manual smoke test: python3 response-engine/response_engine.py
    scenarios = [
        ("Critical", {"mitre_technique": "T1486 - Data Encrypted for Impact", "hash_reputation": "Malicious", "ip_reputation": "Malicious", "threat_score": 92}),
        ("High", {"mitre_technique": "T1110 - Brute Force", "hash_reputation": "Unknown", "ip_reputation": "Suspicious", "threat_score": 60}),
        ("Medium", {"mitre_technique": "T1595 - Active Scanning", "hash_reputation": "Unknown", "ip_reputation": "Clean", "threat_score": 20}),
        ("Low", {"mitre_technique": "T1000-UNK - Unmapped / Needs Manual Triage", "hash_reputation": "Unknown", "ip_reputation": "Unknown", "threat_score": 0}),
    ]
    for severity, enrichment in scenarios:
        key, playbook = decide_response(severity, enrichment)
        risk_score = compute_risk_score(severity, enrichment)
        status, executed, pending = execute_response(key, playbook, {"severity": severity})
        print(f">>> risk_score={risk_score} status={status} executed={executed} pending_approval={pending}")
        if pending:
            approved = approve_pending_steps(playbook, {"severity": severity})
            print(f">>> analyst approved -> executed: {approved}")
        print()
