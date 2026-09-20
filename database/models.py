from sqlalchemy import Column, Integer, String, DateTime
from database.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    status = Column(String, nullable=False, default="Open")
    ip = Column(String, nullable=True)
    hash = Column(String, nullable=True)
    timestamp = Column(DateTime, nullable=False)

    # Day 3 (Nanda) -- threat-intelligence enrichment
    ip_reputation = Column(String, nullable=True)      # "Clean" | "Suspicious" | "Malicious" | "Unknown"
    hash_reputation = Column(String, nullable=True)     # "Clean" | "Suspicious" | "Malicious" | "Unknown"
    threat_score = Column(Integer, nullable=True)       # 0-100, higher = worse
    mitre_technique = Column(String, nullable=True)     # e.g. "T1110 - Brute Force"

    # Day 3 (Nanda) -- automated response engine
    risk_score = Column(Integer, nullable=True)          # 0-100 composite score (60% severity / 40% threat_score)
    response_action = Column(String, nullable=True)       # playbook name, e.g. "Credential / Brute-Force Response"
    response_playbook = Column(String, nullable=True)     # JSON-encoded list of {"action": str, "auto": bool} steps
    response_status = Column(String, nullable=True)       # "auto_resolved" | "pending_approval" | "approved_and_executed" | "rejected"