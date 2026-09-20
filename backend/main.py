import json
import os
import sys
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import engine, Base, SessionLocal, migrate_schema
from database import models

# ai-model/, threat-intelligence/ and response-engine/ all have hyphens in
# their names, so they can't be imported as normal dotted packages
# (`import ai-model.classifier` is a syntax error). Add each to sys.path
# instead and import the modules directly.
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
AI_MODEL_DIR = os.path.join(ROOT_DIR, "..", "ai-model")
THREAT_INTEL_DIR = os.path.join(ROOT_DIR, "..", "threat-intelligence")
RESPONSE_ENGINE_DIR = os.path.join(ROOT_DIR, "..", "response-engine")
for _dir in (AI_MODEL_DIR, THREAT_INTEL_DIR, RESPONSE_ENGINE_DIR):
    sys.path.append(os.path.abspath(_dir))

from classifier import predict_severity  # noqa: E402
from threat_intel import enrich_alert  # noqa: E402
from response_engine import (  # noqa: E402
    approve_pending_steps,
    compute_risk_score,
    decide_response,
    execute_response,
    response_steps_json,
)

Base.metadata.create_all(bind=engine)
migrate_schema()

app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class AlertCreate(BaseModel):
    source: str
    description: str
    # Severity is intentionally optional on the way in: this is a *raw*
    # alert straight from a log source, so the AI classifier is what
    # decides severity. Anything sent here is ignored -- see
    # documentation/api-contract.md for the Day 2 changelog note.
    severity: str | None = None
    status: str = "Open"
    ip: str | None = None
    hash: str | None = None
    timestamp: datetime


@app.get("/")
def root():
    return {"message": "AI-SOAR Platform API is running"}


@app.post("/alerts")
def create_alert(alert: AlertCreate):
    db = SessionLocal()
    alert_data = alert.dict()

    # AI Classifier -> Risk Priority step of the pipeline: score the raw
    # alert and store the AI-assigned severity, regardless of whatever
    # (if anything) was sent in the request.
    alert_data["severity"] = predict_severity(
        source=alert_data["source"],
        description=alert_data["description"],
        ip=alert_data.get("ip"),
        hash=alert_data.get("hash"),
        timestamp=alert_data.get("timestamp"),
    )

    # Threat Intelligence step: enrich with IP/hash reputation + MITRE
    # ATT&CK technique mapping.
    enrichment = enrich_alert(
        source=alert_data["source"],
        description=alert_data["description"],
        ip=alert_data.get("ip"),
        hash=alert_data.get("hash"),
    )
    alert_data["ip_reputation"] = enrichment["ip_reputation"]
    alert_data["hash_reputation"] = enrichment["hash_reputation"]
    alert_data["threat_score"] = enrichment["threat_score"]
    alert_data["mitre_technique"] = enrichment["mitre_technique"]

    # Composite risk score (0-100): blends the AI severity label with the
    # threat-intel score for finer-grained prioritization than the 4-bucket
    # severity alone -- see response_engine.compute_risk_score() docstring.
    alert_data["risk_score"] = compute_risk_score(alert_data["severity"], enrichment)

    # Automated Response step: pick a playbook and run only its low-risk
    # ("auto") steps now; destructive steps (isolate host, block IP, ...)
    # are held as "pending_approval" until an analyst calls
    # POST /alerts/{id}/approve -- see response-engine/playbooks.py.
    playbook_key, playbook = decide_response(alert_data["severity"], enrichment)
    response_status, executed_steps, pending_steps = execute_response(
        playbook_key, playbook, {"ip": alert_data.get("ip"), "hash": alert_data.get("hash")}
    )
    alert_data["response_action"] = playbook["name"]
    alert_data["response_playbook"] = response_steps_json(playbook)
    alert_data["response_status"] = response_status  # "auto_resolved" | "pending_approval"

    new_alert = models.Alert(**alert_data)
    db.add(new_alert)
    db.commit()
    db.refresh(new_alert)
    db.close()
    return new_alert


@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(models.Alert).all()
    db.close()
    return alerts


@app.post("/alerts/{alert_id}/approve")
def approve_alert_response(alert_id: int):
    """
    Human-in-the-loop step: a SOC analyst signs off on an alert's
    destructive response steps (isolate host, block IP, lock account, ...)
    that execute_response() held back at ingestion time. Runs (logs) those
    steps now and flips response_status to "approved_and_executed".

    404 if the alert doesn't exist; 409 if it has nothing pending (already
    resolved automatically, or already approved/rejected).
    """
    db = SessionLocal()
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        db.close()
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    if alert.response_status != "pending_approval":
        db.close()
        raise HTTPException(
            status_code=409,
            detail=f"Alert {alert_id} has no pending response to approve (status={alert.response_status})",
        )

    playbook = {"steps": json.loads(alert.response_playbook)}
    approved_steps = approve_pending_steps(playbook, {"ip": alert.ip, "hash": alert.hash})

    alert.response_status = "approved_and_executed"
    db.commit()
    db.refresh(alert)
    db.close()
    return {"alert_id": alert_id, "status": alert.response_status, "executed_steps": approved_steps}


@app.post("/alerts/{alert_id}/reject")
def reject_alert_response(alert_id: int):
    """
    Analyst dismisses the pending destructive steps (e.g. investigated and
    confirmed false positive) without running them.
    """
    db = SessionLocal()
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        db.close()
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    if alert.response_status != "pending_approval":
        db.close()
        raise HTTPException(
            status_code=409,
            detail=f"Alert {alert_id} has no pending response to reject (status={alert.response_status})",
        )

    alert.response_status = "rejected"
    db.commit()
    db.refresh(alert)
    db.close()
    return {"alert_id": alert_id, "status": alert.response_status}
