import os
import sys
from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database.database import engine, Base, SessionLocal
from database import models

# ai-model/ has a hyphen in its name, so it can't be imported as a normal
# dotted package (`import ai-model.classifier` is a syntax error). Add it to
# sys.path instead and import the module directly.
AI_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ai-model")
sys.path.append(os.path.abspath(AI_MODEL_DIR))
from classifier import predict_severity  # noqa: E402

Base.metadata.create_all(bind=engine)

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
