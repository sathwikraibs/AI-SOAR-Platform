from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session
from database.database import engine, Base, SessionLocal
from database import models

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
    severity: str
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
    new_alert = models.Alert(**alert.dict())
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