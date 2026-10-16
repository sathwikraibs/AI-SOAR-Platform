import csv
import hashlib
import io
import json
import os
import platform
import re
import secrets
import subprocess
import sys
from datetime import datetime, timedelta

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from database.database import engine, Base, SessionLocal, migrate_schema
from database import models
from integration_health import record_failure, get_recent_failures

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
from threat_intel import check_hash_reputation, check_ip_reputation, enrich_alert  # noqa: E402
from geo_lookup import geolocate_ip  # noqa: E402
from response_engine import (  # noqa: E402
    approve_pending_steps,
    compute_risk_score,
    decide_response,
    execute_response,
    response_steps_json,
)
from playbooks import PLAYBOOKS  # noqa: E402

from .ssh_manager import run_diagnostics  # noqa: E402

Base.metadata.create_all(bind=engine)
migrate_schema()

app = FastAPI()

# The dashboard (frontend-dashboard/) runs on its own Vite dev server
# (http://localhost:5173 by default) and calls this API from the browser,
# which is a different origin than localhost:8000 -- without CORS enabled
# the browser blocks every request with a "No 'Access-Control-Allow-Origin'
# header" error before it even reaches these endpoints. This stays local-only
# (no cookies/auth on this API), so allowing any origin is fine here; the
# real security boundary is that this backend never listens on anything but
# localhost -- see target-app/app.py for the one piece that's actually public.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Optional Critical-alert notification
#
# If SOAR_SLACK_WEBHOOK_URL is set, every Critical-severity alert also gets
# posted to that Slack (or any Slack-compatible incoming-webhook) channel --
# useful for a demo where you want a phone/desktop notification to fire the
# instant something Critical is detected, instead of only seeing it in the
# dashboard. Entirely optional: with no webhook configured this is a no-op,
# and a failed webhook call never affects alert ingestion (best-effort,
# short timeout, errors are swallowed after a log line).
# ---------------------------------------------------------------------------

SLACK_WEBHOOK_URL = os.getenv("SOAR_SLACK_WEBHOOK_URL")
_NOTIFY_TIMEOUT = 4


def notify_if_critical(alert: "models.Alert") -> None:
    if not SLACK_WEBHOOK_URL or alert.severity != "Critical":
        return
    text = (
        f":rotating_light: *Critical alert #{alert.id}* (risk {alert.risk_score})\n"
        f"*Source:* {alert.source}  *IP:* {alert.ip or 'n/a'}\n"
        f"*MITRE:* {alert.mitre_technique or 'n/a'}\n"
        f"*Description:* {alert.description}\n"
        f"*Response:* {alert.response_action or 'n/a'} ({alert.response_status})"
    )
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=_NOTIFY_TIMEOUT)
    except requests.RequestException as exc:  # noqa: BLE001 - never let a notification failure break ingestion
        print(f"[backend] WARNING: Slack notification failed for alert {alert.id} ({exc})")
        record_failure("Slack Notifications", str(exc), context=f"Alert #{alert.id}")


def log_audit(db: Session, actor: str, action: str, target: str, source_ip: str | None = None, result: str = "Success") -> None:
    """
    Appends one row to audit_log. Called at every point in this file where
    something with real consequences actually happens (alert ingested,
    analyst approved/rejected a response) -- backs both GET /audit and
    Response Center's "recent actions" feed (same table, the dashboard
    just filters to approve/reject rows for that one). Best-effort: a
    logging failure should never break the request that triggered it.
    """
    try:
        db.add(models.AuditLog(
            timestamp=datetime.utcnow(),
            actor=actor,
            action=action,
            target=target,
            source_ip=source_ip,
            result=result,
        ))
        db.commit()
    except Exception as exc:  # noqa: BLE001
        print(f"[backend] WARNING: audit log write failed ({exc})")


def alert_to_dict(alert: "models.Alert") -> dict:
    """
    Converts an Alert ORM row into a plain dict for the API response.

    Newer FastAPI/Pydantic releases don't reliably serialize a raw
    SQLAlchemy model instance returned straight from a route (it can
    silently come back as `{}` instead of erroring, since jsonable_encoder
    falls back to a generic object path that doesn't know about SQLAlchemy's
    instrumented attributes) -- so every route that hands an Alert back to
    the client goes through this instead of `return alert` / `return
    db.query(...).all()` directly.
    """
    return {
        "id": alert.id,
        "source": alert.source,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "ip": alert.ip,
        "hash": alert.hash,
        "timestamp": alert.timestamp,
        "rule_key": alert.rule_key,
        "ip_reputation": alert.ip_reputation,
        "hash_reputation": alert.hash_reputation,
        "threat_score": alert.threat_score,
        "mitre_technique": alert.mitre_technique,
        "risk_score": alert.risk_score,
        "response_action": alert.response_action,
        "response_playbook": alert.response_playbook,
        "response_status": alert.response_status,
    }


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
    # Which detection-agent rule produced this (see rule_definitions in the
    # /detection-rules endpoint below). None for hand-submitted alerts.
    rule_key: str | None = None


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
    notify_if_critical(new_alert)
    log_audit(db, actor="system", action="Alert ingested", target=f"ALT-{new_alert.id}", source_ip=new_alert.ip)
    result = alert_to_dict(new_alert)
    db.close()
    return result


@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(models.Alert).all()
    db.close()
    return [alert_to_dict(a) for a in alerts]


# NOTE: registered here -- before /alerts/{alert_id} below -- on purpose.
# FastAPI/Starlette matches routes in declaration order, and
# /alerts/{alert_id} (with alert_id typed as int) matches any single path
# segment after /alerts/, including the literal "export.csv". With this
# route declared afterward instead, GET /alerts/export.csv was being
# swallowed by get_alert_detail("export.csv") and failing FastAPI's int
# validation (422) before ever reaching this function -- the Export CSV
# button was completely unreachable. Same class of bug as /reports/daily
# vs /reports/{filename} above; fixed the same way.
@app.get("/alerts/export.csv")
def export_alerts_csv():
    """
    Every alert as a CSV download -- for pulling the session's alerts into
    a spreadsheet (e.g. to attach alongside the project report) without
    having to script against GET /alerts yourself.
    """
    db = SessionLocal()
    alerts = db.query(models.Alert).order_by(models.Alert.id).all()
    db.close()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id", "timestamp", "source", "description", "severity", "ip", "hash",
            "ip_reputation", "hash_reputation", "threat_score", "mitre_technique",
            "risk_score", "response_action", "response_status",
        ]
    )
    for a in alerts:
        writer.writerow(
            [
                a.id, a.timestamp, a.source, a.description, a.severity, a.ip, a.hash,
                a.ip_reputation, a.hash_reputation, a.threat_score, a.mitre_technique,
                a.risk_score, a.response_action, a.response_status,
            ]
        )
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
    )


def _build_execution_log(alert: "models.Alert") -> list[dict]:
    """
    Turns the stored playbook (response_playbook: JSON list of
    {"action", "auto"}) plus the alert's current response_status into a
    per-step execution log -- e.g. for a dashboard detail view that wants
    to show *which* steps actually ran, not just the overall status.

    Every "auto" step already executed at ingestion time, regardless of
    response_status. "auto": False steps depend on what happened since:
      - response_status == "pending_approval" -> still pending
      - response_status == "approved_and_executed" -> executed (approved)
      - response_status == "rejected" -> rejected, never executed
      - response_status == "auto_resolved" -> there were no non-auto steps
        in this playbook to begin with
    """
    if not alert.response_playbook:
        return []
    steps = json.loads(alert.response_playbook)
    log = []
    for step in steps:
        if step["auto"]:
            step_status = "executed"
        elif alert.response_status == "approved_and_executed":
            step_status = "executed"
        elif alert.response_status == "rejected":
            step_status = "rejected"
        else:
            step_status = "pending"
        log.append({"action": step["action"], "auto": step["auto"], "status": step_status})
    return log


@app.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: int):
    """
    Full detail for one alert, including a per-step execution_log -- the
    "what did the response engine actually do" view that a plain GET
    /alerts row can't show (it only has response_action/response_status,
    a name and a summary string, not a step-by-step breakdown).
    """
    db = SessionLocal()
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    db.close()
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    return {
        "id": alert.id,
        "source": alert.source,
        "description": alert.description,
        "severity": alert.severity,
        "ip": alert.ip,
        "hash": alert.hash,
        "timestamp": alert.timestamp,
        "ip_reputation": alert.ip_reputation,
        "hash_reputation": alert.hash_reputation,
        "threat_score": alert.threat_score,
        "mitre_technique": alert.mitre_technique,
        "risk_score": alert.risk_score,
        "response_action": alert.response_action,
        "response_status": alert.response_status,
        "execution_log": _build_execution_log(alert),
    }


# Mirrors detection-agent/rules_target.py's own correlation window (same
# constant, kept in sync manually since the two are independent processes)
# -- an "incident" here is defined the same way the watcher already defines
# a multi-stage attack: several alerts from the same source IP close
# together in time.
INCIDENT_CORRELATION_WINDOW_SECONDS = 120


@app.get("/incidents")
def list_incidents():
    """
    Groups this session's alerts by source IP into "incidents" -- alerts
    from the same IP within INCIDENT_CORRELATION_WINDOW_SECONDS of each
    other are treated as one incident instead of N separate rows. This is
    the same idea detection-agent's SOAR-Correlation finding already acts
    on; this endpoint just exposes the grouping itself for a dashboard
    that wants to show "3 alerts, 1 incident" instead of a flat list.
    """
    db = SessionLocal()
    alerts = db.query(models.Alert).filter(models.Alert.ip.isnot(None)).order_by(models.Alert.timestamp).all()
    db.close()

    by_ip: dict[str, list] = {}
    for a in alerts:
        by_ip.setdefault(a.ip, []).append(a)

    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    incidents = []
    incident_id = 1
    for ip, ip_alerts in by_ip.items():
        window: list = []
        window_start = None
        for a in ip_alerts:
            if window_start is None or (a.timestamp - window_start) <= timedelta(seconds=INCIDENT_CORRELATION_WINDOW_SECONDS):
                window.append(a)
                if window_start is None:
                    window_start = a.timestamp
            else:
                incidents.append(_summarize_incident(incident_id, ip, window, severity_rank))
                incident_id += 1
                window = [a]
                window_start = a.timestamp
        if window:
            incidents.append(_summarize_incident(incident_id, ip, window, severity_rank))
            incident_id += 1

    incidents.sort(key=lambda inc: inc["last_seen"], reverse=True)
    return incidents


def _summarize_incident(incident_id: int, ip: str, alerts: list, severity_rank: dict) -> dict:
    max_severity = max((a.severity for a in alerts), key=lambda s: severity_rank.get(s, 0))
    techniques = sorted({a.mitre_technique for a in alerts if a.mitre_technique})
    return {
        "incident_id": incident_id,
        "ip": ip,
        "alert_count": len(alerts),
        "alert_ids": [a.id for a in alerts],
        "max_severity": max_severity,
        "mitre_techniques": techniques,
        "any_pending_approval": any(a.response_status == "pending_approval" for a in alerts),
        "first_seen": alerts[0].timestamp,
        "last_seen": alerts[-1].timestamp,
    }


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

    # Same DetachedInstanceError fix as the admin endpoints above -- capture
    # the response BEFORE log_audit()'s own db.commit() expires alert's
    # attributes out from under us.
    result = {"alert_id": alert_id, "status": alert.response_status, "executed_steps": approved_steps}

    log_audit(db, actor="analyst", action="Approved response", target=f"ALT-{alert_id}", source_ip=alert.ip)
    db.close()
    return result


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

    result = {"alert_id": alert_id, "status": alert.response_status}

    log_audit(db, actor="analyst", action="Rejected response", target=f"ALT-{alert_id}", source_ip=alert.ip, result="Dismissed")
    db.close()
    return result


# ---------------------------------------------------------------------------
# Autonomous incident reports (Sathwik's stage)
#
# report-generator/generate_report.py polls GET /alerts every ~20s and,
# whenever there are new alerts, writes a PDF summary into reports/ at the
# repo root. These two endpoints just list/serve those files -- they don't
# add any new alert or response logic, so nothing above this changes.
# ---------------------------------------------------------------------------

REPORTS_DIR = os.path.join(ROOT_DIR, "..", "reports")
DAILY_REPORTS_DIR = os.path.join(ROOT_DIR, "..", "reports", "daily")


@app.get("/reports")
def list_reports():
    """
    Lists auto-generated incident reports, newest first, for the dashboard's
    Reports tab. Each entry's download_url can be fetched directly.
    """
    if not os.path.isdir(REPORTS_DIR):
        return []
    files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")]
    files.sort(reverse=True)  # report_<timestamp>.pdf -> lexicographic sort == chronological
    return [
        {
            "filename": f,
            "generated_at": f.removeprefix("report_").removesuffix(".pdf"),
            "download_url": f"/reports/{f}",
        }
        for f in files
    ]


# NOTE: these two daily-report routes are registered *before*
# /reports/{filename} below on purpose. FastAPI/Starlette matches routes
# in the order they're declared, and /reports/{filename} matches any
# single path segment after /reports/ -- including the literal word
# "daily" -- so if it came first, GET /reports/daily would be swallowed
# by download_report("daily") instead of ever reaching list_daily_reports.
@app.get("/reports/daily")
def list_daily_reports():
    """
    Lists auto-generated 24-hour digest reports, newest first, for the
    dashboard's 24-Hour Report tab. These come from a separate process
    (report-generator/generate_daily_report.py), which writes ONE
    consolidated PDF covering the last 24 hours of alerts every 24 hours
    -- distinct from GET /reports' frequent per-cycle incremental reports.
    """
    if not os.path.isdir(DAILY_REPORTS_DIR):
        return []
    files = [f for f in os.listdir(DAILY_REPORTS_DIR) if f.endswith(".pdf")]
    files.sort(reverse=True)  # daily_report_<timestamp>.pdf -> lexicographic sort == chronological
    return [
        {
            "filename": f,
            "generated_at": f.removeprefix("daily_report_").removesuffix(".pdf"),
            "download_url": f"/reports/daily/{f}",
        }
        for f in files
    ]


@app.get("/reports/daily/{filename}")
def download_daily_report(filename: str, downloaded_by: str | None = None):
    """
    Downloads one 24-hour digest report PDF by filename, as returned by
    GET /reports/daily. downloaded_by is optional and comes from the
    dashboard's currently logged-in admin (see Admin Panel) so the audit
    log can attribute the download to a real person instead of a generic
    "analyst" -- there's no real auth here, so this is self-reported by the
    frontend, same honesty tradeoff as the rest of the Admin Panel.
    """
    if "/" in filename or ".." in filename or not filename.startswith("daily_report_") or not filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Invalid report filename")

    filepath = os.path.join(DAILY_REPORTS_DIR, filename)
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail=f"Report {filename} not found")

    db = SessionLocal()
    log_audit(db, actor=downloaded_by or "analyst", action="Report downloaded", target=filename)
    db.close()
    return FileResponse(filepath, media_type="application/pdf", filename=filename)


@app.get("/reports/{filename}")
def download_report(filename: str, downloaded_by: str | None = None):
    """Downloads one report PDF by filename, as returned by GET /reports. See download_daily_report() for downloaded_by."""
    if "/" in filename or ".." in filename or not filename.startswith("report_") or not filename.endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Invalid report filename")

    filepath = os.path.join(REPORTS_DIR, filename)
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail=f"Report {filename} not found")

    db = SessionLocal()
    log_audit(db, actor=downloaded_by or "analyst", action="Report downloaded", target=filename)
    db.close()
    return FileResponse(filepath, media_type="application/pdf", filename=filename)


# ---------------------------------------------------------------------------
# Threat intel lookup + geo map (dashboard's Investigations and Global
# Threat Map tabs -- previously frontend-only mock data with nothing real
# to call).
# ---------------------------------------------------------------------------

@app.get("/threat-intel/lookup")
def lookup_ioc(type: str, value: str):
    """
    On-demand IOC lookup for the Investigations tab's search box -- the
    same reputation checks enrich_alert() runs automatically on ingestion
    (AbuseIPDB for IPs, VirusTotal for hashes; heuristic fallback if no
    API key is configured), plus how many stored alerts already reference
    this IOC.

    `type` is "ip" or "hash". Anything else is a 400.
    """
    type = type.lower()
    if type not in ("ip", "hash"):
        raise HTTPException(status_code=400, detail="type must be 'ip' or 'hash'")

    db = SessionLocal()
    if type == "ip":
        reputation, score = check_ip_reputation(value)
        related = db.query(models.Alert).filter(models.Alert.ip == value).order_by(models.Alert.timestamp.desc()).all()
        geo = geolocate_ip(value)
    else:
        reputation, score = check_hash_reputation(value)
        related = db.query(models.Alert).filter(models.Alert.hash == value).order_by(models.Alert.timestamp.desc()).all()
        geo = None
    db.close()

    return {
        "type": type,
        "value": value,
        "reputation": reputation,
        "score": score,
        "country": geo["country"] if geo else None,
        "related_alert_count": len(related),
        "related_alert_ids": [a.id for a in related],
        "mitre_technique": related[0].mitre_technique if related else None,
    }


@app.get("/threat-intel/geo")
def geo_threat_data(hours: int | None = None):
    """
    Groups every stored alert with an IP by country for the Global Threat
    Map -- geolocates each unique IP (ip-api.com, cached; see geo_lookup.py)
    and rolls the results up per country: attack count, unique IP count,
    and the highest severity seen from that country. IPs that can't be
    geolocated (private/reserved, or the lookup failed/timed out) are
    grouped under "Internal Network" / "Unknown" with no coordinates, and
    the frontend can choose not to plot those.

    `hours`, when given, restricts this to alerts from the last N hours
    (backs the map's "Last 24 hours" / "Last 7 days" / "All time" filter --
    without it, every stored alert is included regardless of age).
    """
    db = SessionLocal()
    query = db.query(models.Alert).filter(models.Alert.ip.isnot(None))
    if hours is not None:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        query = query.filter(models.Alert.timestamp >= cutoff)
    alerts = query.all()
    db.close()

    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    by_country: dict[str, dict] = {}
    for a in alerts:
        geo = geolocate_ip(a.ip)
        country = geo["country"] if geo else "Unknown"
        bucket = by_country.setdefault(country, {
            "country": country,
            "lat": geo["lat"] if geo else None,
            "lon": geo["lon"] if geo else None,
            "attacks": 0,
            "ips": set(),
            "max_severity": "Low",
        })
        bucket["attacks"] += 1
        bucket["ips"].add(a.ip)
        if severity_rank.get(a.severity, 0) > severity_rank.get(bucket["max_severity"], 0):
            bucket["max_severity"] = a.severity

    result = [
        {
            "country": b["country"],
            "lat": b["lat"],
            "lon": b["lon"],
            "attacks": b["attacks"],
            "unique_ips": len(b["ips"]),
            "severity": b["max_severity"],
        }
        for b in by_country.values()
    ]
    result.sort(key=lambda r: r["attacks"], reverse=True)
    return result


# ---------------------------------------------------------------------------
# SSH diagnostics (dashboard's SSH / Sessions tab). See ssh_manager.py's
# module docstring for why this runs a fixed diagnostic command set
# instead of an arbitrary user-supplied command.
# ---------------------------------------------------------------------------

class SshConnectRequest(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str | None = None


@app.post("/ssh/connect")
def ssh_connect(req: SshConnectRequest):
    result = run_diagnostics(host=req.host, port=req.port, username=req.username, password=req.password)

    db = SessionLocal()
    session_row = models.SshSession(
        timestamp=datetime.utcnow(),
        host=req.host,
        port=req.port,
        username=req.username,
        success=result["connected"],
        output=result.get("output"),
        error=result.get("error"),
    )
    db.add(session_row)
    db.commit()
    log_audit(
        db,
        actor="analyst",
        action="SSH diagnostic connect" if result["connected"] else "SSH connect failed",
        target=f"{req.username}@{req.host}:{req.port}",
        source_ip=req.host,
        result="Success" if result["connected"] else "Failed",
    )
    db.close()

    if not result["connected"]:
        raise HTTPException(status_code=502, detail=result["error"])
    return result


@app.get("/ssh/sessions")
def list_ssh_sessions():
    """Real history of every /ssh/connect attempt, newest first -- backs the SSH / Sessions tab's session-log table."""
    db = SessionLocal()
    rows = db.query(models.SshSession).order_by(models.SshSession.timestamp.desc()).limit(100).all()
    db.close()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "host": r.host,
            "port": r.port,
            "username": r.username,
            "success": r.success,
            "output": r.output,
            "error": r.error,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Playbooks, IOC list, Assets, Audit log, Integration status.
#
# All five expose data that already genuinely exists elsewhere in the
# system (playbooks.py's real definitions, alerts already in the DB, the
# new audit_log table, actual env-var configuration) -- none of them
# invent numbers the way the dashboard's old mock data did.
# ---------------------------------------------------------------------------

@app.get("/playbooks")
def list_playbooks():
    """
    The real playbook catalog response_engine.py actually dispatches to
    (see response-engine/playbooks.py), plus how many times each has
    actually fired -- counted from alerts.response_action, which is set
    to the playbook's name at ingestion time.
    """
    db = SessionLocal()
    alerts = db.query(models.Alert).all()
    db.close()

    usage: dict[str, int] = {}
    for a in alerts:
        if a.response_action:
            usage[a.response_action] = usage.get(a.response_action, 0) + 1

    return [
        {
            "key": key,
            "name": playbook["name"],
            "steps": playbook["steps"],
            "times_triggered": usage.get(playbook["name"], 0),
        }
        for key, playbook in PLAYBOOKS.items()
    ]


@app.get("/threat-intel/iocs")
def list_iocs():
    """
    Every distinct IP/hash seen across stored alerts, with its
    already-computed reputation and how many alerts reference it -- the
    Threat Intelligence tab's table. There's no separate "IOC database";
    this is derived straight from the alerts table, which is also all the
    IOC history this system actually has.
    """
    db = SessionLocal()
    alerts = db.query(models.Alert).all()
    db.close()

    iocs: dict[tuple[str, str], dict] = {}
    for a in alerts:
        if a.ip:
            key = ("IP", a.ip)
            entry = iocs.setdefault(key, {"value": a.ip, "type": "IP", "reputation": a.ip_reputation or "Unknown", "count": 0})
            entry["count"] += 1
        if a.hash:
            key = ("Hash", a.hash)
            entry = iocs.setdefault(key, {"value": a.hash, "type": "Hash", "reputation": a.hash_reputation or "Unknown", "count": 0})
            entry["count"] += 1

    result = list(iocs.values())
    result.sort(key=lambda r: r["count"], reverse=True)
    return result


def _arp_lookup_mac(ip: str | None) -> str | None:
    """
    Best-effort MAC address lookup for a LAN IP, read straight from the
    backend host's own ARP table (`arp -a` on Windows, `arp -n` elsewhere).
    This only resolves if the backend and that IP have already exchanged
    packets on the same local network segment -- true for the "Add Asset"
    flow, since the browser submitting that form *is* the device being
    registered, so its ARP entry is fresh. Never raises: an unsupported
    platform, a missing `arp` binary, or an unresolved IP all just mean no
    MAC, the same "never break the caller" pattern as threat_intel.py and
    geo_lookup.py.
    """
    if not ip:
        return None
    try:
        if platform.system().lower().startswith("win"):
            output = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3).stdout
            match = re.search(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", output)
        else:
            output = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=3).stdout
            match = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", output)
        return match.group(0) if match else None
    except Exception as exc:  # noqa: BLE001 - ARP lookup failing should never break the "Add Asset" flow
        print(f"[assets] WARNING: ARP lookup failed for {ip} ({exc})")
        return None


@app.get("/assets/detect")
def detect_asset_network_info(request: Request):
    """
    Auto-detects the LAN IP and (best-effort) MAC address of whoever is
    filling out the "Add Asset" form on the dashboard -- called when that
    dialog opens so those two fields can be pre-filled instead of typed by
    hand. The IP is exactly what the network stack reports as the
    connecting peer (real, not guessed); the MAC comes from `_arp_lookup_mac`
    and can come back null if the backend and that device aren't on the
    same LAN segment.
    """
    client_ip = request.client.host if request.client else None
    return {"lan_ip": client_ip, "mac_address": _arp_lookup_mac(client_ip)}


class ManagedAssetCreate(BaseModel):
    employee_name: str
    hostname: str
    lan_ip: str
    mac_address: str | None = None
    ssh_enabled: bool = False
    department: str | None = None
    notes: str | None = None


@app.post("/assets")
def create_managed_asset(asset: ManagedAssetCreate):
    """
    Manually registers a real device/employee asset -- the actual LAN
    inventory record, ahead of the LAN-monitoring review milestone. This
    is distinct from GET /assets' other rows, which only exist because an
    alert happened to reference that Alert.source; a managed asset exists
    the moment it's registered, whether or not it's ever triggered an alert.
    """
    if not asset.employee_name.strip() or not asset.hostname.strip() or not asset.lan_ip.strip():
        raise HTTPException(status_code=422, detail="employee_name, hostname and lan_ip are required")
    db = SessionLocal()
    row = models.ManagedAsset(
        employee_name=asset.employee_name.strip(),
        hostname=asset.hostname.strip(),
        lan_ip=asset.lan_ip.strip(),
        mac_address=asset.mac_address,
        ssh_enabled=asset.ssh_enabled,
        department=asset.department,
        notes=asset.notes,
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    result = {"id": row.id, "hostname": row.hostname}

    log_audit(db, actor="analyst", action="Asset registered", target=row.hostname, source_ip=row.lan_ip)
    db.close()
    return result


@app.get("/assets")
def list_assets():
    """
    Two sources feed this list: alert-derived rows (there's no real
    asset-inventory system driving alert ingestion, so every distinct
    Alert.source is treated as an asset with real stats -- alert count,
    worst severity, highest risk score, last seen) and manually-registered
    ManagedAsset rows from the "Add Asset" form. A hostname present in
    both is merged into one row (owner/MAC layered onto the live alert
    stats); a manually-added device with no alerts yet still gets its own
    row rather than waiting for one.

    "status" is "Online"/"Offline" (alert within the last hour or not) for
    anything with alert history, or "Registered" for a managed asset with
    no alerts yet -- there's no liveness signal to fabricate one from.
    """
    db = SessionLocal()
    alerts = db.query(models.Alert).order_by(models.Alert.timestamp).all()
    managed = db.query(models.ManagedAsset).order_by(models.ManagedAsset.created_at).all()
    db.close()

    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    by_source: dict[str, dict] = {}
    for a in alerts:
        entry = by_source.setdefault(a.source, {
            "hostname": a.source,
            "ip": a.ip,
            "alert_count": 0,
            "active_incidents": 0,
            "max_severity": "Low",
            "max_risk_score": 0,
            "last_seen": a.timestamp,
            "owner": None,
            "mac": None,
            "managed": False,
        })
        entry["alert_count"] += 1
        entry["ip"] = a.ip or entry["ip"]
        entry["last_seen"] = a.timestamp
        if a.response_status == "pending_approval":
            entry["active_incidents"] += 1
        if severity_rank.get(a.severity, 0) > severity_rank.get(entry["max_severity"], 0):
            entry["max_severity"] = a.severity
        if (a.risk_score or 0) > entry["max_risk_score"]:
            entry["max_risk_score"] = a.risk_score or 0

    for m in managed:
        entry = by_source.setdefault(m.hostname, {
            "hostname": m.hostname,
            "ip": m.lan_ip,
            "alert_count": 0,
            "active_incidents": 0,
            "max_severity": None,
            "max_risk_score": 0,
            "last_seen": m.created_at,
            "owner": None,
            "mac": None,
            "managed": False,
        })
        entry["owner"] = m.employee_name
        entry["mac"] = m.mac_address
        entry["managed"] = True
        entry["ip"] = entry["ip"] or m.lan_ip

    now = datetime.utcnow()
    result = []
    for entry in by_source.values():
        if entry["alert_count"] > 0:
            status = "Online" if (now - entry["last_seen"]) <= timedelta(hours=1) else "Offline"
        else:
            status = "Registered"
        result.append({
            "hostname": entry["hostname"],
            "ip": entry["ip"],
            "mac_address": entry["mac"],
            "owner": entry["owner"],
            "type": "Managed" if entry["managed"] else "From Alerts",
            "status": status,
            "risk_score": entry["max_risk_score"],
            "active_incidents": entry["active_incidents"],
            "max_severity": entry["max_severity"],
            "alert_count": entry["alert_count"],
            "last_seen": entry["last_seen"],
        })
    result.sort(key=lambda r: r["last_seen"], reverse=True)
    return result


@app.get("/audit")
def list_audit_log():
    """
    Full audit trail: every alert ingestion and every analyst
    approve/reject decision (see log_audit()). Response Center's "recent
    actions" feed reads this same endpoint and just filters to the
    approve/reject rows client-side, rather than this backend maintaining
    two separate logs for what's really one event stream.
    """
    db = SessionLocal()
    rows = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(200).all()
    db.close()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp,
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "source_ip": r.source_ip,
            "result": r.result,
        }
        for r in rows
    ]


@app.get("/integrations/status")
def integrations_status():
    """
    Real health check of the external integrations this backend actually
    talks to -- "Connected" here means the API key/webhook is configured,
    not a live network probe (AbuseIPDB/VirusTotal calls are made
    per-lookup, not proactively pinged), which is still a genuine signal
    and not the dashboard's old always-"Connected" hardcoded list.

    Each entry also carries recent_failures: the last few times a real call
    to that integration actually broke (timeout, bad key, rate limit, ...),
    recorded by integration_health.record_failure() right where each
    integration is called (threat_intel.py, geo_lookup.py, this file's
    Slack notifier). "Connected" only says a key/webhook is configured --
    it says nothing about whether the last real call to it worked, which is
    exactly the gap recent_failures fills.
    """
    def _entry(name: str, connected: bool, detail: str, failure_key: str | None = None) -> dict:
        # failure_key lets the displayed name differ from the key
        # record_failure() was called with elsewhere (e.g. geo_lookup.py
        # logs under the short name "IP Geolocation", not this endpoint's
        # more descriptive display label) -- without this, get_recent_failures
        # would look up the wrong dict key and silently always return [],
        # even though failures were actually being recorded.
        return {
            "name": name,
            "connected": connected,
            "detail": detail,
            "recent_failures": get_recent_failures(failure_key or name, limit=5),
        }

    return [
        _entry("Backend API", True, "This API is obviously up if you're reading this response."),
        _entry("AbuseIPDB", bool(os.getenv("ABUSEIPDB_API_KEY")), "IP reputation lookups" if os.getenv("ABUSEIPDB_API_KEY") else "ABUSEIPDB_API_KEY not set -- falling back to heuristic scoring"),
        _entry("VirusTotal", bool(os.getenv("VIRUSTOTAL_API_KEY")), "File hash lookups" if os.getenv("VIRUSTOTAL_API_KEY") else "VIRUSTOTAL_API_KEY not set -- falling back to heuristic scoring"),
        # Keyless endpoint (see geo_lookup.py) -- there's no API key to be
        # "not configured", so this is always considered connected. Its
        # recent_failures is what actually shows whether ip-api.com itself
        # is reachable right now (rate-limited, down, etc).
        _entry("IP Geolocation (ip-api.com)", True, "Keyless geolocation for the Global Threat Map -- no API key needed.", failure_key="IP Geolocation"),
        _entry("Slack Notifications", bool(os.getenv("SOAR_SLACK_WEBHOOK_URL")), "Critical-alert notifications" if os.getenv("SOAR_SLACK_WEBHOOK_URL") else "SOAR_SLACK_WEBHOOK_URL not set"),
    ]


# ---------------------------------------------------------------------------
# Detection Rules (dashboard's Detection Rules tab).
#
# The rule keys below are the actual detection points in
# detection-agent/rules.py and detection-agent/rules_target.py (see those
# files' RULE_KEY constants) -- this is not a separate invented list, it's
# the real rule set the watcher runs, given names/descriptions an analyst
# can read.
#
# Enable/disable state lives in the detection_rule_state table (a rule
# with no row yet defaults to enabled). detection-agent is a fully
# separate process with no DB access, so it polls GET /detection-rules
# once per loop iteration and skips any rule_key that comes back disabled
# -- see detection-agent/rule_state.py.
# ---------------------------------------------------------------------------

RULE_DEFINITIONS = [
    {
        "key": "suspicious_process",
        "name": "Suspicious Process Spawn",
        "description": "Reverse shells, download-and-execute pipelines, and other LOLBin/post-exploitation command-line patterns on this machine.",
        "source": "Endpoint",
    },
    {
        "key": "linux_ssh_brute_force",
        "name": "OS-Level SSH Brute Force",
        "description": "Repeated failed SSH logins from the same IP within a short window, tailed from the system auth log.",
        "source": "Linux-Auth",
    },
    {
        "key": "malicious_ip_connection",
        "name": "Known-Malicious IP Connection",
        "description": "An outbound connection from this machine to an IP on the known-bad watchlist.",
        "source": "Network",
    },
    {
        "key": "login_brute_force",
        "name": "Target-App Login Brute Force",
        "description": "Repeated failed logins against the same account on the target web app.",
        "source": "Target-App",
    },
    {
        "key": "credential_stuffing",
        "name": "Credential Stuffing",
        "description": "Failed logins against 2+ different accounts from the same IP on the target app -- distinct from single-account brute force.",
        "source": "Target-App",
    },
    {
        "key": "path_traversal",
        "name": "Path Traversal Attempt",
        "description": "A request on the target app trying to read files outside the upload directory (e.g. ../../etc/passwd).",
        "source": "Target-App",
    },
    {
        "key": "suspicious_file_upload",
        "name": "Suspicious File Upload",
        "description": "A file with a suspicious extension uploaded to the target app; its hash is submitted for VirusTotal reputation via the normal alert pipeline.",
        "source": "Target-App",
    },
    {
        "key": "multi_stage_correlation",
        "name": "Multi-Stage Attack Correlation",
        "description": "The same source IP triggers 2+ distinct rules above within a short window -- escalated as a single higher-priority multi-stage attack.",
        "source": "SOAR-Correlation",
    },
]


@app.get("/detection-rules")
def list_detection_rules():
    db = SessionLocal()
    state_rows = {row.rule_key: row.enabled for row in db.query(models.DetectionRuleState).all()}
    counts: dict[str, int] = {}
    for (rule_key, count) in (
        db.query(models.Alert.rule_key, func.count(models.Alert.id))
        .group_by(models.Alert.rule_key)
        .all()
    ):
        if rule_key:
            counts[rule_key] = count
    db.close()

    return [
        {
            "key": rule["key"],
            "name": rule["name"],
            "description": rule["description"],
            "source": rule["source"],
            "enabled": state_rows.get(rule["key"], True),
            "times_triggered": counts.get(rule["key"], 0),
        }
        for rule in RULE_DEFINITIONS
    ]


@app.post("/detection-rules/{rule_key}/toggle")
def toggle_detection_rule(rule_key: str):
    if rule_key not in {rule["key"] for rule in RULE_DEFINITIONS}:
        raise HTTPException(status_code=404, detail=f"Unknown rule key '{rule_key}'")

    db = SessionLocal()
    row = db.query(models.DetectionRuleState).filter(models.DetectionRuleState.rule_key == rule_key).first()
    if row is None:
        # No row yet means it's been enabled (the default) -- toggling now disables it.
        row = models.DetectionRuleState(rule_key=rule_key, enabled=False)
        db.add(row)
    else:
        row.enabled = not row.enabled
    db.commit()
    db.refresh(row)
    log_audit(
        db,
        actor="analyst",
        action=f"{'Enabled' if row.enabled else 'Disabled'} detection rule",
        target=rule_key,
    )
    enabled = row.enabled
    db.close()
    return {"key": rule_key, "enabled": enabled}


# ---------------------------------------------------------------------------
# Admin Panel (dashboard's Admin Panel tab).
#
# This is an identity/attribution layer, not a real access-control system --
# nothing else in this backend checks who's logged in before doing
# anything (same as SSH's no-auth-in-front-of-it design; see
# ssh_manager.py's docstring). What it actually does:
#   - lets an analyst create or pick an admin identity, password-protected,
#     so actions can say who did them instead of just "analyst"
#   - timestamps every login/logout as an admin_sessions row AND an
#     audit_log entry (so it shows up in both the Admin Panel's own log
#     and the general Audit tab)
#   - records an auto-approve/manual policy per severity and per playbook
#     (ApprovalPolicy) -- NOTE: recorded only. POST /alerts does not read
#     this yet, so changing it here does not yet change what happens to a
#     real incoming alert. That's a deliberate, disclosed next step, not a
#     bug -- see the frontend Admin Panel tab's own note about this.
# ---------------------------------------------------------------------------

PASSWORD_HASH_ITERATIONS = 100_000


def _hash_password(password: str, salt: str) -> str:
    """
    Salted PBKDF2-HMAC-SHA256, stdlib only (no new dependency). Reasonable
    hygiene for what this is -- again, an identity/attribution layer, not a
    real access-control boundary (nothing enforces this login anywhere
    else in the backend).
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PASSWORD_HASH_ITERATIONS).hex()


class AdminCreateRequest(BaseModel):
    name: str
    company_id: str
    role: str | None = None
    password: str


class AdminLoginRequest(BaseModel):
    admin_id: int
    password: str


class AdminLogoutRequest(BaseModel):
    admin_id: int


class ApprovalPolicyUpdate(BaseModel):
    scope: str  # "severity" | "playbook"
    key: str
    mode: str  # "auto" | "manual"
    updated_by: str | None = None


def _admin_to_dict(admin: "models.AdminAccount", session_id: int | None = None) -> dict:
    return {
        "id": admin.id,
        "name": admin.name,
        "company_id": admin.company_id,
        "role": admin.role,
        "session_id": session_id,
    }


@app.post("/admin/create")
def create_admin(req: AdminCreateRequest):
    """
    Creates a new admin identity AND immediately logs them in (one
    admin_sessions row with login_at = now) -- "while clicking create
    admin the timestamp should be recorded" from the same action, not a
    separate step.
    """
    if not req.name.strip() or not req.company_id.strip() or not req.password:
        raise HTTPException(status_code=422, detail="name, company_id and password are required")

    db = SessionLocal()
    salt = secrets.token_hex(16)
    admin = models.AdminAccount(
        name=req.name.strip(),
        company_id=req.company_id.strip(),
        role=(req.role.strip() if req.role and req.role.strip() else None),
        password_hash=_hash_password(req.password, salt),
        password_salt=salt,
        created_at=datetime.utcnow(),
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    session = models.AdminSession(
        admin_id=admin.id, admin_name=admin.name, company_id=admin.company_id, role=admin.role,
        login_at=datetime.utcnow(),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # Build the response BEFORE log_audit()'s own db.commit() calls below --
    # SQLAlchemy expires every tracked object's attributes after each
    # commit by default, so reading admin.id/session.id after those commits
    # (and after db.close()) raises DetachedInstanceError. Capturing the
    # plain values now, while the session is still fresh, sidesteps that.
    result = _admin_to_dict(admin, session.id)

    log_audit(db, actor=admin.name, action="Admin created", target=admin.company_id)
    log_audit(db, actor=admin.name, action="Admin logged in", target=admin.company_id)
    db.close()
    return result


@app.get("/admin/list")
def list_admins():
    """Existing admin identities to pick from -- never returns password_hash/password_salt."""
    db = SessionLocal()
    admins = db.query(models.AdminAccount).order_by(models.AdminAccount.name).all()
    db.close()
    return [_admin_to_dict(a) for a in admins]


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    db = SessionLocal()
    admin = db.query(models.AdminAccount).filter(models.AdminAccount.id == req.admin_id).first()
    if admin is None:
        db.close()
        raise HTTPException(status_code=404, detail="Admin not found")

    if _hash_password(req.password, admin.password_salt) != admin.password_hash:
        log_audit(db, actor=admin.name, action="Admin login failed", target=admin.company_id, result="Failed")
        db.close()
        raise HTTPException(status_code=401, detail="Incorrect password")

    session = models.AdminSession(
        admin_id=admin.id, admin_name=admin.name, company_id=admin.company_id, role=admin.role,
        login_at=datetime.utcnow(),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # Same fix as create_admin() above: capture the response BEFORE
    # log_audit()'s db.commit() expires admin/session attributes.
    result = _admin_to_dict(admin, session.id)

    log_audit(db, actor=admin.name, action="Admin logged in", target=admin.company_id)
    db.close()
    return result


@app.post("/admin/logout")
def admin_logout(req: AdminLogoutRequest):
    db = SessionLocal()
    admin = db.query(models.AdminAccount).filter(models.AdminAccount.id == req.admin_id).first()
    open_session = (
        db.query(models.AdminSession)
        .filter(models.AdminSession.admin_id == req.admin_id, models.AdminSession.logout_at.is_(None))
        .order_by(models.AdminSession.login_at.desc())
        .first()
    )
    if open_session is not None:
        open_session.logout_at = datetime.utcnow()
        db.commit()
    if admin is not None:
        log_audit(db, actor=admin.name, action="Admin logged out", target=admin.company_id)
    db.close()
    return {"status": "ok"}


@app.get("/admin/sessions")
def list_admin_sessions():
    """Admin access log -- who logged in/out and when. Backs the Admin Panel's own log table."""
    db = SessionLocal()
    rows = db.query(models.AdminSession).order_by(models.AdminSession.login_at.desc()).limit(200).all()
    db.close()
    return [
        {
            "id": r.id,
            "admin_name": r.admin_name,
            "company_id": r.company_id,
            "role": r.role,
            "login_at": r.login_at,
            "logout_at": r.logout_at,
        }
        for r in rows
    ]


@app.get("/admin/approval-policy")
def get_approval_policy():
    """
    Current auto-approve/manual policy, by severity and by playbook.
    Playbook keys come straight from PLAYBOOKS (the real, live playbook
    set response_engine.py actually uses), not a separately hand-typed
    list that could drift out of sync with it. Anything with no saved
    row yet defaults to "manual" -- the same safe default the rest of the
    pipeline already uses (nothing auto-executes without an explicit
    override).
    """
    db = SessionLocal()
    rows = db.query(models.ApprovalPolicy).all()
    db.close()
    policy = {r.policy_key: r.mode for r in rows}
    return {
        "severity": {s: policy.get(f"severity:{s}", "manual") for s in ("Critical", "High", "Medium", "Low")},
        "playbook": {p: policy.get(f"playbook:{p}", "manual") for p in PLAYBOOKS.keys()},
    }


@app.post("/admin/approval-policy")
def set_approval_policy(req: ApprovalPolicyUpdate):
    if req.scope not in ("severity", "playbook"):
        raise HTTPException(status_code=422, detail="scope must be 'severity' or 'playbook'")
    if req.mode not in ("auto", "manual"):
        raise HTTPException(status_code=422, detail="mode must be 'auto' or 'manual'")
    if req.scope == "severity" and req.key not in ("Critical", "High", "Medium", "Low"):
        raise HTTPException(status_code=422, detail=f"Unknown severity '{req.key}'")
    if req.scope == "playbook" and req.key not in PLAYBOOKS:
        raise HTTPException(status_code=422, detail=f"Unknown playbook '{req.key}'")

    policy_key = f"{req.scope}:{req.key}"
    db = SessionLocal()
    row = db.query(models.ApprovalPolicy).filter(models.ApprovalPolicy.policy_key == policy_key).first()
    if row is None:
        row = models.ApprovalPolicy(policy_key=policy_key, mode=req.mode, updated_at=datetime.utcnow(), updated_by=req.updated_by)
        db.add(row)
    else:
        row.mode = req.mode
        row.updated_at = datetime.utcnow()
        row.updated_by = req.updated_by
    db.commit()
    log_audit(db, actor=req.updated_by or "analyst", action=f"Set {req.scope} approval policy", target=f"{req.key} -> {req.mode}")
    db.close()
    return {"policy_key": policy_key, "mode": req.mode}
