from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.parser import parse_alert
from backend.normalizer import normalize_alert

from threat_intel.enricher import enrich_ip

from playbooks.engine import execute_playbook

from database.models import (
    create_alerts_table,
    create_incidents_table,
    create_incident_activity_table
)

from database.crud import (
    save_alert,
    create_incident,

    get_total_alerts,
    get_high_risk_alerts,
    get_critical_alerts,
    get_playbook_executions,
    get_open_incidents,
    get_blocked_ips,
    get_mttr,
    get_recent_alerts,

    get_all_incidents,
    get_incident_by_id,
    get_incident_summary,

    incident_exists,

    update_incident_status,
    assign_analyst,
    add_analyst_note,
    resolve_incident,

    delete_incident,

    log_incident_activity,
    get_incident_activity,
    get_alerts_by_severity,
    get_incidents_by_status_chart,
    get_daily_alerts,
    get_risk_distribution
)

app = FastAPI(
    title="SOAR Incident Containment Engine",
    version="1.0.0"
)

# ----------------------------------------
# Initialize Database
# ----------------------------------------

create_alerts_table()
create_incidents_table()
create_incident_activity_table()

# ----------------------------------------
# Static Files
# ----------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

from pydantic import BaseModel


from typing import Literal

class StatusUpdate(BaseModel):
    status: Literal[
        "NEW",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "CLOSED"
    ]

class AnalystAssignment(BaseModel):
    assigned_to: str


class AnalystNote(BaseModel):
    note: str


# ----------------------------------------
# Shared Alert Processing
# ----------------------------------------

def process_alert(alert: dict):

    # -----------------------------
    # Parse Alert
    # -----------------------------

    parsed = parse_alert(alert)

    # -----------------------------
    # Normalize Alert
    # -----------------------------

    normalized = normalize_alert(parsed)

    attacker_ip = normalized.get("attacker_ip")

    # -----------------------------
    # Threat Intelligence
    # -----------------------------

    if attacker_ip:

        enrichment = enrich_ip(
            ip_address=attacker_ip,
            alert_type=normalized["type"],
            severity=normalized["severity"]
        )

        if enrichment:
            normalized.update(enrichment)

    # -----------------------------
    # Risk Score
    # -----------------------------

    risk_score = normalized.get("risk_score", 0)

    normalized["risk_score"] = risk_score

    # -----------------------------
    # Risk Level
    # -----------------------------

    if "risk_level" not in normalized:

        if risk_score >= 90:
            normalized["risk_level"] = "CRITICAL"

        elif risk_score >= 70:
            normalized["risk_level"] = "HIGH"

        elif risk_score >= 40:
            normalized["risk_level"] = "MEDIUM"

        else:
            normalized["risk_level"] = "LOW"

    normalized["status"] = "NEW"

    # -----------------------------
    # Execute Playbook
    # -----------------------------

    if attacker_ip:

        playbook_result = execute_playbook({

            "ip": attacker_ip,

            "risk_score": normalized["risk_score"]

        })

        normalized["action_taken"] = playbook_result.get(
            "action",
            "Pending"
        )

    else:

        playbook_result = {

            "status": "skipped",

            "message": "No attacker IP found."

        }

        normalized["action_taken"] = "Pending"

    # ======================================================
    # Save Alert
    # ======================================================

    saved_alert_id = save_alert(normalized)

    # ======================================================
    # Automatically Create Incident
    # ======================================================

    incident = {

        "incident_id": f"INC-{saved_alert_id}",

        "alert_id": saved_alert_id,

        "title": f"{normalized['type']} Alert",

        "priority": (
            "P1"
            if normalized["risk_level"] == "CRITICAL"
            else "P2"
            if normalized["risk_level"] == "HIGH"
            else "P3"
            if normalized["risk_level"] == "MEDIUM"
            else "P4"
        ),

        "incident_status": "NEW",

        "assigned_to": "Unassigned",

        "analyst_notes": ""

    }

    create_incident(incident)
    log_incident_activity(
    incident["incident_id"],
    "CREATED",
    "Incident created automatically from alert.",
    "System"
)

    # ======================================================
    # Return
    # ======================================================

    return normalized, playbook_result
# ----------------------------------------
# Dashboard
# ----------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,

            # KPI Cards
            "total_alerts": get_total_alerts(),
            "high_risk": get_high_risk_alerts(),
            "critical_alerts": get_critical_alerts(),
            "playbooks": get_playbook_executions(),
            "incidents": get_open_incidents(),
            "blocked_ips": get_blocked_ips(),
            "mttr": get_mttr(),

            # Recent Alerts
            "recent_alerts": get_recent_alerts(),

            # Threat Intelligence Panel
            "top_ip": "N/A",
            "abuse_score": "--",
            "vt_score": "--",
            "country": "--",

            # Playbook Result
            "result": None,

    "severity_chart": get_alerts_by_severity(),
    "status_chart": get_incidents_by_status_chart(),
    "daily_chart": get_daily_alerts(),
    "risk_chart": get_risk_distribution()
    }
        )


@app.post("/", response_class=HTMLResponse)
async def execute_dashboard(

    request: Request,

    alert_id: str = Form(...),

    alert_type: str = Form(...),

    severity: str = Form(...),

    source_ip: str = Form(...),

    attacker_ip: str = Form(...)

):

    raw_alert = {

        "alert_id": alert_id,

        "alert_type": alert_type,

        "severity": severity,

        "source_ip": source_ip,

        "attacker_ip": attacker_ip

    }

    normalized, playbook_result = process_alert(raw_alert)

    return templates.TemplateResponse(

        request=request,

        name="dashboard.html",

        context={

            "request": request,

            # Dashboard KPIs

            "total_alerts": get_total_alerts(),

            "high_risk": get_high_risk_alerts(),

            "critical_alerts": get_critical_alerts(),

            "playbooks": get_playbook_executions(),

            "incidents": get_open_incidents(),

            "blocked_ips": get_blocked_ips(),

            "mttr": get_mttr(),

            # Recent Alerts

            "recent_alerts": get_recent_alerts(),

            # Threat Intelligence

            "top_ip": normalized.get("attacker_ip", "N/A"),

            "abuse_score": normalized.get("abuse_score", "--"),

            "vt_score": normalized.get("virustotal_score", "--"),

            "country": normalized.get("country", "--"),

            # Playbook Result

            "result": playbook_result,

            # Dashboard Analytics

            "severity_chart": get_alerts_by_severity(),

            "status_chart": get_incidents_by_status_chart(),

            "daily_chart": get_daily_alerts(),

            "risk_chart": get_risk_distribution()

        }

    )

# ----------------------------------------
# REST API
# ----------------------------------------

@app.post("/alerts")

def receive_alert(alert: dict):

    normalized, playbook_result = process_alert(alert)

    return {

        "message": "Alert processed successfully",

        "alert": normalized,

        "playbook": playbook_result,

    }
# ----------------------------------------
# INCIDENT DASHBOARD
# ----------------------------------------

@app.get("/incidents/dashboard", response_class=HTMLResponse)
async def incident_dashboard(request: Request):

    incidents = get_all_incidents()

    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "request": request,
            "incidents": incidents
        }
    )
# ----------------------------------------
# INCIDENT DETAILS PAGE
# ----------------------------------------

@app.get(
    "/incidents/dashboard/{incident_id}",
    response_class=HTMLResponse
)
async def incident_details_dashboard(
    request: Request,
    incident_id: str
):


    incident = get_incident_by_id(incident_id)
    activity = get_incident_activity(incident_id)

    if incident is None:

        return templates.TemplateResponse(
            request=request,
            name="incident_details.html",
            context={
                "request": request,
                "error": "Incident not found."
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="incident_details.html",
        context={
            "request": request,
            "incident": incident,
            "activity": activity

            
        }
    )

 # ----------------------------------------
# INCIDENT DETAILS ACTIONS (UI)
# ----------------------------------------
@app.post("/incidents/dashboard/{incident_id}/status")
async def update_incident_status_ui(
    incident_id: str,
    status: str = Form(...)
):
    update_incident_status(incident_id, status)

    log_incident_activity(
        incident_id,
        "STATUS",
        f"Status changed to {status}",
        "SOC Analyst"
    )

    if status.upper() == "RESOLVED":

        resolve_incident(incident_id)

        log_incident_activity(
            incident_id,
            "RESOLVED",
            "Incident resolved.",
            "SOC Analyst"
        )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303
    )


@app.post("/incidents/dashboard/{incident_id}/assign")
async def assign_incident_ui(
    incident_id: str,
    assigned_to: str = Form(...)
):
    assign_analyst(incident_id, assigned_to)

    log_incident_activity(
        incident_id,
        "ASSIGNED",
        f"Assigned to {assigned_to}",
        assigned_to
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303
    )


@app.post("/incidents/dashboard/{incident_id}/notes")
async def save_notes_ui(
    incident_id: str,
    note: str = Form(...)
):
    add_analyst_note(incident_id, note)

    log_incident_activity(
        incident_id,
        "NOTE",
        note,
        "SOC Analyst"
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303
    )

    

# ----------------------------------------
# INCIDENT MANAGEMENT REST API
# ----------------------------------------

@app.get("/incidents")
def list_incidents():

    return {
        "count": len(get_incident_summary()),
        "incidents": get_incident_summary()
    }


@app.get("/incidents/{incident_id}")
def incident_details(incident_id: str):

    if not incident_exists(incident_id):
        return {
            "error": "Incident not found."
        }

    return get_incident_by_id(incident_id)


@app.patch("/incidents/{incident_id}/status")
def change_status(
    incident_id: str,
    data: StatusUpdate
):

    if not incident_exists(incident_id):
        return {
            "error": "Incident not found."
        }

    update_incident_status(
        incident_id,
        data.status
    )

    if data.status.upper() == "RESOLVED":
        resolve_incident(incident_id)

    return {
        "message": "Incident status updated."
    }


@app.patch("/incidents/{incident_id}/assign")
def assign_incident(
    incident_id: str,
    data: AnalystAssignment
):

    if not incident_exists(incident_id):
        return {
            "error": "Incident not found."
        }

    assign_analyst(
        incident_id,
        data.assigned_to
    )

    return {
        "message": "Incident assigned successfully."
    }


@app.patch("/incidents/{incident_id}/notes")
def update_notes(
    incident_id: str,
    data: AnalystNote
):

    if not incident_exists(incident_id):
        return {
            "error": "Incident not found."
        }

    add_analyst_note(
        incident_id,
        data.note
    )

    return {
        "message": "Analyst note added."
    }


@app.delete("/incidents/{incident_id}")
def remove_incident(incident_id: str):

    if not incident_exists(incident_id):
        return {
            "error": "Incident not found."
        }

    delete_incident(incident_id)

    return {
        "message": "Incident deleted successfully."
    }
    
    

# ----------------------------------------
# Health Check
# ----------------------------------------

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "service": "SOAR Incident Containment Engine",

        "version": app.version

    }
