from fastapi import FastAPI, Request, Form
from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    StreamingResponse
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import csv
import io
import tempfile
import os

from backend.parser import parse_alert
from backend.normalizer import normalize_alert
from backend.auth import hash_password

from threat_intel.enricher import enrich_ip
from playbooks.engine import execute_playbook

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER

from database.models import (
    create_alerts_table,
    create_incidents_table,
    create_incident_activity_table,
    create_users_table
)

from database.crud import (
    save_alert,
    create_incident,

    create_user,
    user_exists,

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
    export_incidents,
    get_all_users,

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
    authenticate_user,
    get_risk_distribution
)
from starlette.middleware.sessions import SessionMiddleware
app = FastAPI(
    title="SOAR Incident Containment Engine",
    version="1.0.0"
)

app.add_middleware(
    SessionMiddleware,
    secret_key="soar-super-secret-key"
)




# ----------------------------------------
# Initialize Database
# ----------------------------------------

# ----------------------------------------
# Initialize Database
# ----------------------------------------

create_alerts_table()
create_incidents_table()
create_incident_activity_table()
create_users_table()

# ----------------------------------------
# Create Default Admin
# ----------------------------------------

if not user_exists("admin"):

    create_user({

        "username": "admin",

        "password_hash": hash_password("Admin@123"),

        "full_name": "System Administrator",

        "role": "ADMIN"

    })
# ----------------------------------------
# USER MANAGEMENT
# ----------------------------------------

@app.get("/admin/users", response_class=HTMLResponse)
async def user_management(request: Request):

    redirect = require_admin(request)

    if redirect:
        return redirect

    users = get_all_users()

    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "request": request,
            "users": users
        }
    )
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
# LOGIN PAGE
# ----------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "request": request,
            "error": None
        }
    )

# ----------------------------------------
# LOGOUT
# ----------------------------------------

@app.get("/logout")
async def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        url="/login",
        status_code=303
    )
# ----------------------------------------
# LOGIN
# ----------------------------------------

@app.post("/login")
async def login(

    request: Request,

    username: str = Form(...),

    password: str = Form(...)

):

    user = authenticate_user(
        username,
        password
    )

    if not user:

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "request": request,
                "error": "Invalid username or password."
            }
        )

    request.session["username"] = user["username"]
    request.session["role"] = user["role"]

    return RedirectResponse(
        url="/",
        status_code=303
    ) 







# ----------------------------------------
# Dashboard
# ----------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):

    redirect = require_login(request)

    if redirect:
        return redirect

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,

            "total_alerts": get_total_alerts(),
            "high_risk": get_high_risk_alerts(),
            "critical_alerts": get_critical_alerts(),
            "playbooks": get_playbook_executions(),
            "incidents": get_open_incidents(),
            "blocked_ips": get_blocked_ips(),
            "mttr": get_mttr(),

            "recent_alerts": get_recent_alerts(),

            "top_ip": "N/A",
            "abuse_score": "--",
            "vt_score": "--",
            "country": "--",

            "result": None,

            "severity_chart": get_alerts_by_severity(),
            "status_chart": get_incidents_by_status_chart(),
            "daily_chart": get_daily_alerts(),
            "risk_chart": get_risk_distribution()
        }
    )
# ----------------------------------------
# ADMIN CHECK
# ----------------------------------------

def require_admin(request: Request):

    redirect = require_login(request)

    if redirect:
        return redirect

    if request.session.get("role") != "ADMIN":

        return RedirectResponse(
            url="/",
            status_code=303
        )

    return None


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

    redirect = require_login(request)

    if redirect:
        return redirect

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
# AUTHENTICATION HELPER
# ----------------------------------------

def require_login(request: Request):

    if "username" not in request.session:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return None
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
def remove_incident(
    request: Request,
    incident_id: str
):

    redirect = require_admin(request)

    if redirect:
        return redirect

    if not incident_exists(incident_id):
        return {
            "error": "Incident not found."
        }

    delete_incident(incident_id)

    return {
        "message": "Incident deleted successfully."
    }
    
# ----------------------------------------
# EXPORT INCIDENTS (CSV)
# ----------------------------------------

@app.get("/incidents/export/csv")
def export_incidents_csv():

    incidents = export_incidents()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Incident ID",
        "Alert ID",
        "Title",
        "Priority",
        "Status",
        "Assigned To",
        "Created At"
    ])

    for incident in incidents:

        writer.writerow(incident)

    output.seek(0)

    return StreamingResponse(

        iter([output.getvalue()]),

        media_type="text/csv",

        headers={
            "Content-Disposition":
            "attachment; filename=incidents_report.csv"
        }

    )
    
@app.get("/incidents/export/pdf")
def export_incidents_pdf(request: Request):

    redirect = require_admin(request)

    if redirect:
        return redirect

    incidents = export_incidents()


    incidents = export_incidents()

    temp = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".pdf"
    )

    pdf = SimpleDocTemplate(temp.name)

    styles = getSampleStyleSheet()

    title_style = styles["Heading1"]
    title_style.alignment = TA_CENTER

    elements = []

    elements.append(
        Paragraph(
            "SOAR Incident Report",
            title_style
        )
    )

    elements.append(
        Paragraph("<br/><br/>", styles["Normal"])
    )

    data = [[
        "Incident ID",
        "Alert ID",
        "Priority",
        "Status",
        "Assigned",
        "Created"
    ]]

    for row in incidents:

        data.append([
            row[0],
            row[1],
            row[3],
            row[4],
            row[5],
            row[6]
        ])

    table = Table(data)

    table.setStyle(TableStyle([

        ("BACKGROUND", (0,0), (-1,0), colors.darkblue),

        ("TEXTCOLOR", (0,0), (-1,0), colors.white),

        ("GRID", (0,0), (-1,-1), 1, colors.black),

        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),

        ("ALIGN", (0,0), (-1,-1), "CENTER"),

        ("BOTTOMPADDING", (0,0), (-1,0), 10),

        ("BACKGROUND", (0,1), (-1,-1), colors.beige)

    ]))

    elements.append(table)

    pdf.build(elements)

    return StreamingResponse(

        open(temp.name, "rb"),

        media_type="application/pdf",

        headers={

            "Content-Disposition":
            "attachment; filename=incident_report.pdf"

        }

    )
    
    

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
