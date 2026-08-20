# ==========================================================
# SOAR INCIDENT CONTAINMENT ENGINE
# backend/main.py
# PART 1
# ==========================================================

from datetime import datetime
import csv
import io
import tempfile
import time

from fastapi import (
    FastAPI,
    Request,
    Form,
    HTTPException
)

from fastapi.responses import (
    HTMLResponse,
    RedirectResponse,
    StreamingResponse
)

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel
from typing import Literal, Optional

from starlette.middleware.sessions import SessionMiddleware


# ==========================================================
# PROJECT IMPORTS
# ==========================================================

from backend.parser import parse_alert
from backend.normalizer import normalize_alert
from backend.auth import hash_password

from threat_intel.enricher import enrich_ip
from playbooks.engine import execute_playbook


# ==========================================================
# REPORTING IMPORTS
# ==========================================================

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER


# ==========================================================
# DATABASE MODELS
# ==========================================================

from database.models import (
    create_alerts_table,
    create_incidents_table,
    create_incident_activity_table,
    create_users_table
)


# ==========================================================
# DATABASE CRUD
# ==========================================================

from database.crud import (
    save_alert,
    create_incident,

    create_user,
    user_exists,
    authenticate_user,

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
    get_risk_distribution
)


# ==========================================================
# FASTAPI APPLICATION
# ==========================================================

app = FastAPI(
    title="SOAR Incident Containment Engine",
    version="1.0.0"
)


# ==========================================================
# SESSION MIDDLEWARE
# ==========================================================

app.add_middleware(
    SessionMiddleware,
    secret_key="soar-super-secret-key"
)


# ==========================================================
# STATIC FILES
# ==========================================================

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# ==========================================================
# TEMPLATES
# ==========================================================

templates = Jinja2Templates(
    directory="templates"
)


# ==========================================================
# DATABASE INITIALIZATION
# ==========================================================

create_alerts_table()
create_incidents_table()
create_incident_activity_table()
create_users_table()


# ==========================================================
# DEFAULT ADMIN ACCOUNT
# ==========================================================

if not user_exists("admin"):

    create_user({
        "username": "admin",
        "password_hash": hash_password("Admin@123"),
        "full_name": "System Administrator",
        "role": "ADMIN"
    })


# ==========================================================
# REQUEST MODELS
# ==========================================================

class AlertRequest(BaseModel):

    alert_id: str
    alert_type: str
    severity: str

    source_ip: Optional[str] = None
    attacker_ip: Optional[str] = None

    description: Optional[str] = None
    timestamp: Optional[str] = None


class WazuhAlertRequest(BaseModel):

    timestamp: Optional[str] = None

    rule: dict = {}
    agent: dict = {}
    data: dict = {}

    full_log: Optional[str] = None


class IncidentStatusRequest(BaseModel):

    status: str


class AssignRequest(BaseModel):

    assigned_to: str


class NotesRequest(BaseModel):

    notes: str


# ==========================================================
# AUTHENTICATION HELPERS
# ==========================================================

def require_login(request: Request):

    username = request.session.get("username")

    if not username:

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return None


def require_admin(request: Request):

    redirect = require_login(request)

    if redirect:
        return redirect

    role = request.session.get("role")

    if role != "ADMIN":

        raise HTTPException(
            status_code=403,
            detail="Administrator access required"
        )

    return None


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def get_risk_level(risk_score: int):

    if risk_score >= 90:
        return "CRITICAL"

    elif risk_score >= 70:
        return "HIGH"

    elif risk_score >= 40:
        return "MEDIUM"

    return "LOW"


def get_incident_priority(risk_level: str):

    priority_map = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
        "SAFE": "P4"
    }

    return priority_map.get(
        str(risk_level).upper(),
        "P4"
    )


def make_json_safe(data):

    """
    Convert SQLite rows or other non-JSON
    serializable objects into normal dictionaries.
    """

    if data is None:
        return []

    safe_data = []

    for item in data:

        if isinstance(item, dict):

            safe_data.append(item)

        else:

            try:
                safe_data.append(dict(item))

            except Exception:
                safe_data.append(item)

    return safe_data


# ==========================================================
# SHARED ALERT PROCESSING PIPELINE
# ==========================================================

def process_alert(alert: dict):

    """
    Main SOAR processing pipeline.

    Alert
        ↓
    Parser
        ↓
    Normalizer
        ↓
    Threat Intelligence
        ↓
    Risk Score
        ↓
    Playbook
        ↓
    Alert Storage
        ↓
    Incident Creation
    """

    # ------------------------------------------------------
    # PARSE ALERT
    # ------------------------------------------------------

    parsed = parse_alert(alert)

    if not parsed:
        raise ValueError(
            "Unable to parse alert"
        )


    # ------------------------------------------------------
    # NORMALIZE ALERT
    # ------------------------------------------------------

    normalized = normalize_alert(parsed)

    if not normalized:
        raise ValueError(
            "Unable to normalize alert"
        )


    # ------------------------------------------------------
    # VALIDATE REQUIRED FIELDS
    # ------------------------------------------------------

    alert_id = normalized.get("id")

    if not alert_id:

        raise ValueError(
            "Alert ID is required"
        )


    alert_type = normalized.get(
        "type",
        "Unknown Alert"
    )

    severity = str(
        normalized.get(
            "severity",
            "LOW"
        )
    ).upper()

    source_ip = normalized.get(
        "source_ip"
    )

    attacker_ip = normalized.get(
        "attacker_ip"
    )


    # ------------------------------------------------------
    # THREAT INTELLIGENCE
    # ------------------------------------------------------

    enrichment_result = {}

    if attacker_ip:

        try:

            enrichment_result = enrich_ip(
                attacker_ip,
                alert_type,
                severity
            )

            if enrichment_result is None:
                enrichment_result = {}

        except Exception as error:

            print(
                f"Threat intelligence error: "
                f"{error}"
            )

            enrichment_result = {}

    else:

        print(
            "No attacker IP available. "
            "Skipping threat intelligence enrichment."
        )


    # ------------------------------------------------------
    # MERGE ENRICHMENT DATA
    # ------------------------------------------------------

    if isinstance(
        enrichment_result,
        dict
    ):

        normalized.update(
            enrichment_result
        )


    # ------------------------------------------------------
    # RISK SCORE
    # ------------------------------------------------------

    risk_score = normalized.get(
        "risk_score",
        0
    )

    try:

        risk_score = int(
            float(risk_score)
        )

    except (
        ValueError,
        TypeError
    ):

        risk_score = 0


    risk_score = max(
        0,
        min(
            risk_score,
            100
        )
    )


    normalized["risk_score"] = risk_score


    risk_level = normalized.get(
        "risk_level"
    )

    if not risk_level:

        risk_level = get_risk_level(
            risk_score
        )

    normalized["risk_level"] = str(
        risk_level
    ).upper()


    # ------------------------------------------------------
    # PLAYBOOK EXECUTION
    # ------------------------------------------------------

    try:

        playbook_result = execute_playbook(
            attacker_ip,
            risk_score
        )

    except Exception as error:

        print(
            f"Playbook execution error: "
            f"{error}"
        )

        playbook_result = {
            "status": "FAILED",
            "action": "No action executed",
            "error": str(error)
        }


    # ------------------------------------------------------
    # DETERMINE ACTION
    # ------------------------------------------------------

    if isinstance(
        playbook_result,
        dict
    ):

        action_taken = (
            playbook_result.get("action")
            or playbook_result.get("playbook")
            or playbook_result.get("message")
            or "Processed"
        )

    else:

        action_taken = str(
            playbook_result
        )


    normalized["action_taken"] = (
        action_taken
    )

    normalized["status"] = (
        normalized.get("status")
        or "NEW"
    )


    # ------------------------------------------------------
    # SAVE ALERT
    # ------------------------------------------------------

    try:

        save_alert(
            normalized
        )

        alert_saved = True

    except Exception as error:

        error_message = str(error)

        if (
            "UNIQUE constraint failed"
            in error_message
        ):

            print(
                f"Alert {alert_id} already exists."
            )

            alert_saved = False

        else:

            raise


    # ------------------------------------------------------
    # CREATE INCIDENT
    # ------------------------------------------------------

    incident_id = (
        f"INC-{alert_id}"
    )

    incident_created = False

    try:

        if not incident_exists(
            incident_id
        ):

            incident_data = {

                "incident_id":
                    incident_id,

                "alert_id":
                    alert_id,

                "title":
                    f"{alert_type} - {alert_id}",

                "priority":
                    get_incident_priority(
                        normalized[
                            "risk_level"
                        ]
                    ),

                "incident_status":
                    "NEW",

                "assigned_to":
                    "Unassigned",

                "analyst_notes":
                    None
            }

            create_incident(
                incident_data
            )

            incident_created = True


            # ----------------------------------------------
            # INCIDENT ACTIVITY
            # ----------------------------------------------

            log_incident_activity(
                incident_id,
                "INCIDENT_CREATED",
                "Incident automatically created "
                "by SOAR processing pipeline"
            )

            log_incident_activity(
                incident_id,
                "ALERT_PROCESSED",
                f"Alert {alert_id} processed "
                f"with risk score {risk_score}"
            )

            log_incident_activity(
                incident_id,
                "PLAYBOOK_EXECUTED",
                f"Automated response executed: "
                f"{action_taken}"
            )

        else:

            print(
                f"Incident {incident_id} "
                f"already exists."
            )

    except Exception as error:

        print(
            f"Incident creation error: "
            f"{error}"
        )


    # ------------------------------------------------------
    # FINAL RESPONSE
    # ------------------------------------------------------

    return {

        "message":
            "Alert processed successfully",

        "alert":
            normalized,

        "playbook":
            playbook_result,

        "incident": {
            "incident_id":
                incident_id,

            "created":
                incident_created
        },

        "alert_saved":
            alert_saved
    }


# ==========================================================
# HOME DASHBOARD
# ==========================================================

@app.get(
    "/",
    response_class=HTMLResponse
)

async def dashboard(
    request: Request
):

    redirect = require_login(
        request
    )

    if redirect:
        return redirect


    total_alerts = get_total_alerts()
    high_risk = get_high_risk_alerts()
    critical_alerts = get_critical_alerts()
    playbooks = get_playbook_executions()
    incidents = get_open_incidents()
    blocked_ips = get_blocked_ips()
    mttr = get_mttr()

    recent_alerts = get_recent_alerts()

    severity_data = make_json_safe(
        get_alerts_by_severity()
    )

    incident_status_data = make_json_safe(
        get_incidents_by_status_chart()
    )

    daily_alerts = make_json_safe(
        get_daily_alerts()
    )

    risk_distribution = make_json_safe(
        get_risk_distribution()
    )


    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={

            "total_alerts":
                total_alerts,

            "high_risk":
                high_risk,

            "critical_alerts":
                critical_alerts,

            "playbooks":
                playbooks,

            "incidents":
                incidents,

            "blocked_ips":
                blocked_ips,

            "mttr":
                mttr,

            "recent_alerts":
                recent_alerts,

            # Chart aliases
            "severity_chart":
                severity_data,

            "status_chart":
                incident_status_data,

            "daily_chart":
                daily_alerts,

            "risk_chart":
                risk_distribution,

            # Alternative variable names
            "severity_data":
                severity_data,

            "incident_status_data":
                incident_status_data,

            "daily_alerts":
                daily_alerts,

            "risk_distribution":
                risk_distribution
        }
    )


# ==========================================================
# DASHBOARD ALERT SUBMISSION
# ==========================================================

@app.post(
    "/",
    response_class=HTMLResponse
)

async def execute_dashboard(

    request: Request,

    alert_id: str = Form(...),
    alert_type: str = Form(...),
    severity: str = Form(...),

    source_ip: str = Form(...),

    attacker_ip: str = Form(...)
):

    redirect = require_login(
        request
    )

    if redirect:
        return redirect


    raw_alert = {

        "alert_id":
            alert_id,

        "alert_type":
            alert_type,

        "severity":
            severity,

        "source_ip":
            source_ip,

        "attacker_ip":
            attacker_ip
    }


    try:

        process_alert(
            raw_alert
        )

    except Exception as error:

        print(
            f"Dashboard alert error: "
            f"{error}"
        )


    # Redirect instead of rendering the
    # dashboard with potentially stale data

    return RedirectResponse(
        url="/",
        status_code=303
    )


# ==========================================================
# ALERT INGESTION API
# ==========================================================

@app.post(
    "/alerts"
)

async def receive_alert(
    alert: AlertRequest
):

    try:

        result = process_alert(
            alert.model_dump()
        )

        return result


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


    except Exception as error:

        print(
            f"Alert processing error: "
            f"{error}"
        )

        raise HTTPException(
            status_code=500,
            detail="SOAR alert processing failed"
        )


# ==========================================================
# END OF PART 1
# PART 2 CONTINUES DIRECTLY BELOW
# ==========================================================
# ==========================================================
# WAZUH WEBHOOK
# ==========================================================

@app.post("/wazuh/webhook")
async def wazuh_webhook(alert: WazuhAlertRequest):

    wazuh_data = alert.model_dump()

    rule = wazuh_data.get("rule", {})
    agent = wazuh_data.get("agent", {})
    data = wazuh_data.get("data", {})

    rule_level = rule.get("level", 0)

    # ------------------------------------------------------
    # MAP WAZUH LEVEL TO SOAR SEVERITY
    # ------------------------------------------------------

    try:
        rule_level = int(rule_level)
    except (ValueError, TypeError):
        rule_level = 0

    if rule_level >= 12:
        severity = "CRITICAL"
    elif rule_level >= 8:
        severity = "HIGH"
    elif rule_level >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # ------------------------------------------------------
    # CREATE SOAR ALERT
    # ------------------------------------------------------

    timestamp = wazuh_data.get("timestamp")

    if not timestamp:
        timestamp = datetime.now().isoformat()

    alert_id = (
        f"WAZUH-"
        f"{rule.get('id', 'UNKNOWN')}-"
        f"{int(time.time() * 1000)}"
    )

    soar_alert = {
        "alert_id": alert_id,
        "alert_type": rule.get(
            "description",
            "Wazuh Security Alert"
        ),
        "severity": severity,
        "source_ip": agent.get("ip"),
        "attacker_ip": (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("source_ip")
        ),
        "description": wazuh_data.get("full_log"),
        "timestamp": timestamp
    }

    try:

        result = process_alert(
            soar_alert
        )

        return {
            "message": "Wazuh alert received and processed",
            "wazuh_alert": wazuh_data,
            "soar_result": result
        }

    except Exception as error:

        print(
            f"Wazuh processing error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to process Wazuh alert"
        )


# ==========================================================
# INCIDENT LIST
# ==========================================================

@app.get(
    "/incidents",
    response_class=HTMLResponse
)
async def incidents_page(request: Request):

    redirect = require_login(request)

    if redirect:
        return redirect

    incidents = get_all_incidents()

    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "incidents": incidents
        }
    )


# ==========================================================
# INCIDENT API DETAILS
# ==========================================================

@app.get("/incidents/{incident_id}")
async def incident_details(
    incident_id: str,
    request: Request
):

    redirect = require_login(request)

    if redirect:
        return redirect

    incident = get_incident_by_id(
        incident_id
    )

    if not incident:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return dict(incident)


# ==========================================================
# INCIDENT DASHBOARD / INVESTIGATION PAGE
# ==========================================================

@app.get(
    "/incidents/dashboard/{incident_id}",
    response_class=HTMLResponse
)
async def incident_dashboard(
    incident_id: str,
    request: Request
):

    redirect = require_login(request)

    if redirect:
        return redirect

    incident = get_incident_by_id(
        incident_id
    )

    if not incident:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    activity = get_incident_activity(
        incident_id
    )

    return templates.TemplateResponse(
        request=request,
        name="incident_dashboard.html",
        context={
            "incident": incident,
            "activity": activity
        }
    )


# ==========================================================
# INCIDENT DASHBOARD REDIRECT / SUMMARY
# ==========================================================

@app.get(
    "/incidents/dashboard",
    response_class=HTMLResponse
)
async def incidents_dashboard(
    request: Request
):

    redirect = require_login(request)

    if redirect:
        return redirect

    incidents = get_all_incidents()

    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "incidents": incidents
        }
    )


# ==========================================================
# UPDATE INCIDENT STATUS
# ==========================================================

@app.post(
    "/incidents/dashboard/{incident_id}/status"
)
async def dashboard_update_status(

    incident_id: str,
    request: Request,
    status: str = Form(...)
):

    redirect = require_login(request)

    if redirect:
        return redirect

    update_incident_status(
        incident_id,
        status
    )

    log_incident_activity(
        incident_id,
        "STATUS_UPDATED",
        f"Incident status changed to {status}",
        request.session.get(
            "username",
            "Analyst"
        )
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303
    )


@app.patch(
    "/incidents/{incident_id}/status"
)
async def api_update_status(

    incident_id: str,
    data: IncidentStatusRequest,
    request: Request
):

    redirect = require_login(request)

    if redirect:
        return redirect

    update_incident_status(
        incident_id,
        data.status
    )

    log_incident_activity(
        incident_id,
        "STATUS_UPDATED",
        f"Incident status changed to {data.status}",
        request.session.get(
            "username",
            "Analyst"
        )
    )

    return {
        "message": "Incident status updated",
        "incident_id": incident_id,
        "status": data.status
    }


# ==========================================================
# ASSIGN ANALYST
# ==========================================================

@app.post(
    "/incidents/dashboard/{incident_id}/assign"
)
async def dashboard_assign_analyst(

    incident_id: str,
    request: Request,
    assigned_to: str = Form(...)
):

    redirect = require_login(request)

    if redirect:
        return redirect

    assign_analyst(
        incident_id,
        assigned_to
    )

    log_incident_activity(
        incident_id,
        "ANALYST_ASSIGNED",
        f"Incident assigned to {assigned_to}",
        request.session.get(
            "username",
            "System"
        )
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303
    )


@app.patch(
    "/incidents/{incident_id}/assign"
)
async def api_assign_analyst(

    incident_id: str,
    data: AssignRequest,
    request: Request
):

    redirect = require_login(request)

    if redirect:
        return redirect

    assign_analyst(
        incident_id,
        data.assigned_to
    )

    log_incident_activity(
        incident_id,
        "ANALYST_ASSIGNED",
        f"Incident assigned to {data.assigned_to}",
        request.session.get(
            "username",
            "System"
        )
    )

    return {
        "message": "Analyst assigned",
        "incident_id": incident_id,
        "assigned_to": data.assigned_to
    }


# ==========================================================
# ADD ANALYST NOTES
# ==========================================================

@app.post(
    "/incidents/dashboard/{incident_id}/notes"
)
async def dashboard_add_notes(

    incident_id: str,
    request: Request,
    notes: str = Form(...)
):

    redirect = require_login(request)

    if redirect:
        return redirect

    add_analyst_note(
        incident_id,
        notes
    )

    log_incident_activity(
        incident_id,
        "NOTE_ADDED",
        "Analyst added an investigation note",
        request.session.get(
            "username",
            "Analyst"
        )
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303
    )


@app.patch(
    "/incidents/{incident_id}/notes"
)
async def api_add_notes(

    incident_id: str,
    data: NotesRequest,
    request: Request
):

    redirect = require_login(request)

    if redirect:
        return redirect

    add_analyst_note(
        incident_id,
        data.notes
    )

    log_incident_activity(
        incident_id,
        "NOTE_ADDED",
        "Analyst added an investigation note",
        request.session.get(
            "username",
            "Analyst"
        )
    )

    return {
        "message": "Analyst note added",
        "incident_id": incident_id
    }


# ==========================================================
# DELETE INCIDENT
# ==========================================================

@app.delete("/incidents/{incident_id}")
async def remove_incident(

    incident_id: str,
    request: Request
):

    admin_check = require_admin(request)

    if admin_check:
        return admin_check

    delete_incident(
        incident_id
    )

    return {
        "message": "Incident deleted",
        "incident_id": incident_id
    }


# ==========================================================
# CSV EXPORT
# ==========================================================

@app.get("/incidents/export/csv")
async def export_csv(request: Request):

    redirect = require_login(request)

    if redirect:
        return redirect

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

        row = dict(incident)

        writer.writerow([
            row.get("incident_id"),
            row.get("alert_id"),
            row.get("title"),
            row.get("priority"),
            row.get("incident_status"),
            row.get("assigned_to"),
            row.get("created_at")
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=soar_incidents.csv"
        }
    )


# ==========================================================
# PDF EXPORT
# ==========================================================

@app.get("/incidents/export/pdf")
async def export_pdf(request: Request):

    redirect = require_login(request)

    if redirect:
        return redirect

    incidents = export_incidents()

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer
    )

    styles = getSampleStyleSheet()

    title = Paragraph(
        "SOAR Incident Report",
        styles["Title"]
    )

    data = [[
        "Incident ID",
        "Alert ID",
        "Priority",
        "Status",
        "Assigned To"
    ]]

    for incident in incidents:

        row = dict(incident)

        data.append([
            str(row.get("incident_id", "")),
            str(row.get("alert_id", "")),
            str(row.get("priority", "")),
            str(row.get("incident_status", "")),
            str(row.get("assigned_to", ""))
        ])

    table = Table(data)

    table.setStyle(
        TableStyle([
            (
                "GRID",
                (0, 0),
                (-1, -1),
                1,
                colors.black
            ),
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            )
        ])
    )

    document.build([
        title,
        table
    ])

    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                "attachment; filename=soar_incidents.pdf"
        }
    )


# ==========================================================
# ADMIN - USER MANAGEMENT
# ==========================================================

@app.get(
    "/admin/users",
    response_class=HTMLResponse
)
async def admin_users(
    request: Request
):

    admin_check = require_admin(
        request
    )

    if admin_check:
        return admin_check

    users = get_all_users()

    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "users": users
        }
    )


# ==========================================================
# LOGIN PAGE
# ==========================================================

@app.get(
    "/login",
    response_class=HTMLResponse
)
async def login_page(
    request: Request
):

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={}
    )


# ==========================================================
# LOGIN ACTION
# ==========================================================

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
                "error":
                    "Invalid username or password"
            },
            status_code=401
        )

    user_data = dict(user)

    request.session["username"] = (
        user_data.get("username")
    )

    request.session["role"] = (
        user_data.get("role")
    )

    request.session["full_name"] = (
        user_data.get("full_name")
    )

    return RedirectResponse(
        url="/",
        status_code=303
    )


# ==========================================================
# LOGOUT
# ==========================================================

@app.get("/logout")
async def logout(
    request: Request
):

    request.session.clear()

    return RedirectResponse(
        url="/login",
        status_code=303
    )


# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.get("/health")
async def health_check():

    return {
        "status": "healthy",
        "service":
            "SOAR Incident Containment Engine",
        "timestamp":
            datetime.now().isoformat()
    }


# ==========================================================
# END OF SOAR APPLICATION
# ==========================================================