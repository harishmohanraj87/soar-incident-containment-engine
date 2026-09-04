# ==========================================================
# SOAR INCIDENT CONTAINMENT ENGINE
# backend/main.py
#
# SPRINT 2 FEATURES
# ----------------------------------------------------------
# Feature 1 - Geographic Threat Intelligence / Attack Map
# Feature 2 - Advanced Alert Search & Filtering
# Feature 3 - Advanced SOC Dashboard
# Feature 4 - Real-Time SOC Notifications
# Feature 5 - Advanced Incident Investigation
# ==========================================================

import os
import time
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

from backend.parser import parse_alert
from backend.normalizer import normalize_alert
from backend.auth import hash_password
from wazuh.webhook import router as wazuh_router

from threat_intel.enricher import enrich_ip
from playbooks.engine import execute_playbook

from database.models import (
    create_alerts_table,
    create_incidents_table,
    create_incident_activity_table,
    create_users_table,
    create_notifications_table,
)

from database.crud import (
    save_alert,
    get_total_alerts,
    get_high_risk_alerts,
    get_critical_alerts,
    get_playbook_executions,
    get_open_incidents,
    get_blocked_ips,
    get_mttr,
    get_recent_alerts,

    create_incident,
    get_all_incidents,
    get_incident_by_id,
    get_incident_summary,
    get_incidents_by_status,
    get_incidents_by_analyst,
    get_incident_counts,
    incident_exists,
    update_incident_status,
    assign_analyst,
    add_analyst_note,
    resolve_incident,
    delete_incident,

    log_incident_activity,
    get_incident_activity,
    get_incident_investigation,

    get_alerts_by_severity,
    get_incidents_by_status_chart,
    get_daily_alerts,
    get_risk_distribution,

    get_threat_map_data,
    get_threat_map_summary,
    search_alerts,

    get_dashboard_overview,

    create_notification,
    get_notifications,
    get_unread_notification_count,
    mark_notification_read,
    mark_all_notifications_read,

    export_incidents,

    create_user,
    user_exists,
    authenticate_user,
    get_all_users,
    create_playbook_approval,
    get_playbook_approval,
    get_pending_playbook_approvals,
    get_incident_playbook_approvals,
    review_playbook_approval,

)


# ==========================================================
# APPLICATION
# ==========================================================

app = FastAPI(
    title="SOAR Incident Containment Engine",
    description="Security Orchestration, Automation and Response Platform",
    version="1.0.0",
)


# ==========================================================
# WAZUH INTEGRATION ROUTER
# ==========================================================

app.include_router(wazuh_router)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv(
        "SESSION_SECRET",
        "soar-super-secret-key",
    ),
)

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)

templates = Jinja2Templates(directory="templates")


# ==========================================================
# DATABASE INITIALIZATION
# ==========================================================

create_alerts_table()
create_incidents_table()
create_incident_activity_table()
create_users_table()
create_notifications_table()


# ==========================================================
# DEFAULT ADMIN ACCOUNT
# ==========================================================

if not user_exists("admin"):
    create_user(
        {
            "username": "admin",
            "password_hash": hash_password("Admin@123"),
            "full_name": "System Administrator",
            "role": "ADMIN",
        }
    )


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



class IncidentStatusRequest(BaseModel):
    status: str


class AssignRequest(BaseModel):
    assigned_to: str


class NotesRequest(BaseModel):
    notes: str
class PlaybookApprovalRequest(BaseModel):
    status: str = Field(
        ...,
        description="APPROVED or REJECTED"
    )

    reviewer_comment: str = ""


# ==========================================================
# AUTHENTICATION
# ==========================================================

def require_login(request: Request):
    if not request.session.get("username"):
        return RedirectResponse(
            url="/login",
            status_code=303,
        )
    return None


def require_admin(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    if request.session.get("role") != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    return None


# ==========================================================
# HELPERS
# ==========================================================

def make_json_safe(data):
    if data is None:
        return []

    if isinstance(data, dict):
        return {
            key: make_json_safe(value)
            if isinstance(value, (dict, list, tuple))
            else value
            for key, value in data.items()
        }

    if isinstance(data, (list, tuple)):
        result = []
        for item in data:
            if isinstance(item, dict):
                result.append(make_json_safe(item))
            else:
                try:
                    result.append(dict(item))
                except Exception:
                    result.append(item)
        return result

    return data


def get_risk_level(risk_score):
    try:
        score = float(risk_score or 0)
    except (TypeError, ValueError):
        score = 0

    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def get_incident_priority(risk_level):
    priority_map = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
        "SAFE": "P4",
    }

    return priority_map.get(
        str(risk_level).upper(),
        "P4",
    )


def current_user(request: Request):
    return (
        request.session.get("username")
        or "System"
    )


# ==========================================================
# SHARED SOAR ALERT PROCESSING PIPELINE
# ==========================================================

def process_alert(alert: dict):
    """
    Alert
      -> Parser
      -> Normalizer
      -> Threat Intelligence
      -> Geographic Enrichment
      -> Risk
      -> Playbook
      -> Alert Storage
      -> Incident Creation
      -> Notification
    """

    # ------------------------------------------------------
    # 1. PARSE
    # ------------------------------------------------------

    parsed = parse_alert(alert)

    if not parsed:
        raise ValueError("Unable to parse alert")

    # ------------------------------------------------------
    # 2. NORMALIZE
    # ------------------------------------------------------

    normalized = normalize_alert(parsed)

    if not normalized:
        raise ValueError("Unable to normalize alert")

    alert_id = normalized.get("id")

    if not alert_id:
        raise ValueError("Alert ID is required")

    alert_type = normalized.get(
        "type",
        "Unknown Security Alert",
    )

    severity = str(
        normalized.get(
            "severity",
            "LOW",
        )
    ).upper()

    attacker_ip = normalized.get("attacker_ip")
    source_ip = normalized.get("source_ip")

    # ------------------------------------------------------
    # 3. THREAT INTELLIGENCE + GEO ENRICHMENT
    # ------------------------------------------------------

    enrichment = {}

    if attacker_ip:
        try:
            enrichment = enrich_ip(
                ip_address=attacker_ip,
                alert_type=alert_type,
                severity=severity,
            ) or {}

            if isinstance(enrichment, dict):
                normalized.update(enrichment)

        except Exception as error:
            print(
                f"Threat enrichment warning: {error}"
            )

    # ------------------------------------------------------
    # 4. RISK
    # ------------------------------------------------------

    risk_score = normalized.get(
        "risk_score",
        0,
    )

    try:
        risk_score = int(float(risk_score or 0))
    except (TypeError, ValueError):
        risk_score = 0

    normalized["risk_score"] = risk_score

    risk_level = normalized.get("risk_level")

    if not risk_level:
        risk_level = get_risk_level(risk_score)

    normalized["risk_level"] = str(
        risk_level
    ).upper()

    # ------------------------------------------------------
    # 5. PLAYBOOK
    # ------------------------------------------------------

    if attacker_ip:
        try:
            playbook_result = execute_playbook(
                {
                    "ip": attacker_ip,
                    "risk_score": risk_score,
                }
            )
        except Exception as error:
            print(
                f"Playbook execution error: {error}"
            )

            playbook_result = {
                "status": "FAILED",
                "action": "No action executed",
                "error": str(error),
            }
    else:
        playbook_result = {
            "status": "SKIPPED",
            "message": "No attacker IP found",
            "action": "Pending",
        }

    if isinstance(playbook_result, dict):
        action_taken = (
            playbook_result.get("action")
            or playbook_result.get("playbook")
            or playbook_result.get("message")
            or "Processed"
        )
    else:
        action_taken = str(playbook_result)

    normalized["action_taken"] = action_taken
    normalized["status"] = "PROCESSED"

    # ------------------------------------------------------
    # 6. SAVE ALERT
    # ------------------------------------------------------

    try:
        save_result = save_alert(normalized)
    except Exception as error:
        if "UNIQUE constraint failed" in str(error):
            print(
                f"Alert {alert_id} already exists."
            )

            return {
                "status": "duplicate",
                "message": (
                    "Alert already exists. "
                    "No duplicate incident created."
                ),
                "alert_id": alert_id,
                "incident_id": f"INC-{alert_id}",
                "risk_score": risk_score,
                "risk_level": normalized["risk_level"],
                "action_taken": action_taken,
                "enrichment": enrichment,
            }

        raise

    alert_created = bool(
        save_result.get("created", False)
    )

    # ------------------------------------------------------
    # 7. INCIDENT
    # ------------------------------------------------------

    incident_id = f"INC-{alert_id}"
    incident_created = False

    if not incident_exists(incident_id):
        incident_result = create_incident(
            {
                "incident_id": incident_id,
                "alert_id": alert_id,
                "title": f"{alert_type} - {alert_id}",
                "priority": get_incident_priority(
                    normalized["risk_level"]
                ),
                "incident_status": "NEW",
                "assigned_to": "Unassigned",
                "analyst_notes": "",
            }
        )

        incident_created = bool(
            incident_result.get(
                "created",
                False,
            )
        )

        if incident_created:
            log_incident_activity(
                incident_id,
                "INCIDENT_CREATED",
                "Incident automatically created by SOAR processing pipeline",
                "SOAR Engine",
            )

            log_incident_activity(
                incident_id,
                "ALERT_PROCESSED",
                (
                    f"Alert {alert_id} processed "
                    f"with risk score {risk_score}"
                ),
                "SOAR Engine",
            )

            log_incident_activity(
                incident_id,
                "THREAT_INTELLIGENCE",
                "Threat intelligence and geographic enrichment completed",
                "SOAR Engine",
            )

            log_incident_activity(
                incident_id,
                "RISK_CALCULATED",
                (
                    f"Risk Score: {risk_score} "
                    f"({normalized['risk_level']})"
                ),
                "SOAR Engine",
            )

            log_incident_activity(
                incident_id,
                "PLAYBOOK_EXECUTED",
                f"Automated response executed: {action_taken}",
                "SOAR Engine",
            )

    # ------------------------------------------------------
    # 8. REAL-TIME NOTIFICATIONS
    # ------------------------------------------------------

    if alert_created and severity in ("HIGH", "CRITICAL"):
        try:
            create_notification(
                notification_type="ALERT",
                title=f"{severity} Security Alert",
                message=(
                    f"{alert_type} detected from "
                    f"{attacker_ip or source_ip or 'unknown source'} "
                    f"(Alert {alert_id}). "
                    f"Risk score: {risk_score}."
                ),
                severity=severity,
                alert_id=alert_id,
            )
        except Exception as error:
            print(
                f"Alert notification warning: {error}"
            )

    if incident_created:
        try:
            notification_severity = (
                "CRITICAL"
                if normalized["risk_level"] == "CRITICAL"
                else "HIGH"
                if normalized["risk_level"] == "HIGH"
                else "INFO"
            )

            create_notification(
                notification_type="INCIDENT",
                title="New Security Incident",
                message=(
                    f"Incident {incident_id} created "
                    f"for {alert_type}. "
                    f"Priority: "
                    f"{get_incident_priority(normalized['risk_level'])}."
                ),
                severity=notification_severity,
                alert_id=alert_id,
                incident_id=incident_id,
            )
        except Exception as error:
            print(
                f"Incident notification warning: {error}"
            )

        if action_taken and action_taken != "Pending":
            try:
                create_notification(
                    notification_type="PLAYBOOK",
                    title="SOAR Playbook Executed",
                    message=(
                        f"Automated response for "
                        f"{alert_id}: {action_taken}"
                    ),
                    severity=severity,
                    alert_id=alert_id,
                    incident_id=incident_id,
                )
            except Exception as error:
                print(
                    f"Playbook notification warning: {error}"
                )

    # ------------------------------------------------------
    # 9. RESPONSE
    # ------------------------------------------------------

    return {
        "status": "success",
        "message": "Alert processed successfully",
        "alert": normalized,
        "playbook": playbook_result,
        "incident": {
            "incident_id": incident_id,
            "created": incident_created,
        },
        "alert_saved": alert_created,
        "enrichment": enrichment,
    }


# ==========================================================
# HOME DASHBOARD
# ==========================================================

@app.get(
    "/",
    response_class=HTMLResponse,
)
async def dashboard(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
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

        try:
            threat_map_data = make_json_safe(
                get_threat_map_data(limit=500)
            )
        except Exception as error:
            print(
                f"Threat map data error: {error}"
            )
            threat_map_data = []

        try:
            threat_map_summary = get_threat_map_summary()
        except Exception as error:
            print(
                f"Threat map summary error: {error}"
            )
            threat_map_summary = {
                "total_mapped_threats": 0,
                "unique_countries": 0,
                "critical_threats": 0,
                "high_risk_threats": 0,
            }

    except Exception as error:
        print(
            f"Dashboard error: {error}"
        )

        total_alerts = 0
        high_risk = 0
        critical_alerts = 0
        playbooks = 0
        incidents = 0
        blocked_ips = 0
        mttr = "N/A"
        recent_alerts = []
        severity_data = []
        incident_status_data = []
        daily_alerts = []
        risk_distribution = []
        threat_map_data = []
        threat_map_summary = {
            "total_mapped_threats": 0,
            "unique_countries": 0,
            "critical_threats": 0,
            "high_risk_threats": 0,
        }

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "total_alerts": total_alerts,
            "high_risk": high_risk,
            "critical_alerts": critical_alerts,
            "playbooks": playbooks,
            "incidents": incidents,
            "blocked_ips": blocked_ips,
            "mttr": mttr,
            "recent_alerts": recent_alerts,

            "severity_chart": severity_data,
            "status_chart": incident_status_data,
            "daily_chart": daily_alerts,
            "risk_chart": risk_distribution,

            "severity_data": severity_data,
            "incident_status_data": incident_status_data,
            "daily_alerts": daily_alerts,
            "risk_distribution": risk_distribution,

            "threat_map_data": threat_map_data,
            "threat_map_summary": threat_map_summary,
        },
    )
# ==========================================================
# SOAR PLAYBOOK APPROVALS
# ==========================================================

@app.get("/api/playbook-approvals")
async def pending_playbook_approvals_api(
    request: Request
):
    """
    Return all pending SOAR playbook approval requests.
    """

    redirect = require_login(request)

    if redirect:
        return redirect

    try:

        approvals = get_pending_playbook_approvals()

        return {
            "count": len(approvals),
            "approvals": make_json_safe(
                approvals
            )
        }

    except Exception as error:

        print(
            f"Playbook approval fetch error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load playbook approvals"
        )


@app.get("/api/playbook-approvals/{approval_id}")
async def playbook_approval_detail_api(
    approval_id: int,
    request: Request
):
    """
    Return one playbook approval request.
    """

    redirect = require_login(request)

    if redirect:
        return redirect

    try:

        approval = get_playbook_approval(
            approval_id
        )

        if approval is None:

            raise HTTPException(
                status_code=404,
                detail="Playbook approval not found"
            )

        return make_json_safe(
            approval
        )

    except HTTPException:
        raise

    except Exception as error:

        print(
            f"Playbook approval detail error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load approval request"
        )


@app.post(
    "/api/playbook-approvals/{approval_id}/review"
)
async def review_playbook_approval_api(
    approval_id: int,
    approval_request: PlaybookApprovalRequest,
    request: Request
):
    """
    Approve or reject a pending high-impact
    SOAR playbook action.
    """

    redirect = require_login(request)

    if redirect:
        return redirect

    username = current_user(request)

    status = (
        approval_request.status
        .strip()
        .upper()
    )

    if status not in (
        "APPROVED",
        "REJECTED"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Status must be APPROVED "
                "or REJECTED"
            )
        )

    try:

        approval = get_playbook_approval(
            approval_id
        )

        if approval is None:

            raise HTTPException(
                status_code=404,
                detail="Playbook approval not found"
            )

        if approval["status"] != "PENDING":

            raise HTTPException(
                status_code=409,
                detail=(
                    "Approval request has "
                    "already been reviewed"
                )
            )

        updated = review_playbook_approval(
            approval_id=approval_id,
            status=status,
            reviewed_by=username,
            reviewer_comment=(
                approval_request.reviewer_comment
                or ""
            )
        )

        if not updated:

            raise HTTPException(
                status_code=409,
                detail=(
                    "Approval request could not "
                    "be reviewed"
                )
            )

        updated_approval = get_playbook_approval(
            approval_id
        )

        return {
            "success": True,
            "message": (
                "Playbook approval "
                f"{status.lower()}"
            ),
            "approval": make_json_safe(
                updated_approval
            )
        }

    except HTTPException:
        raise

    except Exception as error:

        print(
            f"Playbook approval review error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to review playbook approval"
        )


@app.get(
    "/api/incidents/{incident_id}/playbook-approvals"
)
async def incident_playbook_approvals_api(
    incident_id: str,
    request: Request
):
    """
    Return all playbook approval requests
    associated with an incident.
    """

    redirect = require_login(request)

    if redirect:
        return redirect

    try:

        approvals = get_incident_playbook_approvals(
            incident_id
        )

        return {
            "incident_id": incident_id,
            "count": len(approvals),
            "approvals": make_json_safe(
                approvals
            )
        }

    except Exception as error:

        print(
            f"Incident approval fetch error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to load incident "
                "playbook approvals"
            )
        )

# ==========================================================
# FEATURE 3 â€” ADVANCED SOC DASHBOARD API
# ==========================================================

@app.get("/api/dashboard/overview")
async def dashboard_overview_api(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        overview = get_dashboard_overview()

        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "data": make_json_safe(overview),
        }

    except Exception as error:
        print(
            f"Dashboard overview API error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load dashboard overview",
        )


# ==========================================================
# FEATURE 1 â€” THREAT MAP
# ==========================================================

@app.get("/api/threat-map")
async def threat_map_api(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        threats = get_threat_map_data(limit=500)

        return {
            "status": "success",
            "count": len(threats),
            "threats": make_json_safe(threats),
        }

    except Exception as error:
        print(
            f"Threat map API error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load threat map data",
        )


@app.get("/api/threat-map/summary")
async def threat_map_summary_api(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        summary = get_threat_map_summary()

        return {
            "status": "success",
            **summary,
        }

    except Exception as error:
        print(
            f"Threat map summary error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load threat map summary",
        )


# ==========================================================
# FEATURE 2 â€” ALERT SEARCH PAGE
# ==========================================================

@app.get(
    "/alerts",
    response_class=HTMLResponse,
)
async def alerts_page(request: Request):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        result = search_alerts(
            limit=50,
            offset=0,
        )

        alerts = result.get(
            "alerts",
            [],
        )

        total = result.get(
            "total",
            len(alerts),
        )

    except Exception as error:
        print(
            f"Alert page error: {error}"
        )
        alerts = []
        total = 0

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "alerts": alerts,
            "total": total,
        },
    )


# ==========================================================
# FEATURE 2 â€” ADVANCED ALERT SEARCH API
# ==========================================================

@app.get("/api/alerts/search")
async def advanced_alert_search(
    request: Request,
    query: Optional[str] = None,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    attacker_ip: Optional[str] = None,
    alert_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    effective_query = query or search

    try:
        result = search_alerts(
            query=effective_query,
            search=effective_query,
            severity=severity,
            risk_level=risk_level,
            status=status,
            alert_type=alert_type,
            source_ip=source_ip,
            attacker_ip=attacker_ip,
            alert_id=alert_id,
            incident_id=incident_id,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )

        # Current CRUD returns a paginated dictionary.
        if isinstance(result, dict):
            alerts = result.get("alerts", [])
            total = result.get(
                "total",
                len(alerts),
            )

            return {
                "status": "success",
                "count": len(alerts),
                "total": total,
                "limit": result.get(
                    "limit",
                    limit,
                ),
                "offset": result.get(
                    "offset",
                    offset,
                ),
                "alerts": make_json_safe(
                    alerts
                ),
            }

        # Backward-compatible fallback.
        return {
            "status": "success",
            "count": len(result),
            "total": len(result),
            "limit": limit,
            "offset": offset,
            "alerts": make_json_safe(result),
        }

    except Exception as error:
        print(
            f"Alert search error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to search alerts",
        )


# ==========================================================
# DASHBOARD ALERT SUBMISSION
# ==========================================================

@app.post(
    "/",
    response_class=HTMLResponse,
)
async def execute_dashboard(
    request: Request,
    alert_id: str = Form(...),
    alert_type: str = Form(...),
    severity: str = Form(...),
    source_ip: str = Form(""),
    attacker_ip: str = Form(""),
):
    redirect = require_login(request)
    if redirect:
        return redirect

    raw_alert = {
        "alert_id": alert_id,
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "attacker_ip": attacker_ip,
    }

    try:
        process_alert(raw_alert)
    except Exception as error:
        print(
            f"Dashboard alert error: {error}"
        )

    return RedirectResponse(
        url="/",
        status_code=303,
    )


# ==========================================================
# ALERT INGESTION API
# ==========================================================

@app.post("/alerts")
async def receive_alert(alert: AlertRequest):
    try:
        return process_alert(
            alert.model_dump()
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:
        print(
            f"Alert processing error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="SOAR alert processing failed",
        )



# ==========================================================
# INCIDENT LIST
# ==========================================================
# INCIDENT LIST
# ==========================================================

@app.get(
    "/incidents",
    response_class=HTMLResponse,
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
            "incidents": make_json_safe(
                incidents
            )
        },
    )

@app.get(
    "/incidents/dashboard",
    response_class=HTMLResponse,
)
async def incidents_dashboard_page(
    request: Request,
):
    redirect = require_login(request)

    if redirect:
        return redirect

    incidents = get_all_incidents()

    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context={
            "incidents": make_json_safe(incidents),
        },
    )
# ==========================================================
# FEATURE 5 â€” INCIDENT INVESTIGATION DASHBOARD
#
# Specific /dashboard route MUST appear before
# generic /incidents/{incident_id}.
# ==========================================================

@app.get(
    "/incidents/dashboard/{incident_id}",
    response_class=HTMLResponse,
)
async def incident_dashboard_page(
    request: Request,
    incident_id: str,
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
            detail="Incident not found",
        )

    activity = get_incident_activity(
        incident_id
    )

    investigation = get_incident_investigation(
        incident_id
    )

    return templates.TemplateResponse(
        request=request,
        name="incident_dashboard.html",
        context={
            "incident": make_json_safe(
                incident
            ),
            "activity": make_json_safe(
                activity
            ),
            "investigation": make_json_safe(
                investigation
            ),
        },
    )


# ==========================================================
# FEATURE 5 â€” INCIDENT INVESTIGATION API
# ==========================================================

@app.get(
    "/api/incidents/{incident_id}/investigation"
)
async def incident_investigation_api(
    request: Request,
    incident_id: str,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        investigation = get_incident_investigation(
            incident_id
        )

        if not investigation:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        return {
            "status": "success",
            "incident_id": incident_id,
            "investigation": make_json_safe(
                investigation
            ),
        }

    except HTTPException:
        raise

    except Exception as error:
        print(
            f"Incident investigation API error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load incident investigation",
        )


# ==========================================================
# INCIDENT ACTIVITY API
# ==========================================================

@app.get(
    "/api/incidents/{incident_id}/activity"
)
async def incident_activity_api(
    request: Request,
    incident_id: str,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        if not incident_exists(incident_id):
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        activity = get_incident_activity(
            incident_id
        )

        return {
            "status": "success",
            "incident_id": incident_id,
            "activity": make_json_safe(
                activity
            ),
            "count": len(activity),
        }

    except HTTPException:
        raise

    except Exception as error:
        print(
            f"Incident activity API error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load incident activity",
        )


# ==========================================================
# INCIDENT DETAIL PAGE
# ==========================================================

@app.get(
    "/incidents/{incident_id}",
    response_class=HTMLResponse,
)
async def incident_details_page(
    request: Request,
    incident_id: str,
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
            detail="Incident not found",
        )

    activity = get_incident_activity(
        incident_id
    )

    return templates.TemplateResponse(
        request=request,
        name="incident_details.html",
        context={
            "incident": make_json_safe(
                incident
            ),
            "activity": make_json_safe(
                activity
            ),
        },
    )


# ==========================================================
# INCIDENT SUMMARY API
# ==========================================================

@app.get("/api/incidents/summary")
async def incident_summary_api(
    request: Request,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        return {
            "status": "success",
            "summary": make_json_safe(
                get_incident_summary()
            ),
        }

    except Exception as error:
        print(
            f"Incident summary error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load incident summary",
        )


# ==========================================================
# INCIDENT COUNTS API
# ==========================================================

@app.get("/api/incidents/counts")
async def incident_counts_api(
    request: Request,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        counts = get_incident_counts()

        return {
            "status": "success",
            "counts": make_json_safe(
                counts
            ),
        }

    except Exception as error:
        print(
            f"Incident counts error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load incident counts",
        )


# ==========================================================
# INCIDENT STATUS UPDATE â€” PATCH
# ==========================================================

@app.patch(
    "/incidents/{incident_id}/status"
)
async def change_incident_status(
    request: Request,
    incident_id: str,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    try:
        body = await request.json()
    except Exception:
        body = {}

    new_status = (
        body.get("status")
        or body.get("incident_status")
    )

    if not new_status:
        raise HTTPException(
            status_code=400,
            detail="Status is required",
        )

    new_status = str(
        new_status
    ).strip().upper()

    allowed_statuses = {
        "NEW",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "CLOSED",
    }

    if new_status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. Allowed values: "
                + ", ".join(sorted(allowed_statuses))
            ),
        )

    update_incident_status(
        incident_id,
        new_status,
    )

    log_incident_activity(
        incident_id,
        "STATUS_UPDATED",
        f"Incident status changed to {new_status}.",
        current_user(request),
    )

    return {
        "status": "success",
        "message": "Incident status updated.",
        "incident_id": incident_id,
        "incident_status": new_status,
    }


# ==========================================================
# INCIDENT STATUS UPDATE â€” FORM
# ==========================================================

@app.post(
    "/incidents/dashboard/{incident_id}/status"
)
async def change_incident_status_form(
    request: Request,
    incident_id: str,
    status: str = Form(...),
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    new_status = str(
        status
    ).strip().upper()

    update_incident_status(
        incident_id,
        new_status,
    )

    log_incident_activity(
        incident_id,
        "STATUS_UPDATED",
        f"Incident status changed to {new_status}.",
        current_user(request),
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303,
    )


# ==========================================================
# ASSIGN ANALYST â€” PATCH API
# ==========================================================

@app.patch(
    "/incidents/{incident_id}/assign"
)
async def assign_incident_api(
    request: Request,
    incident_id: str,
    data: AssignRequest,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    analyst = data.assigned_to.strip()

    if not analyst:
        raise HTTPException(
            status_code=400,
            detail="Analyst name cannot be empty",
        )

    assign_analyst(
        incident_id,
        analyst,
    )

    log_incident_activity(
        incident_id,
        "ANALYST_ASSIGNED",
        f"Incident assigned to {analyst}.",
        current_user(request),
    )

    return {
        "status": "success",
        "message": "Analyst assigned.",
        "incident_id": incident_id,
        "assigned_to": analyst,
    }


# ==========================================================
# ASSIGN ANALYST â€” FORM
# ==========================================================

@app.post(
    "/incidents/dashboard/{incident_id}/assign"
)
async def assign_incident_form(
    request: Request,
    incident_id: str,
    assigned_to: str = Form(...),
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    analyst = assigned_to.strip()

    if not analyst:
        raise HTTPException(
            status_code=400,
            detail="Analyst name cannot be empty",
        )

    assign_analyst(
        incident_id,
        analyst,
    )

    log_incident_activity(
        incident_id,
        "ANALYST_ASSIGNED",
        f"Incident assigned to {analyst}.",
        current_user(request),
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303,
    )


# ==========================================================
# ADD NOTE â€” PATCH API
# ==========================================================

@app.patch(
    "/incidents/{incident_id}/notes"
)
async def add_note_api(
    request: Request,
    incident_id: str,
    data: NotesRequest,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    note = data.notes.strip()

    if not note:
        raise HTTPException(
            status_code=400,
            detail="Note cannot be empty",
        )

    add_analyst_note(
        incident_id,
        note,
    )

    log_incident_activity(
        incident_id,
        "NOTE_ADDED",
        "Analyst investigation note added.",
        current_user(request),
    )

    return {
        "status": "success",
        "message": "Note added.",
        "incident_id": incident_id,
    }


# ==========================================================
# ADD NOTE â€” FORM
# ==========================================================

@app.post(
    "/incidents/dashboard/{incident_id}/notes"
)
async def add_note_form(
    request: Request,
    incident_id: str,
    note: str = Form(...),
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    note = note.strip()

    if not note:
        raise HTTPException(
            status_code=400,
            detail="Note cannot be empty",
        )

    add_analyst_note(
        incident_id,
        note,
    )

    log_incident_activity(
        incident_id,
        "NOTE_ADDED",
        "Analyst investigation note added.",
        current_user(request),
    )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303,
    )


# ==========================================================
# RESOLVE INCIDENT
# ==========================================================

@app.post(
    "/incidents/{incident_id}/resolve"
)
async def resolve_incident_api(
    request: Request,
    incident_id: str,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    resolved = resolve_incident(
        incident_id
    )

    if resolved:
        log_incident_activity(
            incident_id,
            "INCIDENT_RESOLVED",
            "Incident marked as RESOLVED.",
            current_user(request),
        )

        try:
            create_notification(
                notification_type="CONTAINMENT",
                title="Incident Resolved",
                message=(
                    f"Incident {incident_id} "
                    f"was marked as resolved."
                ),
                severity="INFO",
                incident_id=incident_id,
            )
        except Exception as error:
            print(
                f"Resolve notification warning: {error}"
            )

    return RedirectResponse(
        url=f"/incidents/dashboard/{incident_id}",
        status_code=303,
    )


# ==========================================================
# DELETE INCIDENT â€” ADMIN
# ==========================================================

@app.delete(
    "/incidents/{incident_id}"
)
async def delete_incident_api(
    request: Request,
    incident_id: str,
):
    admin_check = require_admin(request)
    if admin_check:
        return admin_check

    if not incident_exists(incident_id):
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    delete_incident(
        incident_id
    )

    return {
        "status": "success",
        "message": "Incident deleted successfully.",
        "incident_id": incident_id,
    }


# ==========================================================
# FEATURE 4 â€” REAL-TIME NOTIFICATIONS
# ==========================================================

@app.get("/api/notifications")
async def notifications_api(
    request: Request,
    limit: int = 20,
    unread_only: bool = False,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        limit = max(
            1,
            min(limit, 100),
        )

        notifications = get_notifications(
            limit=limit,
            unread_only=unread_only,
        )

        return {
            "status": "success",
            "count": len(notifications),
            "notifications": make_json_safe(
                notifications
            ),
        }

    except Exception as error:
        print(
            f"Notifications API error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load notifications",
        )


@app.get(
    "/api/notifications/unread-count"
)
async def unread_notification_count_api(
    request: Request,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        return {
            "status": "success",
            "unread_count": get_unread_notification_count(),
        }

    except Exception as error:
        print(
            f"Unread notification error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to load unread notification count",
        )


@app.post(
    "/api/notifications/{notification_id}/read"
)
async def mark_notification_read_api(
    request: Request,
    notification_id: int,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        updated = mark_notification_read(
            notification_id
        )

        if not updated:
            raise HTTPException(
                status_code=404,
                detail="Notification not found",
            )

        return {
            "status": "success",
            "message": "Notification marked as read",
            "notification_id": notification_id,
        }

    except HTTPException:
        raise

    except Exception as error:
        print(
            f"Mark notification read error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to update notification",
        )


@app.post(
    "/api/notifications/read-all"
)
async def mark_all_notifications_read_api(
    request: Request,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        result = mark_all_notifications_read()

        return {
            "status": "success",
            "message": "All notifications marked as read",
            "result": make_json_safe(result),
        }

    except Exception as error:
        print(
            f"Mark all notifications error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to update notifications",
        )


# ==========================================================
# INCIDENT EXPORT â€” CSV
# ==========================================================

@app.get(
    "/api/incidents/export/csv"
)
async def export_incidents_csv(
    request: Request,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        csv_content = export_incidents(
            format="csv"
        )

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition":
                    "attachment; filename=incidents.csv"
            },
        )

    except Exception as error:
        print(
            f"CSV export error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to export incidents",
        )


# ==========================================================
# INCIDENT EXPORT â€” PDF
# ==========================================================

@app.get(
    "/api/incidents/export/pdf"
)
async def export_incidents_pdf(
    request: Request,
):
    redirect = require_login(request)
    if redirect:
        return redirect

    try:
        pdf_content = export_incidents(
            format="pdf"
        )

        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    "attachment; filename=incidents.pdf"
            },
        )

    except Exception as error:
        print(
            f"PDF export error: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to export incidents",
        )


# Backward-compatible export routes.
@app.get("/incidents/export/csv")
async def export_incidents_csv_legacy(
    request: Request,
):
    return await export_incidents_csv(request)


@app.get("/incidents/export/pdf")
async def export_incidents_pdf_legacy(
    request: Request,
):
    return await export_incidents_pdf(request)


# ==========================================================
# ADMIN â€” USER MANAGEMENT
# ==========================================================

@app.get(
    "/admin/users",
    response_class=HTMLResponse,
)
async def admin_users(request: Request):
    admin_check = require_admin(request)
    if admin_check:
        return admin_check

    users = get_all_users()

    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context={
            "users": make_json_safe(users)
        },
    )


# ==========================================================
# LOGIN
# ==========================================================

@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={},
    )


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = authenticate_user(
        username,
        password,
    )

    if not user:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error":
                    "Invalid username or password"
            },
            status_code=401,
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
        status_code=303,
    )


# ==========================================================
# LOGOUT
# ==========================================================

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        url="/login",
        status_code=303,
    )


# ==========================================================
# HEALTH
# ==========================================================

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "SOAR Incident Containment Engine",
        "timestamp": datetime.now().isoformat(),
    }


# ==========================================================
# END OF SOAR APPLICATION
# ==========================================================

