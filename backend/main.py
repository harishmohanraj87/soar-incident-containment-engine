from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.parser import parse_alert
from backend.normalizer import normalize_alert

from threat_intel.enricher import enrich_ip

from playbooks.engine import execute_playbook

from database.models import create_alerts_table

from database.crud import (
    save_alert,
    get_total_alerts,
    get_high_risk_alerts,
    get_critical_alerts,
    get_playbook_executions,
    get_open_incidents,
    get_blocked_ips,
    get_mttr,
    get_recent_alerts
)

app = FastAPI(
    title="SOAR Incident Containment Engine",
    version="1.0.0"
)

# ----------------------------------------
# Initialize Database
# ----------------------------------------

create_alerts_table()

# ----------------------------------------
# Static Files
# ----------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


# ----------------------------------------
# Shared Alert Processing
# ----------------------------------------

def process_alert(alert: dict):

    parsed = parse_alert(alert)

    normalized = normalize_alert(parsed)

    attacker_ip = normalized.get("attacker_ip")

    # Threat Intelligence Enrichment

    if attacker_ip:

        enrichment = enrich_ip(
            ip_address=attacker_ip,
            alert_type=normalized["type"],
            severity=normalized["severity"]
        )

        if enrichment:
            normalized.update(enrichment)

    # Risk Score

    risk_score = normalized.get("risk_score", 0)

    normalized["risk_score"] = risk_score

    # Risk Level

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

    # Execute Playbook

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

    save_alert(normalized)

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

            "result": None

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

    normalized, result = process_alert(raw_alert)
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

            # Threat Intelligence
            "top_ip": normalized.get("attacker_ip", "N/A"),
            "abuse_score": normalized.get("abuse_score", "--"),
            "vt_score": normalized.get("virustotal_score", "--"),
            "country": normalized.get("country", "--"),

            # Playbook Result
            "result": result

        }

    )


# ----------------------------------------
# API Endpoint
# ----------------------------------------

@app.post("/alerts")
def receive_alert(alert: dict):

    normalized, playbook_result = process_alert(alert)

    return {

        "message": "Alert processed successfully",

        "alert": normalized,

        "playbook": playbook_result

    }


# ----------------------------------------
# Health Check
# ----------------------------------------

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "service": "SOAR Incident Containment Engine",

        "version": "1.0.0"

    }
    