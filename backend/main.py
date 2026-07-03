from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.parser import parse_alert
from backend.normalizer import normalize_alert

from threat_intel.enricher import enrich_ip

from playbooks.engine import execute_playbook

from database.models import create_alerts_table
from database.crud import save_alert


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
# Dashboard
# ----------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "result": None
        }
    )


@app.post("/", response_class=HTMLResponse)
async def execute_dashboard(
    request: Request,
    ip: str = Form(...),
    risk_score: int = Form(...)
):

    alert = {
        "ip": ip,
        "risk_score": risk_score
    }

    result = execute_playbook(alert)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "result": result
        }
    )


# ----------------------------------------
# API
# ----------------------------------------

@app.post("/alerts")
def receive_alert(alert: dict):

    # Step 1 - Parse Alert
    parsed = parse_alert(alert)

    # Step 2 - Normalize Alert
    normalized = normalize_alert(parsed)

    # Step 3 - Threat Intelligence
    attacker_ip = normalized.get("attacker_ip")

    if attacker_ip:
        enrichment = enrich_ip(attacker_ip)
        normalized.update(enrichment)

    # ----------------------------------------
    # Risk Score
    # ----------------------------------------

    abuse_score = normalized.get("abuse_score", 0)

    normalized["risk_score"] = abuse_score

    if abuse_score >= 80:
        normalized["risk_level"] = "HIGH"

    elif abuse_score >= 50:
        normalized["risk_level"] = "MEDIUM"

    else:
        normalized["risk_level"] = "LOW"

    # ----------------------------------------
    # Playbook
    # ----------------------------------------

    if attacker_ip:

        playbook_result = execute_playbook({

            "ip": attacker_ip,

            "risk_score": abuse_score

        })

    else:

        playbook_result = {

            "status": "skipped",

            "message": "No attacker IP found."

        }

    # ----------------------------------------
    # Save Alert
    # ----------------------------------------

    alert_record = {

        "id": normalized.get("id"),

        "type": normalized.get("type"),

        "severity": normalized.get("severity"),

        "source_ip": normalized.get("source_ip"),

        "attacker_ip": normalized.get("attacker_ip"),

        "risk_score": normalized.get("risk_score"),

        "risk_level": normalized.get("risk_level"),

        "action_taken": playbook_result.get("action", "Pending"),

        "status": "NEW"

    }

    save_alert(alert_record)

    # ----------------------------------------
    # Response
    # ----------------------------------------

    return {

        "message": "Alert processed successfully",

        "alert": normalized,

        "playbook": playbook_result

    }