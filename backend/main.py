from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.parser import parse_alert
from backend.normalizer import normalize_alert
from threat_intel.enricher import enrich_ip
from playbooks.engine import execute_playbook

app = FastAPI(
    title="SOAR Incident Containment Engine",
    version="1.0.0"
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")


# -----------------------------
# Dashboard
# -----------------------------

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


# -----------------------------
# API Endpoint
# -----------------------------

@app.post("/alerts")
def receive_alert(alert: dict):

    parsed = parse_alert(alert)

    normalized = normalize_alert(parsed)

    attacker_ip = normalized.get("attacker_ip")

    if attacker_ip:
        enrichment = enrich_ip(attacker_ip)
        normalized.update(enrichment)

    abuse_score = normalized.get("abuse_score", 0)
    normalized["risk_score"] = abuse_score

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

    return {
        "message": "Alert processed successfully",
        "alert": normalized,
        "playbook": playbook_result
    }