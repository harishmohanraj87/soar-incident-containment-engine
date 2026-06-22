from fastapi import FastAPI

from backend.parser import parse_alert
from backend.normalizer import normalize_alert

app = FastAPI(
    title="SOAR Incident Containment Engine",
    version="1.0.0"
)

@app.get("/")
def home():
    return {
        "status": "running",
        "project": "SOAR Incident Containment Engine"
    }

@app.post("/alerts")
def receive_alert(alert: dict):

    parsed = parse_alert(alert)

    normalized = normalize_alert(parsed)

    return {
        "message": "alert processed",
        "data": normalized
    }