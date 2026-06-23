from fastapi import FastAPI

from backend.parser import parse_alert
from backend.normalizer import normalize_alert
from threat_intel.enricher import enrich_ip

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

    # Parse alert
    parsed = parse_alert(alert)

    # Normalize alert
    normalized = normalize_alert(parsed)

    # Extract attacker IP
    attacker_ip = normalized.get("attacker_ip")

    # Threat enrichment
    if attacker_ip:
        enrichment = enrich_ip(attacker_ip)

        # Merge enrichment data
        normalized.update(enrichment)

    return {
        "message": "alert processed",
        "data": normalized
    }