from fastapi import FastAPI

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

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }