"""Isolated integration tests for final-sprint safety and workflow guarantees."""

import asyncio
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

import httpx


TEST_DB = Path(tempfile.gettempdir()) / "soar-final-sprint-tests.db"
for suffix in ("", "-wal", "-shm"):
    try:
        (Path(str(TEST_DB) + suffix)).unlink()
    except FileNotFoundError:
        pass
os.environ["SOAR_DATABASE_PATH"] = str(TEST_DB)
os.environ["SESSION_SECRET"] = "test-session-secret-not-for-production"
os.environ["WAZUH_WEBHOOK_SECRET"] = "test-wazuh-secret"
os.environ["SOAR_EXECUTION_MODE"] = "DEMO"

from backend.main import app, process_alert  # noqa: E402
from backend.auth import hash_password  # noqa: E402
from database.crud import create_user, get_mttr  # noqa: E402


def request(method, url, **kwargs):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, url, **kwargs)
    return asyncio.run(run())


def client_requests(requests):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            responses = []
            for method, url, kwargs in requests:
                responses.append(await client.request(method, url, **kwargs))
            return responses
    return asyncio.run(run())


def login_as(username, password):
    return client_requests([
        ("POST", "/login", {"data": {"username": username, "password": password}, "follow_redirects": False}),
    ])[0]


def test_login_and_low_risk_pipeline():
    login = login_as("admin", "Admin@123")
    assert login.status_code == 303
    result = process_alert({
        "alert_id": "FINAL-LOW-001", "alert_type": "port_scan", "severity": "low",
        "source_ip": "10.1.1.1", "attacker_ip": None,
    })
    assert result["alert_saved"] is True
    assert result["incident"]["created"] is True
    assert request("GET", "/health").status_code == 200


def test_wazuh_auth_and_approval_lifecycle():
    if not __import__("database.crud", fromlist=["user_exists"]).user_exists("analyst"):
        create_user({"username": "analyst", "password_hash": hash_password("Analyst@123"), "full_name": "Analyst", "role": "ANALYST"})
    payload = {
        "timestamp": "2026-10-30T00:00:00Z",
        "rule": {"id": "5710", "level": 12, "description": "Multiple SSH authentication failures"},
        "agent": {"id": "final-agent", "name": "demo-host", "ip": "10.0.0.5"},
        "data": {"srcip": "198.51.100.10"},
    }
    assert request("POST", "/wazuh/webhook", json=payload).status_code == 401
    assert request("POST", "/wazuh/webhook", json=payload, headers={"X-Wazuh-Webhook-Secret": "wrong"}).status_code == 401
    enrichment = {"risk_score": 95, "risk_level": "CRITICAL", "country": "Test", "city": "Test", "region": "Test", "org": "Test"}
    with patch("backend.main.enrich_ip", return_value=enrichment):
        valid = request("POST", "/wazuh/webhook", json=payload, headers={"X-Wazuh-Webhook-Secret": "test-wazuh-secret"})
    assert valid.status_code == 200
    approval_id = valid.json()["soar_result"]["playbook"]["approval_id"]

    analyst_login = login_as("analyst", "Analyst@123")
    assert analyst_login.status_code == 303
    # A fresh request has no forged analyst session; authorization is tested at the route layer below.
    admin_login = login_as("admin", "Admin@123")
    assert admin_login.status_code == 303

    async def lifecycle():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as analyst, httpx.AsyncClient(transport=transport, base_url="http://test") as admin:
            await analyst.post("/login", data={"username": "analyst", "password": "Analyst@123"})
            forbidden = await analyst.post(f"/api/playbook-approvals/{approval_id}/review", json={"status": "APPROVED"})
            await admin.post("/login", data={"username": "admin", "password": "Admin@123"})
            reviewed = await admin.post(f"/api/playbook-approvals/{approval_id}/review", json={"status": "APPROVED", "reviewer_comment": "demo approval"})
            executed = await admin.post(f"/api/playbook-approvals/{approval_id}/execute")
            duplicate = await admin.post(f"/api/playbook-approvals/{approval_id}/execute")
            return forbidden, reviewed, executed, duplicate
    forbidden, reviewed, executed, duplicate = asyncio.run(lifecycle())
    assert forbidden.status_code == 403
    assert reviewed.status_code == 200
    assert executed.status_code == 200
    assert executed.json()["result"]["approval_status"] == "EXECUTED"
    assert duplicate.status_code == 409


def test_mttr_uses_resolved_incidents_only():
    conn = sqlite3.connect(TEST_DB)
    conn.execute("INSERT OR REPLACE INTO alerts (alert_id, alert_type, severity) VALUES ('MTTR-A', 'test', 'LOW')")
    conn.execute("INSERT OR REPLACE INTO incidents (incident_id, alert_id, title, incident_status, created_at, resolved_at) VALUES ('MTTR-I', 'MTTR-A', 'test', 'RESOLVED', '2026-01-01 00:00:00', '2026-01-01 00:10:00')")
    conn.commit()
    conn.close()
    assert get_mttr() == "10.0 min"
