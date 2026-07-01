# SOAR Backend Plan

## Week 1 Goal

Build the backend foundation of the SOAR Incident Containment Engine.

---

## Backend Architecture

SIEM Alert
    ↓
FastAPI Endpoint
    ↓
Parser
    ↓
Normalizer
    ↓
Database
    ↓
Threat Intelligence
    ↓
Audit Logging
    ↓
Future Playbook Engine

---

## Components

### main.py

Purpose:
Start the FastAPI application and expose API endpoints.

Responsibilities:
- Receive alerts
- Health checks
- API routing

---

### parser.py

Purpose:
Extract important information from incoming alerts.

Input:
Raw JSON alert

Output:
Parsed alert object

Example:

{
  "alert_id": "ALT-90210",
  "severity": "High",
  "source_ip": "192.168.1.50"
}

---

### normalizer.py

Purpose:
Convert different alert formats into a common structure.

Input:
Parsed alert

Output:
Normalized alert

Example:

{
  "id": "ALT-90210",
  "severity": "HIGH",
  "ip": "192.168.1.50"
}

---

## Week 1 Deliverables

- FastAPI project structure
- Alert ingestion endpoint
- Parser module
- Normalizer module
- Initial testing

---

## Team Integration

Surya
↓
Provides sample alerts

Harish
↓
Processes alerts

Sreyas
↓
Stores alerts in database

Yash
↓
Provides threat intelligence enrichment

Shruti
↓
Provides audit logging

---

## Week 2 Preview

- AbuseIPDB integration
- VirusTotal integration
- IPInfo integration
- Risk score calculation