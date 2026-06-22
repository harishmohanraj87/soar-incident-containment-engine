 #SOAR Incident Containment Engine

A Security Orchestration, Automation, and Response (SOAR) platform designed to automate security alert processing, threat intelligence enrichment, incident tracking, and response actions.

---

## Project Goals

- Receive and process security alerts from SIEM systems
- Normalize alerts into a standardized format
- Extract Indicators of Compromise (IOCs)
- Enrich alerts using Threat Intelligence APIs
- Store alerts and incidents in a database
- Maintain audit logs and event tracking
- Execute automated containment playbooks
- Provide incident visibility through a dashboard

---

## Week 1 Progress

### Project Setup
- Repository initialized and configured
- GitHub workflow established (Branches, Pull Requests, Code Reviews)
- Team roles assigned and project architecture defined

### Backend Foundation
- FastAPI backend initialized
- Created:
  - `backend/main.py`
  - `backend/parser.py`
  - `backend/normalizer.py`
- Successfully launched FastAPI development server

### Database Foundation
- SQLite database integrated
- Created:
  - `database/database.py`
  - `database/models.py`
- Alerts table successfully initialized

### Threat Intelligence Research
Completed API research and integration planning for:
- AbuseIPDB
- VirusTotal
- IPInfo

### Logging & Event Tracking
Completed:
- Audit Logging Research
- Standardized Event Schema Design

### Alert Simulation Library
Created realistic security alert datasets including:
- Brute Force Attacks
- Malware Detections
- Data Exfiltration
- SQL Injection Attempts
- Port Scans
- Anomalous Logins

---

## Technology Stack

- Python
- FastAPI
- SQLite
- GitHub
- VirusTotal API
- AbuseIPDB API
- IPInfo API

---

## Team

### Harish Mohanraj
- Project Lead
- Backend Development
- Database Development

### Yash Prashant Kulkarni
- Threat Intelligence Lead

### Surya
- SIEM Alert Simulator Developer

---

## Current Status

✅ Week 1 Completed

### Completed
- Backend Foundation
- Database Foundation
- Threat Intelligence Research
- Audit Logging Research
- Event Schema Design
- SIEM Alert Dataset
