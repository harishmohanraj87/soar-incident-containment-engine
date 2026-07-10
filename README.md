# 🛡️ SOAR Incident Containment Engine

## 📌 Overview

The **SOAR Incident Containment Engine** is a Security Orchestration, Automation, and Response (SOAR) platform that automates the complete incident response lifecycle.

The system receives security alerts from SIEM platforms, normalizes incoming events, enriches Indicators of Compromise (IOCs) using Threat Intelligence, calculates risk scores, executes automated playbooks, creates incidents, and provides SOC analysts with a professional dashboard for monitoring and investigation.

---

# 🎯 Objectives

The project demonstrates how a modern SOAR platform can:

- Ingest SIEM alerts
- Normalize heterogeneous alert formats
- Enrich attacker information
- Calculate automated risk scores
- Execute response playbooks
- Create and manage incidents
- Track analyst activities
- Generate incident reports
- Authenticate users securely
- Enforce Role-Based Access Control (RBAC)

---

# 🏗 System Architecture

```text
SIEM Alert (JSON)
        │
        ▼
Alert Parser
        │
        ▼
Alert Normalizer
        │
        ▼
Threat Intelligence Enrichment
   ├── AbuseIPDB
   ├── VirusTotal
   └── IPInfo
        │
        ▼
Risk Scoring Engine
        │
        ▼
Playbook Automation
        │
        ▼
Incident Creation
        │
        ▼
SQLite Database
        │
        ▼
Dashboard & Analytics
        │
        ▼
SOC Analyst
        │
        ▼
Authentication & RBAC
```

---

# ⚙ Technology Stack

## Backend

- Python
- FastAPI
- Pydantic

## Frontend

- HTML
- Jinja2
- Bootstrap
- AdminLTE
- Chart.js

## Database

- SQLite

## Threat Intelligence

- AbuseIPDB
- VirusTotal
- IPInfo

## Reporting

- CSV Export
- PDF Export (ReportLab)

## Security

- Passlib
- bcrypt
- Session Authentication
- Role-Based Access Control (RBAC)

## Development

- Git
- GitHub
- Pull Requests
- Feature Branch Workflow

---

# 🚀 Features

## Alert Management

- Alert Submission
- Alert Parsing
- Alert Normalization
- Alert Storage
- Risk Classification

---

## Threat Intelligence

- AbuseIPDB Enrichment
- VirusTotal Enrichment
- IPInfo Enrichment
- Reputation Lookup
- Risk Calculation

---

## Playbook Automation

- Automated Playbook Execution
- Response Decision Engine
- Incident Creation
- Automation Status Tracking

---

## Incident Management

- Incident Dashboard
- Incident Details
- Incident Timeline
- Analyst Assignment
- Status Updates
- Investigation Notes
- Incident Resolution

---

## Dashboard Analytics

- Total Alerts
- Critical Alerts
- Open Incidents
- Blocked IPs
- Average MTTR

Charts

- Alert Trend
- Severity Distribution
- Incident Status
- Risk Distribution

---

## Reporting

- CSV Export
- PDF Export
- Incident Summary Reports

---

## Authentication

- Secure Login
- Logout
- Password Hashing (bcrypt)
- Session Authentication

---

## Role-Based Access Control

### ADMIN

- Dashboard Access
- Incident Management
- Export Reports
- User Management

### ANALYST

- Dashboard Access
- Incident Investigation
- Update Status
- Assign Incidents
- Add Notes

---

## User Management

- View Users
- View Roles
- Administrator Account Initialization

---

# 📂 Project Structure

```text
SOAR-Incident-Containment-Engine/

backend/
│
├── main.py
├── parser.py
├── normalizer.py
└── auth.py

database/
│
├── database.py
├── models.py
└── crud.py

playbooks/
│
└── engine.py

threat_intel/
│
└── enricher.py

templates/
│
├── dashboard.html
├── incidents.html
├── incident_details.html
├── login.html
├── users.html
└── base.html

static/

docs/

tests/
```

---

# 📊 Database Design

## alerts

Stores all ingested alerts.

Fields include:

- Alert ID
- Severity
- Source IP
- Attacker IP
- Risk Score
- Risk Level
- Status

---

## incidents

Stores generated incidents.

Fields include:

- Incident ID
- Alert ID
- Priority
- Status
- Assigned Analyst
- Notes
- Created Time

---

## incident_activity

Stores chronological investigation activities.

Examples

- Incident Created
- Assigned
- Status Updated
- Notes Added
- Resolved

---

## users

Stores authentication information.

Fields include

- Username
- Password Hash
- Full Name
- Role

---

# 🔄 SOAR Workflow

```text
Receive Alert
      │
      ▼
Parse Alert
      │
      ▼
Normalize Alert
      │
      ▼
Threat Intelligence Lookup
      │
      ▼
Risk Score Calculation
      │
      ▼
Execute Playbook
      │
      ▼
Create Incident
      │
      ▼
Display Dashboard
      │
      ▼
SOC Investigation
```

---

# ▶ Running the Project

## Install dependencies

```bash
pip install -r requirements.txt
```

## Start the server

```bash
python -m uvicorn backend.main:app --reload
```

---

## Open

Dashboard

```
http://127.0.0.1:8000/
```

Swagger

```
http://127.0.0.1:8000/docs
```

Login

```
http://127.0.0.1:8000/login
```

User Management

```
http://127.0.0.1:8000/admin/users
```

---

# 🎬 Demo Workflow

1. Login as Administrator

↓

2. Submit Security Alert

↓

3. Alert Parsing

↓

4. Alert Normalization

↓

5. Threat Intelligence Enrichment

↓

6. Risk Score Calculation

↓

7. Playbook Execution

↓

8. Incident Creation

↓

9. View Dashboard Analytics

↓

10. Investigate Incident

↓

11. Export CSV/PDF Report

↓

12. Logout

---

# 🔐 Security Features

- Password Hashing (bcrypt)
- Session Authentication
- Route Protection
- Role-Based Access Control
- Secure User Management

---

# 📚 Learning Outcomes

This project demonstrates:

- Security Operations Center (SOC) workflow
- Security Orchestration Automation and Response (SOAR)
- Threat Intelligence Integration
- Incident Response
- Risk-Based Decision Making
- Security Dashboard Development
- Authentication & Authorization
- Python Backend Development
- REST API Development

---

# 👨‍💻 Team

### Harish Mohanraj

Project Lead

- Backend Development
- FastAPI Development
- Database Design
- Dashboard Development
- Incident Management
- Authentication & RBAC
- Reporting Module
- System Integration

---

### Yash Prashant Kulkarni

Threat Intelligence

- AbuseIPDB Research
- VirusTotal Research
- Threat Intelligence Integration

---

### Surya

SIEM Alert Simulation

- Alert Dataset
- Testing
- Simulation

---

# 📈 Current Status

```text
Sprint 1  ✅ Alert Ingestion

Sprint 2  ✅ Threat Intelligence

Sprint 3  ✅ Playbook Automation

Sprint 4  ✅ Dashboard Development

Sprint 5  ✅ Incident Management

Sprint 6  ✅ Dashboard Analytics

Sprint 7  ✅ Reporting Module

Sprint 8  ✅ Authentication Foundation

Sprint 9  ✅ RBAC & User Management

Sprint 10 🚀 Planned (Audit Logs, Notifications & Advanced SOC Features)
```

---



## 🎯 Future Enhancements

- PostgreSQL Integration
- Docker Deployment
- Kubernetes Support
- Email Notifications
- Slack Integration
- Real SIEM Integration
- EDR Integration
- Firewall Automation
- Multi-Factor Authentication (MFA)
- Audit Log Dashboard
