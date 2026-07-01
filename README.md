# 🛡️ SOAR Incident Containment Engine

## 🔍 Overview

The SOAR Incident Containment Engine is a Security Orchestration, Automation, and Response (SOAR) platform designed to automate security alert processing, threat intelligence enrichment, incident tracking, and response workflows.

The system receives security alerts from SIEM platforms, enriches them using external Threat Intelligence sources, calculates risk scores, and prepares incidents for automated response actions.

---

## 🎯 Objective

This project aims to:

- Automate security alert processing
- Normalize alerts from different sources
- Enrich Indicators of Compromise (IOCs)
- Integrate external Threat Intelligence feeds
- Calculate threat risk scores
- Track incidents and audit events
- Prepare alerts for automated containment actions

---

## ⚙️ Tech Stack

### Backend
- Python
- FastAPI

### Database
- SQLite

### Threat Intelligence
- AbuseIPDB
- VirusTotal
- IPInfo

### Development Tools
- Git
- GitHub
- Pull Requests
- Feature Branch Workflow

---

## 🧠 How It Works (Pipeline)

```text
SIEM Alert
    ↓
FastAPI Alert Endpoint
    ↓
Parser
    ↓
Normalizer
    ↓
Threat Intelligence Enrichment
    ├── AbuseIPDB
    ├── VirusTotal
    └── IPInfo
    ↓
Risk Scoring Engine
    ↓
Database
    ↓
Audit Logs
    ↓
Response Playbooks
```

---

# 📅 Project Progress

## ✅ Week 1 – Foundation & Architecture

### Completed

- Repository Setup
- GitHub Workflow Setup
- Team Role Assignment
- FastAPI Backend Setup
- Alert Parser Development
- Alert Normalizer Development
- SQLite Database Setup
- Threat Intelligence Research
- Audit Logging Research
- Event Schema Design
- Sample Alert Dataset Creation

### Deliverables

```text
backend/
├── main.py
├── parser.py
└── normalizer.py

database/
├── database.py
└── models.py

docs/
├── logging_research.md
└── event_schema.md
```

---

## ✅ Week 2 – Automated Threat Enrichment

### Completed

- Threat Intelligence Enrichment Engine
- AbuseIPDB Integration
- VirusTotal Integration
- IPInfo Integration
- Risk Score Engine
- FastAPI Integration
- End-to-End Alert Processing

### Workflow Implemented

```text
Alert
 ↓
Parser
 ↓
Normalizer
 ↓
Threat Enrichment
 ↓
Risk Score
 ↓
Response
```

### Example Alert

```json
{
  "alert_id": "ALT-1001",
  "alert_type": "Brute Force",
  "severity": "High",
  "attacker_ip": "1.1.1.1"
}
```

### Example Response

```json
{
  "message": "alert processed",
  "risk_level": "LOW",
  "risk_score": 0
}
```

---

## 🚧 Week 3 – Incident Tracking & Audit Logging

### Planned

- Store alerts in SQLite
- Audit Logging Engine
- Incident Timeline Tracking
- Event Persistence
- Case Management Foundation

---

## ⏳ Week 4 – Response Automation

### Planned

- Automated Playbooks
- IP Blocking Simulation
- Host Isolation Simulation
- Dashboard Development
- Final Integration Testing

---

## 📁 Project Structure

```text
SOAR-Incident-Containment-Engine/

├── backend/
│   ├── main.py
│   ├── parser.py
│   └── normalizer.py
│
├── threat_intel/
│   ├── enricher.py
│   ├── abuseipdb_research.md
│   ├── virustotal_research.md
│   └── ipinfo_research.md
│
├── database/
│   ├── database.py
│   └── models.py
│
├── docs/
│   ├── logging_research.md
│   └── event_schema.md
│
└── tests/
```

---

## ▶️ How To Run

Install dependencies:

```bash
pip install -r requirements.txt
```

Run backend:

```bash
python -m uvicorn backend.main:app --reload
```

Open Swagger UI:

```text
http://127.0.0.1:8000/docs
```

---

## 🔐 Cybersecurity Relevance

This project demonstrates:

- Security Operations Center (SOC) workflows
- Threat Intelligence Integration
- Incident Response Automation
- Security Alert Processing
- Risk-Based Decision Making
- SOAR Architecture Design

---

## 👨‍💻 Team

### Harish Mohanraj
Project Lead
- Backend Development
- Database Development
- System Integration

### Yash Prashant Kulkarni
Threat Intelligence Lead
- AbuseIPDB Integration
- VirusTotal Integration
- IPInfo Integration

### Surya
SIEM Alert Simulator Developer
- Alert Dataset Creation
- Testing Scenarios
- Event Simulation

---

## 📊 Current Status

```text
Week 1  ✅ Completed
Week 2  ✅ Completed
Week 3  🚧 In Progress
Week 4  ⏳ Planned
```

**Current Project Completion:** 50%
