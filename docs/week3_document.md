# 📅 Week 3 Development Plan
## SOAR Incident Containment Engine

**Sprint Duration:** Week 3 (Days 15–21)

**Sprint Goal:**
Build the incident persistence layer, audit logging, and prepare the SOAR platform for automated response workflows.

---

# 🎯 Objectives

By the end of Week 3, the system should be able to:

- Store processed alerts in the database
- Maintain audit logs for all alert events
- Track incident status throughout its lifecycle
- Prepare backend APIs for automated containment
- Improve testing and documentation

---

# 🏗 Planned Workflow

```text
SIEM Alert
      ↓
FastAPI Endpoint
      ↓
Parser
      ↓
Normalizer
      ↓
Threat Enrichment
      ↓
Risk Score
      ↓
SQLite Database
      ↓
Audit Logs
      ↓
Incident Status Tracking
      ↓
API Response
```

---

# 👥 Team Responsibilities

## 👨‍💻 Harish Mohanraj (Project Lead)

### Backend Development

- Integrate SQLite storage with alert workflow
- Store enriched alerts automatically
- Create database helper functions
- Develop incident status management
- Review and merge pull requests
- Coordinate weekly progress

Deliverables:

- Database integration
- Alert persistence
- Incident management
- Backend API improvements

---

## 🔍 Yash Prashant Kulkarni (Threat Intelligence Lead)

### Threat Intelligence Improvements

- Improve enrichment error handling
- Optimize API response handling
- Add timeout and exception management
- Research additional threat intelligence providers
- Validate enrichment accuracy

Deliverables:

- Improved enricher.py
- Better API reliability
- Updated documentation

---

## 🖥 Surya (SIEM Alert Simulator Developer)

### Testing & Simulation

- Expand test datasets
- Create additional attack scenarios
- Validate enrichment workflow
- Update TESTING.md
- Verify parser compatibility

Deliverables:

- New sample alerts
- Updated testing guide
- Additional validation scenarios

---

# 📂 Expected Deliverables

## Backend

- SQLite integration
- Alert storage
- Incident management

## Database

- Alert persistence
- Incident tracking
- Status updates

## Logging

- Audit logging module
- Event history
- Timestamp tracking

## Documentation

- Database documentation
- API documentation
- Updated README

---

# 📝 GitHub Workflow

All contributors should:

- Create a feature branch
- Commit changes regularly
- Open a Pull Request
- Request review before merging
- Do not commit directly to `main`

---

# 📋 Definition of Done

Week 3 is complete when:

- Alerts are stored in SQLite
- Audit logs are generated
- Incident status can be updated
- Backend APIs are fully tested
- Documentation is updated
- All Pull Requests are reviewed and merged

---

# 🚀 Expected Outcome

By the end of Week 3, the SOAR platform will support:

- Persistent alert storage
- Incident lifecycle tracking
- Audit logging
- Improved backend architecture

This prepares the project for Week 4, where automated containment playbooks and dashboard integration will be implemented.

---

## 📊 Sprint Status

| Task | Status |
|------|--------|
| Database Integration | ⏳ Planned |
| Alert Storage | ⏳ Planned |
| Incident Tracking | ⏳ Planned |
| Audit Logging | ⏳ Planned |
| API Improvements | ⏳ Planned |
| Testing | ⏳ Planned |
| Documentation | ⏳ Planned |

---

**Prepared by:** Harish Mohanraj  
**Role:** Project Lead  
**Project:** SOAR Incident Containment Engine