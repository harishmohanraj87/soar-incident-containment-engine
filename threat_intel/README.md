# Threat Intelligence Module
## SOAR Incident Containment Engine — Infotact Cybersecurity Internship

**Member 2 — Threat Intelligence Lead**
**Name:** Yash Prashant Kulkarni
**Branch:** `feature/threat-intel`

---

## What This Module Does

When a suspicious IP address arrives in an alert, this module:

1. Checks **AbuseIPDB** → Has this IP been reported for abuse by the community?
2. Checks **VirusTotal** → Do 70+ antivirus engines flag this IP as malicious?
3. Checks **IPInfo** → Which country and ISP does this IP belong to?
4. Calculates a **Risk Score (0–100)** from all results
5. Returns enriched data to the Risk Engine for automated decision making

---

## APIs Being Used

| API | Purpose | Free Limit |
|-----|---------|-----------|
| AbuseIPDB | Community abuse reports for IPs | 1,000 req/day |
| VirusTotal | Multi-engine IP reputation scan | 500 req/day |
| IPInfo | Geolocation and ISP lookup | 50,000 req/month |

---

## Risk Score Formula

```
AbuseIPDB Score  (0-100)  x  0.40  =  40 points max
VirusTotal Score (0-100)  x  0.40  =  40 points max
Alert Severity   (0-100)  x  0.20  =  20 points max
─────────────────────────────────────────────────────
Final Risk Score                   =  0 to 100
```

**What the score means:**
- 0–49 → Low risk → Just log it
- 50–79 → Medium risk → Send to analyst for review
- 80–100 → High risk → Auto block IP + create incident

---

## Module Files (will be added this week)

```
threat_intel/
├── README.md                 ← This file (Day 1)
├── abuseipdb_research.md     ← AbuseIPDB API guide (Day 2)
├── virustotal_research.md    ← VirusTotal API guide (Day 3)
├── ipinfo_research.md        ← IPInfo API guide (Day 4)
├── threat_intel_report.md    ← Full report (Day 5)
└── enricher.py               ← Python code (Week 2)
```

---

## Week 1 Progress

- [x] Module initialized
- [ ] AbuseIPDB research
- [ ] VirusTotal research
- [ ] IPInfo research
- [ ] Full Threat Intel Report

---

*Infotact Solutions — SOAR Incident Containment Engine*
