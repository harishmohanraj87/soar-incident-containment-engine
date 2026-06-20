# Enricher Integration Notes

**Project:** SOAR Incident Containment Engine
**Module:** Threat Intelligence — enricher.py
**Author:** Yash Prashant Kulkarni (Member 2 — Threat Intelligence Lead)
**For:** Harish Mohanraj (Member 1 — Backend Integration Engineer)
**Date:** 20 June 2026
**Branch:** feature/threat-intel

---

## What This Module Does

`enricher.py` takes any IP address and automatically checks it against
three external Threat Intelligence APIs:

1. **AbuseIPDB** — community abuse reports and reputation score
2. **VirusTotal** — scan result from 70+ antivirus engines
3. **IPInfo** — geolocation, ISP, and network context

It combines all results into one dictionary with a final `risk_score`
and `risk_level` (HIGH / MEDIUM / LOW).

---

## How to Call It From the Backend

### Import

from threat_intel.enricher import enrich_ip

### Usage in your /alerts POST route

@app.route("/alerts", methods=["POST"])
def create_alert():
    alert = request.get_json()
    ip = alert.get("src_ip")
    enrichment = enrich_ip(ip)
    alert.update(enrichment)
    save_alert(alert)
    return jsonify(alert), 200

---

## Input

ip_address → string → example: "118.25.6.39"

---

## Output

{
  "ip": "118.25.6.39",
  "abuse_score": 100,
  "total_reports": 42,
  "whitelisted": false,
  "virustotal_score": 19,
  "malicious_engines": 12,
  "suspicious_engines": 2,
  "total_engines": 94,
  "country": "CN",
  "city": "Shenzhen",
  "region": "Guangdong",
  "org": "AS45090 Tencent Cloud Computing",
  "timezone": "Asia/Shanghai",
  "risk_score": 76,
  "risk_level": "MEDIUM"
}

---

## Risk Score Formula

risk_score = (abuse_score x 0.40) + (virustotal_score x 0.40)

80-100 = HIGH
50-79  = MEDIUM
0-49   = LOW

---

## API Rate Limits

AbuseIPDB  → 1,000 requests/day
VirusTotal → 500 requests/day
IPInfo     → 50,000 requests/month

If any API fails → returns default values, does not crash.

---

## Required .env Keys

ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
IPINFO_TOKEN=your_token_here

---

*Infotact Solutions — SOAR Incident Containment Engine*
*Week 2 — Threat Intelligence Lead — Yash Prashant Kulkarni*