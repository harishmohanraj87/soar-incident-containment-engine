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

## How to Use

```python
from threat_intel.enricher import enrich_ip

result = enrich_ip(
    ip_address="118.25.6.39",
    alert_type="brute_force",
    severity="high"
)
print(result)
```

**Sample Output:**
```json
{
  "ip": "118.25.6.39",
  "alert_type": "brute_force",
  "severity": "high",
  "severity_score": 75,
  "abuse_score": 100,
  "total_reports": 42,
  "whitelisted": false,
  "isp": "Tencent Cloud",
  "virustotal_score": 19,
  "malicious_engines": 12,
  "suspicious_engines": 2,
  "total_engines": 94,
  "country": "CN",
  "city": "Shenzhen",
  "region": "Guangdong",
  "org": "AS45090 Tencent Cloud",
  "timezone": "Asia/Shanghai",
  "risk_score": 88,
  "risk_level": "HIGH",
  "risk_factors": ["Very high abuse score (100)", "Flagged by 12 malicious engines"],
  "recommended_action": "Block IP + create incident + alert SOC analyst",
  "partial_enrichment": false,
  "enrichment_time_s": 2.3
}
```

---

## APIs Being Used

| API | Purpose | Free Limit |
|-----|---------|-----------|
| AbuseIPDB | Community abuse reports for IPs | 1,000 req/day |
| VirusTotal | Multi-engine IP reputation scan | 500 req/day |
| IPInfo | Geolocation and ISP lookup | 50,000 req/month |

**Researched (not yet integrated):**

| API | Purpose | Free Limit |
|-----|---------|-----------|
| Shodan | Open ports and CVE detection | 1 credit/lookup |
| GreyNoise | Scanner vs real attacker detection | 50 req/day |

---

## Risk Score Formula

```
AbuseIPDB Score  (0-100)  x  0.40  =  40 points max
VirusTotal Score (0-100)  x  0.40  =  40 points max
Alert Severity   (0-100)  x  0.20  =  20 points max
+ Bonus for high report count and many malicious engines
─────────────────────────────────────────────────────
Final Risk Score                   =  0 to 100
```

**Risk Levels:**

| Score | Level | Action |
|-------|-------|--------|
| 90–100 | CRITICAL | Auto-block IP + create P1 incident + notify SOC |
| 70–89 | HIGH | Block IP + create incident + alert SOC analyst |
| 45–69 | MEDIUM | Flag for analyst review + monitor traffic |
| 20–44 | LOW | Log and monitor — no immediate action needed |
| 0–19 | SAFE | Whitelisted IP — allow traffic |

**Alert Severity Score Mapping:**

| Severity | Score |
|----------|-------|
| critical | 100 |
| high | 75 |
| medium | 50 |
| low | 25 |
| info | 10 |

---

## Environment Setup

Create a `.env` file in the project root:

```
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
IPINFO_TOKEN=your_token_here
```

Install dependencies:

```bash
pip install requests python-dotenv
```

---

## Module Files

```
threat_intel/
├── README.md                        ← This file
├── enricher.py                      ← Main enrichment module
├── enricher_integration_notes.md    ← Backend integration guide
├── enrichment_validation_report.md  ← Validation and accuracy report
├── abuseipdb_research.md            ← AbuseIPDB API research
├── virustotal_research.md           ← VirusTotal API research
├── ipinfo_research.md               ← IPInfo API research
├── shodan_research.md               ← Shodan API research
└── greynoise_research.md            ← GreyNoise API research

tests/
└── test_enricher.py                 ← 21 unit tests (all passing)
```

---

## Error Handling

All API failures are handled gracefully:

- **Timeout** — retries 2 times, then returns default values
- **Connection error** — retries 2 times, then returns default values
- **Rate limit (429)** — skips that API, returns default values
- **Missing API key** — logs error, returns default values
- **Invalid IP** — returns `None` immediately
- **Private IP** — returns `None` (192.168.x.x, 10.x.x.x, 127.x.x.x)
- **Partial failure** — `partial_enrichment: true` flag set in output

---

## Performance

| Metric | Value |
|--------|-------|
| API execution | Parallel (ThreadPoolExecutor) |
| Average enrichment time | ~2–3 seconds |
| Max retries per API | 2 |
| Timeout per API call | 10 seconds |

---

## Unit Tests

```bash
python3 -m pytest tests/test_enricher.py -v
```

**Results: 21 passed ✅**

| Test Class | Tests | Status |
|------------|-------|--------|
| TestAbuseIPDB | 5 | ✅ All passing |
| TestVirusTotal | 5 | ✅ All passing |
| TestIPInfo | 4 | ✅ All passing |
| TestEnrichIP | 7 | ✅ All passing |

---

## Sprint Progress

### Week 1 ✅
- [x] Module initialized
- [x] AbuseIPDB research
- [x] VirusTotal research
- [x] IPInfo research
- [x] Full Threat Intel Report

### Week 2 ✅
- [x] Implemented check_abuseipdb()
- [x] Implemented check_virustotal()
- [x] Implemented check_ipinfo()
- [x] Created unified enrich_ip() with risk scoring
- [x] Added enricher_integration_notes.md
- [x] PR submitted and merged

### Week 3 ✅
- [x] Improved error handling — timeouts, exceptions, missing keys
- [x] Parallel API execution — 3x faster
- [x] 21 unit tests — all passing
- [x] Shodan and GreyNoise research
- [x] Validation report and README update

### Final Sprint ✅
- [x] Day 1 — Full risk formula with alert severity weight
- [x] Day 2 — Retry logic for all API calls
- [x] Day 3 — Improved risk scoring — bonus points, risk factors, recommended actions
- [x] Day 4 — Edge case handling — private IPs, invalid formats, type safety
- [x] Day 5 — Final documentation update

---

*Infotact Solutions — SOAR Incident Containment Engine*
*Threat Intelligence Lead — Yash Prashant Kulkarni*