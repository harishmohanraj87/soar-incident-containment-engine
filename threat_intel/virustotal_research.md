# VirusTotal API Research

**Project:** SOAR Incident Containment Engine
**Module:** Threat Intelligence
**Author:** Yash Prashant Kulkarni
**Date:** 13 June 2026
**Related Issue:** #3 Threat Intelligence Research

---

## What is VirusTotal

VirusTotal is a free online service that analyzes files, URLs, domains and IP
addresses using 70+ antivirus engines and security tools simultaneously. It
aggregates results from multiple vendors and provides a unified reputation score.

In our SOAR platform, VirusTotal is the second enrichment check we run after
AbuseIPDB. While AbuseIPDB relies on community reports, VirusTotal relies on
actual antivirus engine analysis — making it a stronger technical validation
of whether an IP is malicious.

---

## How It Fits in Our Pipeline

```
Alert Parser
     |
     | sends IP address
     v
AbuseIPDB Check (Day 2)
     |
     v
VirusTotal Check  <-- We are here
     |
     | returns malicious engine count + reputation
     v
Risk Engine (combined score)
```

---

## API Details

**Base URL:**
```
https://www.virustotal.com/api/v3/
```

**Authentication:**
- API Key passed in request header
- Header name: `x-apikey`
- Free tier: 500 requests per day, 4 requests per minute

**Sign Up:**
```
https://www.virustotal.com/gui/join-us
```

---

## Endpoint: Check IP Address

**Method:** GET

**URL:**
```
https://www.virustotal.com/api/v3/ip_addresses/<IP>
```

**Required Headers:**
```
x-apikey: YOUR_VIRUSTOTAL_API_KEY
```

**Full Request Example:**
```
GET https://www.virustotal.com/api/v3/ip_addresses/118.25.6.39
Headers:
  x-apikey: YOUR_API_KEY
```

---

## Sample Response

```json
{
  "data": {
    "id": "118.25.6.39",
    "type": "ip_address",
    "attributes": {
      "last_analysis_stats": {
        "malicious": 12,
        "suspicious": 3,
        "harmless": 55,
        "undetected": 10,
        "timeout": 0
      },
      "last_analysis_date": 1717920000,
      "country": "CN",
      "as_owner": "Tencent Cloud Computing",
      "asn": 45090,
      "reputation": -42,
      "total_votes": {
        "harmless": 5,
        "malicious": 48
      }
    }
  }
}
```

---

## Key Response Fields We Use

| Field | Description | Used For |
|-------|-------------|----------|
| `last_analysis_stats.malicious` | Engines flagging IP as malicious | Primary risk input |
| `last_analysis_stats.suspicious` | Engines flagging IP as suspicious | Supporting evidence |
| `last_analysis_stats.harmless` | Engines clearing the IP | Score normalization |
| `last_analysis_stats.undetected` | Engines with no verdict | Score normalization |
| `country` | Country code of IP | Geolocation context |
| `as_owner` | Organization owning the IP | Alert context |
| `reputation` | VirusTotal community score | Supporting evidence |
| `total_votes.malicious` | Community malicious votes | Supporting evidence |

---

## VirusTotal Score Calculation

We normalize the engine results into a 0-100 score:

```
Total Engines = malicious + suspicious + harmless + undetected

VirusTotal Score = (malicious + suspicious) / Total Engines x 100

Example:
  malicious  = 12
  suspicious = 3
  harmless   = 55
  undetected = 10
  Total      = 80

  Score = (12 + 3) / 80 x 100 = 18.75 → rounds to 19
```

---

## Score Interpretation

| Score | Risk Level |
|-------|------------|
| 0 | Clean — no engines flagged |
| 1 to 24 | Low — very few engines flagged |
| 25 to 49 | Medium — some engines flagged |
| 50 to 74 | High — majority flagged |
| 75 to 100 | Critical — almost all engines flagged |

---

## Contribution to Risk Score

VirusTotal contributes **40% of the total risk score** in our formula:

```
Risk Contribution = VirusTotal Score x 0.40

Example:
  VirusTotal Score = 19
  Contribution = 19 x 0.40 = 7.6 points
```

---

## Comparison with AbuseIPDB

| Feature | AbuseIPDB | VirusTotal |
|---------|-----------|------------|
| Data Source | Community reports | 70+ AV engines |
| Score Type | Abuse confidence | Engine detection rate |
| Free Limit | 1,000 req/day | 500 req/day |
| Best For | Known bad IPs | Technical validation |
| Weight in Formula | 40% | 40% |

Using both together gives us a more reliable and complete risk score than
using either one alone.

---

## Error Responses

| HTTP Code | Meaning | Handling Plan |
|-----------|---------|---------------|
| 200 | Success | Process response normally |
| 401 | Invalid API key | Check key configuration |
| 404 | IP not found in database | Return score of 0 |
| 429 | Rate limit exceeded | Wait 60 seconds and retry |
| 500 | Server error | Skip enrichment, log error |

---

## Rate Limit Handling Plan

- Free tier allows **500 requests per day** and **4 per minute**
- We will add a **60 second delay** on HTTP 429 response
- If daily limit is reached, system will **log a warning** and skip VirusTotal
- Risk score will be calculated using AbuseIPDB score only in that case

---

## Integration Plan for Week 2

The following function will be implemented in `enricher.py`:

```python
import requests
import os

def check_virustotal(ip_address):
    """
    Query VirusTotal for IP reputation data.
    Returns normalized score and metadata for Risk Engine.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
    }
    response = requests.get(url, headers=headers)
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]

    total = sum(stats.values())
    vt_score = round((stats["malicious"] + stats["suspicious"]) / total * 100)

    return {
        "virustotal_score": vt_score,
        "malicious_engines": stats["malicious"],
        "suspicious_engines": stats["suspicious"],
        "total_engines": total
    }
```

**Expected Output to Risk Engine:**
```json
{
  "ip": "118.25.6.39",
  "virustotal_score": 19,
  "malicious_engines": 12,
  "suspicious_engines": 3,
  "total_engines": 80
}
```

---

## References

- VirusTotal Official Website: https://www.virustotal.com
- API v3 Documentation: https://developers.virustotal.com/reference/overview
- IP Address Endpoint: https://developers.virustotal.com/reference/ip-info
- Free Tier Limits: https://www.virustotal.com/gui/faq

---

*Infotact Solutions — SOAR Incident Containment Engine*
*Week 1 Day 3 · Threat Intelligence Lead · Yash Prashant Kulkarni*
