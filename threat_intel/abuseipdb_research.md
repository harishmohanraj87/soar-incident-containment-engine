# AbuseIPDB API Research

**Project:** SOAR Incident Containment Engine
**Module:** Threat Intelligence
**Author:** Yash Prashant Kulkarni
**Date:** 12 June 2026
**Related Issue:** #3 Threat Intelligence Research

---

## What is AbuseIPDB

AbuseIPDB is a community-driven IP reputation database. Security teams worldwide
submit reports when they detect malicious activity from an IP address. The database
aggregates these reports and produces a confidence score showing how likely an IP
is to be malicious.

For our SOAR platform, AbuseIPDB is the first enrichment check we run on every
incoming alert IP before passing data to the Risk Engine.

---

## API Endpoint

```
GET https://api.abuseipdb.com/api/v2/check
```

**Required Headers:**
```
Key: <ABUSEIPDB_API_KEY>
Accept: application/json
```

**Query Parameters:**
```
ipAddress     = IP to check (required)
maxAgeInDays  = Report age filter, use 90 (recommended)
```

**Full Request:**
```
GET https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&maxAgeInDays=90
```

---

## Sample Response

```json
{
  "data": {
    "ipAddress": "118.25.6.39",
    "isPublic": true,
    "isWhitelisted": false,
    "abuseConfidenceScore": 100,
    "countryCode": "CN",
    "isp": "Tencent Cloud Computing",
    "domain": "tencent.com",
    "totalReports": 1254,
    "numDistinctUsers": 312,
    "lastReportedAt": "2024-06-10T08:15:00+00:00"
  }
}
```

---

## Fields Used by Our Risk Engine

| Field | Description | Used For |
|-------|-------------|----------|
| `abuseConfidenceScore` | 0-100 malicious confidence | Primary risk input |
| `totalReports` | Total community reports | Supporting evidence |
| `numDistinctUsers` | Unique reporters count | Report reliability |
| `countryCode` | Country of IP origin | Alert context |
| `isp` | Internet Service Provider | Alert context |
| `isWhitelisted` | AbuseIPDB whitelist status | Skip if true |
| `lastReportedAt` | Most recent report time | Recency validation |

---

## Score Meaning

| Score | Risk Level |
|-------|------------|
| 0 | Clean — no reports |
| 1 to 49 | Low — few reports |
| 50 to 74 | Medium — frequently reported |
| 75 to 100 | High — confirmed malicious |

---

## Contribution to Risk Score

AbuseIPDB score contributes 40% of the final risk score:

```
Risk Contribution = abuseConfidenceScore x 0.40

Example:
  Score = 100
  Contribution = 100 x 0.40 = 40 out of 100
```

---

## Free Tier Limits

| Limit | Value |
|-------|-------|
| Requests per day | 1,000 |
| Historical data | 90 days |
| Rate limit response | HTTP 429 |

---

## Error Codes

| Code | Reason | Handling Plan |
|------|--------|---------------|
| 401 | Invalid API key | Check key config |
| 422 | Invalid IP format | Validate before request |
| 429 | Daily limit exceeded | Skip, log warning, use VirusTotal only |
| 500 | Server error | Skip enrichment, log error |

---

## Python Integration Plan (Week 2)

File: `threat_intel/enricher.py`

```python
import requests
import os

def check_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": os.getenv("ABUSEIPDB_API_KEY"),
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    data = response.json()["data"]
    return {
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data["countryCode"],
        "isp": data["isp"],
        "whitelisted": data["isWhitelisted"]
    }
```

---

## References

- AbuseIPDB Docs: https://docs.abuseipdb.com
- Check Endpoint: https://docs.abuseipdb.com/#check-endpoint
- Pricing and Limits: https://www.abuseipdb.com/pricing
-