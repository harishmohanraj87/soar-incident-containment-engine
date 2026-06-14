# IPInfo API Research

**Project:** SOAR Incident Containment Engine
**Module:** Threat Intelligence
**Author:** Yash Prashant Kulkarni
**Date:** 14 June 2026
**Related Issue:** #3 Threat Intelligence Research

---

## What is IPInfo

IPInfo is a reliable IP address data provider that returns geolocation,
organization, ISP, and network information for any IP address. It is used
by thousands of security teams worldwide to add context to threat data.

In our SOAR platform, IPInfo is the third and final enrichment check we
run after AbuseIPDB and VirusTotal. It does not contribute to the risk
score directly — instead it provides geographic and network context that
helps the SOC analyst understand where a threat is coming from and who
owns the malicious IP.

---

## How It Fits in Our Pipeline

```
Alert Parser
     |
     v
AbuseIPDB Check (Day 2)
     |
     v
VirusTotal Check (Day 3)
     |
     v
IPInfo Check  <-- We are here
     |
     | returns country, ISP, org, city
     v
Risk Engine + Dashboard (context data)
```

---

## API Details

**Base URL:**
```
https://ipinfo.io/
```

**Authentication:**
- Token passed as query parameter
- Parameter name: `token`
- Free tier: 50,000 requests per month

**Sign Up:**
```
https://ipinfo.io/signup
```

---

## Endpoint: Get IP Details

**Method:** GET

**URL:**
```
https://ipinfo.io/<IP>/json
```

**Query Parameters:**
```
token = YOUR_IPINFO_TOKEN (required for production)
```

**Full Request Example:**
```
GET https://ipinfo.io/118.25.6.39/json?token=YOUR_TOKEN
```

---

## Sample Response

```json
{
  "ip": "118.25.6.39",
  "city": "Shenzhen",
  "region": "Guangdong",
  "country": "CN",
  "loc": "22.5455,114.0683",
  "org": "AS45090 Tencent Cloud Computing",
  "postal": "518000",
  "timezone": "Asia/Shanghai"
}
```

---

## Key Response Fields We Use

| Field | Description | Used For |
|-------|-------------|----------|
| `ip` | The queried IP address | Validation |
| `country` | 2-letter country code | Alert context |
| `city` | City of IP origin | Alert context |
| `region` | Region or state | Alert context |
| `org` | ASN and organization name | ISP identification |
| `timezone` | Timezone of IP location | Incident timeline |
| `loc` | Latitude and longitude | Map visualization |

---

## How IPInfo Differs from AbuseIPDB and VirusTotal

| Feature | AbuseIPDB | VirusTotal | IPInfo |
|---------|-----------|------------|--------|
| Purpose | Abuse reputation | AV engine scan | Geolocation data |
| Risk Score Input | Yes — 40% | Yes — 40% | No — context only |
| Data Type | Community reports | Engine verdicts | Network metadata |
| Free Limit | 1,000 req/day | 500 req/day | 50,000 req/month |
| Best For | Known bad IPs | Technical scan | Location context |

IPInfo does not affect the risk score. It enriches the alert with context
so analysts can see where the threat originated and which organization
owns the IP.

---

## Example Enriched Alert with IPInfo Data

After all three API checks, the enriched alert will look like this:

```json
{
  "ip": "118.25.6.39",
  "alert_type": "brute_force",
  "severity": "high",
  "abuse_score": 100,
  "virustotal_score": 19,
  "risk_score": 95,
  "risk_level": "HIGH",
  "country": "CN",
  "city": "Shenzhen",
  "region": "Guangdong",
  "org": "Tencent Cloud Computing",
  "timezone": "Asia/Shanghai"
}
```

---

## Error Responses

| HTTP Code | Meaning | Handling Plan |
|-----------|---------|---------------|
| 200 | Success | Process response normally |
| 401 | Invalid token | Check token configuration |
| 404 | IP not found | Return empty location fields |
| 429 | Rate limit exceeded | Log warning, skip IPInfo |
| 500 | Server error | Skip enrichment, log error |

---

## Rate Limit Handling Plan

- Free tier allows **50,000 requests per month**
- This is the most generous limit among our three APIs
- Rate limit is very unlikely to be hit in our SOAR platform
- If limit is reached, system will skip IPInfo and leave location fields empty

---

## Integration Plan for Week 2

The following function will be implemented in `enricher.py`:

```python
import requests
import os

def check_ipinfo(ip_address):
    """
    Query IPInfo for geolocation and network data.
    Returns location context for analyst dashboard.
    """
    token = os.getenv("IPINFO_TOKEN")
    url = f"https://ipinfo.io/{ip_address}/json?token={token}"

    response = requests.get(url)
    data = response.json()

    return {
        "country": data.get("country", "Unknown"),
        "city": data.get("city", "Unknown"),
        "region": data.get("region", "Unknown"),
        "org": data.get("org", "Unknown"),
        "timezone": data.get("timezone", "Unknown")
    }
```

**Expected Output to Risk Engine and Dashboard:**
```json
{
  "country": "CN",
  "city": "Shenzhen",
  "region": "Guangdong",
  "org": "AS45090 Tencent Cloud Computing",
  "timezone": "Asia/Shanghai"
}
```

---

## Complete enricher.py Plan for Week 2

After Day 4 research is complete, Week 2 will combine all three API
checks into a single function:

```python
def enrich_ip(ip_address):
    abuse_data    = check_abuseipdb(ip_address)
    vt_data       = check_virustotal(ip_address)
    location_data = check_ipinfo(ip_address)

    risk_score = (
        abuse_data["abuse_score"] * 0.40 +
        vt_data["virustotal_score"] * 0.40
    )

    return {
        **abuse_data,
        **vt_data,
        **location_data,
        "risk_score": round(risk_score),
        "risk_level": "HIGH" if risk_score >= 80 else
                      "MEDIUM" if risk_score >= 50 else "LOW"
    }
```

---

## References

- IPInfo Official Website: https://ipinfo.io
- API Documentation: https://ipinfo.io/developers
- Free Tier Details: https://ipinfo.io/pricing
- API Playground: https://ipinfo.io/118.25.6.39

---

*Infotact Solutions — SOAR Incident Containment Engine*
*Week 1 Day 4 · Threat Intelligence Lead · Yash Prashant Kulkarni*