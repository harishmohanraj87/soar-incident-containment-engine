# GreyNoise API Research

**Project:** SOAR Incident Containment Engine
**Module:** Threat Intelligence
**Author:** Yash Prashant Kulkarni
**Date:** 27 June 2026
**Related Issue:** Week 3 Day 4 — Additional Threat Intelligence Providers

---

## What is GreyNoise

GreyNoise is a threat intelligence platform that tells you whether an IP
address is a mass internet scanner, bot, or a real targeted attacker.
It collects and analyzes internet-wide scan traffic to separate noise
from real threats.

In our SOAR platform, GreyNoise would help the SOC analyst quickly
decide: is this IP just a random internet scanner (low priority) or a
real attacker targeting our system (high priority)?

---

## How It Fits in Our Pipeline

```
Alert Parser
     |
     v
AbuseIPDB Check (reputation)
     |
     v
VirusTotal Check (malware scan)
     |
     v
IPInfo Check (geolocation)
     |
     v
GreyNoise Check  <-- Additional enrichment
     |
     | returns: is it a scanner? is it malicious? what is it doing?
     v
Risk Engine + Dashboard
```

---

## API Details

**Base URL:**
```
https://api.greynoise.io/v3
```

**Authentication:**
- API key passed as header
- Header name: `key`
- Free tier: Community API — 50 lookups per day

**Sign Up:**
```
https://www.greynoise.io/plans/community
```

---

## Endpoint: Community IP Lookup

**Method:** GET

**URL:**
```
https://api.greynoise.io/v3/community/<IP>
```

**Headers:**
```
key: YOUR_GREYNOISE_API_KEY
```

**Full Request Example:**
```
GET https://api.greynoise.io/v3/community/118.25.6.39
Headers: key=YOUR_KEY
```

---

## Sample Response

```json
{
  "ip": "118.25.6.39",
  "noise": true,
  "riot": false,
  "classification": "malicious",
  "name": "unknown",
  "link": "https://viz.greynoise.io/ip/118.25.6.39",
  "last_seen": "2026-06-25",
  "message": "This IP is commonly seen scanning the internet"
}
```

---

## Key Response Fields We Use

| Field | Description | Used For |
|-------|-------------|----------|
| `noise` | True if IP is a mass scanner | Filter out background noise |
| `riot` | True if IP is safe/trusted service | Whitelist check |
| `classification` | malicious / benign / unknown | Quick verdict |
| `last_seen` | Last date seen scanning | Recency check |
| `message` | Human readable summary | Analyst dashboard |

---

## Integration Plan for enricher.py

```python
import requests
import os

def check_greynoise(ip_address):
    """
    Query GreyNoise to check if IP is a mass scanner or real attacker.
    Returns noise classification context.
    """
    api_key = os.getenv("GREYNOISE_API_KEY")
    if not api_key:
        return {
            "is_noise": False,
            "is_riot": False,
            "classification": "unknown",
            "last_seen": "Unknown"
        }

    url = f"https://api.greynoise.io/v3/community/{ip_address}"
    headers = {"key": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "is_noise": False,
                "is_riot": False,
                "classification": "unknown",
                "last_seen": "Unknown"
            }

        if response.status_code != 200:
            return {
                "is_noise": False,
                "is_riot": False,
                "classification": "unknown",
                "last_seen": "Unknown"
            }

        data = response.json()
        return {
            "is_noise": data.get("noise", False),
            "is_riot": data.get("riot", False),
            "classification": data.get("classification", "unknown"),
            "last_seen": data.get("last_seen", "Unknown")
        }

    except Exception:
        return {
            "is_noise": False,
            "is_riot": False,
            "classification": "unknown",
            "last_seen": "Unknown"
        }
```

---

## Rate Limits

| Plan | Limit |
|------|-------|
| Community (Free) | 50 lookups/day |
| Pro | Unlimited |

---

## Comparison with Existing APIs

| Feature | AbuseIPDB | VirusTotal | GreyNoise |
|---------|-----------|------------|-----------|
| Purpose | Abuse reports | Malware scan | Scanner detection |
| Risk Score Input | Yes 40% | Yes 40% | No — context only |
| Identifies Scanners | No | No | Yes |
| Real vs Noise | No | No | Yes |
| Free Limit | 1000/day | 500/day | 50/day |

---

## Why GreyNoise is Useful for SOAR

If `is_noise = true` → IP is just a random internet scanner → LOW priority
If `is_noise = false` and `classification = malicious` → real attacker → HIGH priority

This helps the SOC analyst focus on real threats and ignore background noise.

---

## References

- GreyNoise Website: https://www.greynoise.io
- API Documentation: https://docs.greynoise.io
- Community Plan: https://www.greynoise.io/plans/community

---

*Infotact Solutions — SOAR Incident Containment Engine*
*Week 3 Day 4 · Threat Intelligence Lead · Yash Prashant Kulkarni*
