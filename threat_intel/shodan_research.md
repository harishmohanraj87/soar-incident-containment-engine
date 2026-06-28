# Shodan API Research

**Project:** SOAR Incident Containment Engine
**Module:** Threat Intelligence
**Author:** Yash Prashant Kulkarni
**Date:** 27 June 2026
**Related Issue:** Week 3 Day 4 — Additional Threat Intelligence Providers

---

## What is Shodan

Shodan is a search engine for internet-connected devices. Unlike Google
which indexes websites, Shodan indexes open ports, services, banners,
and vulnerabilities on any IP address or device connected to the internet.

In our SOAR platform, Shodan would be used as an additional enrichment
source to check if an attacking IP has open ports, running services, or
known vulnerabilities — giving the SOC analyst deeper technical context.

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
Shodan Check  <-- Additional enrichment
     |
     | returns open ports, services, vulnerabilities
     v
Risk Engine + Dashboard
```

---

## API Details

**Base URL:**
```
https://api.shodan.io
```

**Authentication:**
- API key passed as query parameter
- Parameter name: `key`
- Free tier: 1 API credit per lookup

**Sign Up:**
```
https://account.shodan.io/register
```

---

## Endpoint: Get IP Information

**Method:** GET

**URL:**
```
https://api.shodan.io/shodan/host/<IP>
```

**Query Parameters:**
```
key = YOUR_SHODAN_API_KEY (required)
```

**Full Request Example:**
```
GET https://api.shodan.io/shodan/host/118.25.6.39?key=YOUR_KEY
```

---

## Sample Response

```json
{
  "ip_str": "118.25.6.39",
  "country_name": "China",
  "city": "Shenzhen",
  "org": "Tencent Cloud",
  "isp": "Tencent Cloud Computing",
  "ports": [22, 80, 443, 3306],
  "vulns": ["CVE-2021-44228", "CVE-2020-1472"],
  "hostnames": ["mail.example.com"],
  "last_update": "2026-06-01T12:00:00.000Z"
}
```

---

## Key Response Fields We Use

| Field | Description | Used For |
|-------|-------------|----------|
| `ports` | List of open ports | Attack surface analysis |
| `vulns` | Known CVEs on this IP | Vulnerability context |
| `org` | Organization name | ISP identification |
| `hostnames` | Associated hostnames | Domain correlation |
| `last_update` | Last scan date | Data freshness |

---

## Integration Plan for enricher.py

```python
import requests
import os

def check_shodan(ip_address):
    """
    Query Shodan for open ports and vulnerability data.
    Returns technical attack surface context.
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {
            "open_ports": [],
            "vulnerabilities": [],
            "hostnames": []
        }

    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={api_key}"

    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 404:
            return {
                "open_ports": [],
                "vulnerabilities": [],
                "hostnames": []
            }

        if response.status_code != 200:
            return {
                "open_ports": [],
                "vulnerabilities": [],
                "hostnames": []
            }

        data = response.json()
        return {
            "open_ports": data.get("ports", []),
            "vulnerabilities": list(data.get("vulns", {}).keys()),
            "hostnames": data.get("hostnames", [])
        }

    except Exception:
        return {
            "open_ports": [],
            "vulnerabilities": [],
            "hostnames": []
        }
```

---

## Rate Limits

| Plan | Limit |
|------|-------|
| Free | 1 query credit per lookup |
| Basic ($49/mo) | 100 query credits/month |
| Small Business ($179/mo) | Unlimited |

---

## Comparison with Existing APIs

| Feature | AbuseIPDB | VirusTotal | Shodan |
|---------|-----------|------------|--------|
| Purpose | Abuse reports | Malware scan | Port/service scan |
| Risk Score Input | Yes 40% | Yes 40% | No — context only |
| Open Ports | No | No | Yes |
| CVEs/Vulns | No | No | Yes |
| Free Limit | 1000/day | 500/day | 1 credit/lookup |

---

## References

- Shodan Website: https://www.shodan.io
- API Documentation: https://developer.shodan.io/api
- Sign Up: https://account.shodan.io/register

---

*Infotact Solutions — SOAR Incident Containment Engine*
*Week 3 Day 4 · Threat Intelligence Lead · Yash Prashant Kulkarni*
