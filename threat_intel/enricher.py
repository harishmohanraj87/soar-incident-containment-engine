"""
enricher.py
Threat Intelligence Module — SOAR Incident Containment Engine
Author: Yash Prashant Kulkarni
Role: Threat Intelligence Lead — Member 2
Internship: Infotact Solutions

What this file does:
    Takes any IP address and checks it against 3 APIs:
    1. AbuseIPDB   — community abuse reports
    2. VirusTotal  — 70+ antivirus engine scan
    3. IPInfo      — geolocation and ISP info
    Then combines everything into one enriched result with a final risk score.
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()


# ─────────────────────────────────────────
# 1. AbuseIPDB CHECK
# ─────────────────────────────────────────

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

    if response.status_code != 200:
        print(f"[AbuseIPDB] Error {response.status_code} for {ip_address}")
        return {
            "abuse_score": 0,
            "total_reports": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "whitelisted": False
        }

    data = response.json()["data"]
    return {
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data["countryCode"],
        "isp": data["isp"],
        "whitelisted": data["isWhitelisted"]
    }


# ─────────────────────────────────────────
# 2. VIRUSTOTAL CHECK
# ─────────────────────────────────────────

def check_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": os.getenv("VIRUSTOTAL_API_KEY")
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        print(f"[VirusTotal] IP {ip_address} not found in database")
        return {
            "virustotal_score": 0,
            "malicious_engines": 0,
            "suspicious_engines": 0,
            "total_engines": 0
        }

    if response.status_code != 200:
        print(f"[VirusTotal] Error {response.status_code} for {ip_address}")
        return {
            "virustotal_score": 0,
            "malicious_engines": 0,
            "suspicious_engines": 0,
            "total_engines": 0
        }

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    total = sum(stats.values())

    if total == 0:
        vt_score = 0
    else:
        vt_score = round((stats["malicious"] + stats["suspicious"]) / total * 100)

    return {
        "virustotal_score": vt_score,
        "malicious_engines": stats["malicious"],
        "suspicious_engines": stats["suspicious"],
        "total_engines": total
    }


# ─────────────────────────────────────────
# 3. IPINFO CHECK
# ─────────────────────────────────────────

def check_ipinfo(ip_address):
    token = os.getenv("IPINFO_TOKEN")
    url = f"https://ipinfo.io/{ip_address}/json?token={token}"

    response = requests.get(url)

    if response.status_code != 200:
        print(f"[IPInfo] Error {response.status_code} for {ip_address}")
        return {
            "country": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "org": "Unknown",
            "timezone": "Unknown"
        }

    data = response.json()
    return {
        "country": data.get("country", "Unknown"),
        "city": data.get("city", "Unknown"),
        "region": data.get("region", "Unknown"),
        "org": data.get("org", "Unknown"),
        "timezone": data.get("timezone", "Unknown")
    }


# ─────────────────────────────────────────
# 4. MAIN FUNCTION — combines all 3
# ─────────────────────────────────────────

def enrich_ip(ip_address):
    print(f"\n[*] Enriching IP: {ip_address}")

    abuse_data    = check_abuseipdb(ip_address)
    vt_data       = check_virustotal(ip_address)
    location_data = check_ipinfo(ip_address)

    # Risk score formula from README:
    # AbuseIPDB 40% + VirusTotal 40% (alert severity 20% handled by backend)
    risk_score = (
        abuse_data["abuse_score"]      * 0.40 +
        vt_data["virustotal_score"]    * 0.40
    )
    risk_score = round(risk_score)

    if risk_score >= 80:
        risk_level = "HIGH"
    elif risk_score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "ip":                 ip_address,
        # AbuseIPDB fields
        "abuse_score":        abuse_data["abuse_score"],
        "total_reports":      abuse_data["total_reports"],
        "whitelisted":        abuse_data["whitelisted"],
        # VirusTotal fields
        "virustotal_score":   vt_data["virustotal_score"],
        "malicious_engines":  vt_data["malicious_engines"],
        "suspicious_engines": vt_data["suspicious_engines"],
        "total_engines":      vt_data["total_engines"],
        # IPInfo fields
        "country":            location_data["country"],
        "city":               location_data["city"],
        "region":             location_data["region"],
        "org":                location_data["org"],
        "timezone":           location_data["timezone"],
        # Final risk
        "risk_score":         risk_score,
        "risk_level":         risk_level
    }


# ─────────────────────────────────────────
# TEST — run this file directly to test
# ─────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_ips = ["118.25.6.39", "1.1.1.1"]

    for ip in test_ips:
        result = enrich_ip(ip)
        print(json.dumps(result, indent=2))
        print("─" * 50)
