"""
enricher.py
Threat Intelligence Module — SOAR Incident Containment Engine
Author: Yash Prashant Kulkarni
Role: Threat Intelligence Lead — Member 2
Internship: Infotact Solutions

Week 3 Day 1 Update: Improved error handling, timeouts, exception management
Week 3 Day 2 Update: Optimized API response handling — parallel API calls
                     All 3 APIs now run at the same time (3x faster)

What this file does:
    Takes any IP address and checks it against 3 APIs:
    1. AbuseIPDB   — community abuse reports
    2. VirusTotal  — 70+ antivirus engine scan
    3. IPInfo      — geolocation and ISP info
    Then combines everything into one enriched result with a final risk score.
"""

import requests
import os
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────

TIMEOUT = 10  # seconds — all API calls will fail after this


# ─────────────────────────────────────────
# DEFAULT RESPONSES
# ─────────────────────────────────────────

def _default_abuseipdb():
    return {
        "abuse_score": 0,
        "total_reports": 0,
        "country": "Unknown",
        "isp": "Unknown",
        "whitelisted": False
    }

def _default_virustotal():
    return {
        "virustotal_score": 0,
        "malicious_engines": 0,
        "suspicious_engines": 0,
        "total_engines": 0
    }

def _default_ipinfo():
    return {
        "country": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "org": "Unknown",
        "timezone": "Unknown"
    }


# ─────────────────────────────────────────
# 1. AbuseIPDB CHECK
# ─────────────────────────────────────────

def check_abuseipdb(ip_address):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.error("[AbuseIPDB] API key missing in .env file")
        return _default_abuseipdb()

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)

        if response.status_code == 429:
            logger.warning("[AbuseIPDB] Rate limit hit — skipping")
            return _default_abuseipdb()

        if response.status_code != 200:
            logger.error(f"[AbuseIPDB] HTTP {response.status_code} for {ip_address}")
            return _default_abuseipdb()

        data = response.json()["data"]
        logger.info(f"[AbuseIPDB] Success for {ip_address} — score: {data['abuseConfidenceScore']}")
        return {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "whitelisted": data.get("isWhitelisted", False)
        }

    except requests.exceptions.Timeout:
        logger.error(f"[AbuseIPDB] Timeout after {TIMEOUT}s for {ip_address}")
        return _default_abuseipdb()

    except requests.exceptions.ConnectionError:
        logger.error("[AbuseIPDB] Connection error — no internet or API is down")
        return _default_abuseipdb()

    except requests.exceptions.RequestException as e:
        logger.error(f"[AbuseIPDB] Request failed: {e}")
        return _default_abuseipdb()

    except (KeyError, ValueError) as e:
        logger.error(f"[AbuseIPDB] Failed to parse response: {e}")
        return _default_abuseipdb()


# ─────────────────────────────────────────
# 2. VIRUSTOTAL CHECK
# ─────────────────────────────────────────

def check_virustotal(ip_address):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.error("[VirusTotal] API key missing in .env file")
        return _default_virustotal()

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)

        if response.status_code == 404:
            logger.warning(f"[VirusTotal] IP {ip_address} not found in database")
            return _default_virustotal()

        if response.status_code == 429:
            logger.warning("[VirusTotal] Rate limit hit — skipping")
            return _default_virustotal()

        if response.status_code != 200:
            logger.error(f"[VirusTotal] HTTP {response.status_code} for {ip_address}")
            return _default_virustotal()

        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        total = sum(stats.values())

        vt_score = 0
        if total > 0:
            vt_score = round((stats["malicious"] + stats["suspicious"]) / total * 100)

        logger.info(f"[VirusTotal] Success for {ip_address} — score: {vt_score}")
        return {
            "virustotal_score": vt_score,
            "malicious_engines": stats.get("malicious", 0),
            "suspicious_engines": stats.get("suspicious", 0),
            "total_engines": total
        }

    except requests.exceptions.Timeout:
        logger.error(f"[VirusTotal] Timeout after {TIMEOUT}s for {ip_address}")
        return _default_virustotal()

    except requests.exceptions.ConnectionError:
        logger.error("[VirusTotal] Connection error — no internet or API is down")
        return _default_virustotal()

    except requests.exceptions.RequestException as e:
        logger.error(f"[VirusTotal] Request failed: {e}")
        return _default_virustotal()

    except (KeyError, ValueError) as e:
        logger.error(f"[VirusTotal] Failed to parse response: {e}")
        return _default_virustotal()


# ─────────────────────────────────────────
# 3. IPINFO CHECK
# ─────────────────────────────────────────

def check_ipinfo(ip_address):
    token = os.getenv("IPINFO_TOKEN")
    if not token:
        logger.error("[IPInfo] Token missing in .env file")
        return _default_ipinfo()

    url = f"https://ipinfo.io/{ip_address}/json?token={token}"

    try:
        response = requests.get(url, timeout=TIMEOUT)

        if response.status_code == 429:
            logger.warning("[IPInfo] Rate limit hit — skipping")
            return _default_ipinfo()

        if response.status_code != 200:
            logger.error(f"[IPInfo] HTTP {response.status_code} for {ip_address}")
            return _default_ipinfo()

        data = response.json()

        if "error" in data:
            logger.error(f"[IPInfo] API error: {data['error']}")
            return _default_ipinfo()

        logger.info(f"[IPInfo] Success for {ip_address} — {data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}")
        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "org": data.get("org", "Unknown"),
            "timezone": data.get("timezone", "Unknown")
        }

    except requests.exceptions.Timeout:
        logger.error(f"[IPInfo] Timeout after {TIMEOUT}s for {ip_address}")
        return _default_ipinfo()

    except requests.exceptions.ConnectionError:
        logger.error("[IPInfo] Connection error — no internet or API is down")
        return _default_ipinfo()

    except requests.exceptions.RequestException as e:
        logger.error(f"[IPInfo] Request failed: {e}")
        return _default_ipinfo()

    except (KeyError, ValueError) as e:
        logger.error(f"[IPInfo] Failed to parse response: {e}")
        return _default_ipinfo()


# ─────────────────────────────────────────
# 4. MAIN FUNCTION — runs all 3 in parallel
# ─────────────────────────────────────────

def enrich_ip(ip_address):
    # Basic validation
    if not ip_address or not isinstance(ip_address, str):
        logger.error("[Enricher] Invalid IP address provided")
        return None

    ip_address = ip_address.strip()
    if not ip_address:
        logger.error("[Enricher] Empty IP address provided")
        return None

    logger.info(f"[Enricher] Starting enrichment for {ip_address}")
    start_time = time.time()

    # ── DAY 2 OPTIMIZATION ──────────────────
    # Run all 3 API calls at the same time
    # instead of one by one — 3x faster
    # ────────────────────────────────────────
    results = {}

    tasks = {
        "abuse":    check_abuseipdb,
        "vt":       check_virustotal,
        "location": check_ipinfo
    }

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(fn, ip_address): name
            for name, fn in tasks.items()
        }

        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                logger.error(f"[Enricher] {name} task failed unexpectedly: {e}")
                if name == "abuse":
                    results[name] = _default_abuseipdb()
                elif name == "vt":
                    results[name] = _default_virustotal()
                else:
                    results[name] = _default_ipinfo()

    elapsed = round(time.time() - start_time, 2)
    logger.info(f"[Enricher] All 3 APIs completed in {elapsed}s")

    abuse_data    = results.get("abuse",    _default_abuseipdb())
    vt_data       = results.get("vt",       _default_virustotal())
    location_data = results.get("location", _default_ipinfo())

    # Risk score formula:
    # AbuseIPDB 40% + VirusTotal 40%
    # (alert severity 20% handled by backend)
    risk_score = (
        abuse_data["abuse_score"]   * 0.40 +
        vt_data["virustotal_score"] * 0.40
    )
    risk_score = round(risk_score)

    if risk_score >= 80:
        risk_level = "HIGH"
    elif risk_score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    logger.info(f"[Enricher] Done — risk_score: {risk_score}, risk_level: {risk_level}, time: {elapsed}s")

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
        "risk_level":         risk_level,
        "enrichment_time_s":  elapsed
    }


# ─────────────────────────────────────────
# TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_ips = ["118.25.6.39", "1.1.1.1"]

    for ip in test_ips:
        result = enrich_ip(ip)
        print(json.dumps(result, indent=2))
        print("─" * 50)
