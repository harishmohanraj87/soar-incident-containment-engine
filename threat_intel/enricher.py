"""
enricher.py
Threat Intelligence Module — SOAR Incident Containment Engine
Author: Yash Prashant Kulkarni
Role: Threat Intelligence Lead — Member 2
Internship: Infotact Solutions

Week 3 Day 1 Update: Improved error handling, timeouts, exception management
Week 3 Day 2 Update: Optimized API response handling — parallel API calls
                     All 3 APIs now run at the same time (3x faster)
Final Sprint Day 1:  Enhanced enrichment engine — full risk formula with severity
Final Sprint Day 2:  Optimized API execution — retry logic added
                     - All 3 APIs retry up to 2 times before giving up
                     - 1 second wait between retries
                     - Retry on timeout and connection errors only
                     - No retry on 429 rate limit or 404 not found

What this file does:
    Takes any IP address + alert context and checks it against 3 APIs:
    1. AbuseIPDB   — community abuse reports
    2. VirusTotal  — 70+ antivirus engine scan
    3. IPInfo      — geolocation and ISP info
    Then combines everything into one enriched result with a final risk score.

Full Risk Formula:
    AbuseIPDB Score  x 0.40  (40%)
    VirusTotal Score x 0.40  (40%)
    Alert Severity   x 0.20  (20%)
    ─────────────────────────────
    Final Risk Score = 0 to 100
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

TIMEOUT     = 10  # seconds per API call
MAX_RETRIES = 2   # retry up to 2 times before giving up
RETRY_DELAY = 1   # wait 1 second between retries

# Alert severity mapping — used for 20% weight in risk score
SEVERITY_SCORE_MAP = {
    "critical": 100,
    "high":     75,
    "medium":   50,
    "low":      25,
    "info":     10
}


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
# RETRY HELPER
# ─────────────────────────────────────────

def _make_request(method, url, **kwargs):
    """
    Make an HTTP request with retry logic.
    Retries up to MAX_RETRIES times on timeout or connection errors.
    Does NOT retry on 429 or 404.
    """
    for attempt in range(1, MAX_RETRIES + 2):
        try:
            response = requests.request(method, url, timeout=TIMEOUT, **kwargs)
            return response

        except requests.exceptions.Timeout:
            if attempt <= MAX_RETRIES:
                logger.warning(f"Timeout on attempt {attempt} — retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                logger.error(f"Timeout after {MAX_RETRIES + 1} attempts — giving up")
                raise

        except requests.exceptions.ConnectionError:
            if attempt <= MAX_RETRIES:
                logger.warning(f"Connection error on attempt {attempt} — retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                logger.error(f"Connection error after {MAX_RETRIES + 1} attempts — giving up")
                raise


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
        response = _make_request("GET", url, headers=headers, params=params)

        if response.status_code == 429:
            logger.warning("[AbuseIPDB] Rate limit hit — skipping")
            return _default_abuseipdb()

        if response.status_code != 200:
            logger.error(f"[AbuseIPDB] HTTP {response.status_code} for {ip_address}")
            return _default_abuseipdb()

        data = response.json()["data"]
        logger.info(f"[AbuseIPDB] Success for {ip_address} — score: {data['abuseConfidenceScore']}")
        return {
            "abuse_score":   data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country":       data.get("countryCode", "Unknown"),
            "isp":           data.get("isp", "Unknown"),
            "whitelisted":   data.get("isWhitelisted", False)
        }

    except requests.exceptions.Timeout:
        logger.error(f"[AbuseIPDB] All retries failed — timeout for {ip_address}")
        return _default_abuseipdb()

    except requests.exceptions.ConnectionError:
        logger.error("[AbuseIPDB] All retries failed — connection error")
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
        response = _make_request("GET", url, headers=headers)

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
            "virustotal_score":   vt_score,
            "malicious_engines":  stats.get("malicious", 0),
            "suspicious_engines": stats.get("suspicious", 0),
            "total_engines":      total
        }

    except requests.exceptions.Timeout:
        logger.error(f"[VirusTotal] All retries failed — timeout for {ip_address}")
        return _default_virustotal()

    except requests.exceptions.ConnectionError:
        logger.error("[VirusTotal] All retries failed — connection error")
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
        response = _make_request("GET", url)

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
            "country":  data.get("country", "Unknown"),
            "city":     data.get("city", "Unknown"),
            "region":   data.get("region", "Unknown"),
            "org":      data.get("org", "Unknown"),
            "timezone": data.get("timezone", "Unknown")
        }

    except requests.exceptions.Timeout:
        logger.error(f"[IPInfo] All retries failed — timeout for {ip_address}")
        return _default_ipinfo()

    except requests.exceptions.ConnectionError:
        logger.error("[IPInfo] All retries failed — connection error")
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

def enrich_ip(ip_address, alert_type="unknown", severity="medium"):
    """
    Main enrichment function.

    Args:
        ip_address (str): The IP address to enrich
        alert_type (str): Type of alert e.g. brute_force, port_scan, malware
        severity   (str): Alert severity — critical, high, medium, low, info

    Returns:
        dict: Fully enriched alert with risk score and risk level
    """

    # Basic validation
    if not ip_address or not isinstance(ip_address, str):
        logger.error("[Enricher] Invalid IP address provided")
        return None

    ip_address = ip_address.strip()
    if not ip_address:
        logger.error("[Enricher] Empty IP address provided")
        return None

    # Normalize severity
    severity = severity.lower().strip()
    if severity not in SEVERITY_SCORE_MAP:
        logger.warning(f"[Enricher] Unknown severity '{severity}' — defaulting to medium")
        severity = "medium"

    logger.info(f"[Enricher] Starting enrichment for {ip_address} | type={alert_type} | severity={severity}")
    start_time = time.time()

    # ── PARALLEL API CALLS ──────────────────
    # Run all 3 APIs at the same time — 3x faster
    # Each API has retry logic built in
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

    # ── FULL RISK SCORE FORMULA ─────────────
    # AbuseIPDB 40% + VirusTotal 40% + Severity 20%
    # ────────────────────────────────────────
    severity_score = SEVERITY_SCORE_MAP.get(severity, 50)

    risk_score = (
        abuse_data["abuse_score"]   * 0.40 +
        vt_data["virustotal_score"] * 0.40 +
        severity_score              * 0.20
    )
    risk_score = round(risk_score)

    if risk_score >= 80:
        risk_level = "HIGH"
    elif risk_score >= 50:
        risk_level = "MEDIUM"
    elif risk_score >= 25:
        risk_level = "LOW"
    else:
        risk_level = "INFO"

    logger.info(f"[Enricher] Done — risk_score: {risk_score}, risk_level: {risk_level}, time: {elapsed}s")

    return {
        "ip":                 ip_address,
        "alert_type":         alert_type,
        "severity":           severity,
        "severity_score":     severity_score,
        "abuse_score":        abuse_data["abuse_score"],
        "total_reports":      abuse_data["total_reports"],
        "whitelisted":        abuse_data["whitelisted"],
        "isp":                abuse_data["isp"],
        "virustotal_score":   vt_data["virustotal_score"],
        "malicious_engines":  vt_data["malicious_engines"],
        "suspicious_engines": vt_data["suspicious_engines"],
        "total_engines":      vt_data["total_engines"],
        "country":            location_data["country"],
        "city":               location_data["city"],
        "region":             location_data["region"],
        "org":                location_data["org"],
        "timezone":           location_data["timezone"],
        "risk_score":         risk_score,
        "risk_level":         risk_level,
        "enrichment_time_s":  elapsed
    }


# ─────────────────────────────────────────
# TEST
# ─────────────────────────────────────────

if __name__ == "__main__":
    import json

    test_cases = [
        {"ip": "118.25.6.39", "alert_type": "brute_force", "severity": "high"},
        {"ip": "1.1.1.1",     "alert_type": "port_scan",   "severity": "low"},
        {"ip": "8.8.8.8",     "alert_type": "dns_query",   "severity": "info"},
    ]

    for case in test_cases:
        result = enrich_ip(
            ip_address=case["ip"],
            alert_type=case["alert_type"],
            severity=case["severity"]
        )
        print(json.dumps(result, indent=2))
        print("─" * 50)