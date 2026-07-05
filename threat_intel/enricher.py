"""
enricher.py
Threat Intelligence Module — SOAR Incident Containment Engine
Author: Yash Prashant Kulkarni
Role: Threat Intelligence Lead — Member 2
Internship: Infotact Solutions

Week 3 Day 1 Update: Improved error handling, timeouts, exception management
Week 3 Day 2 Update: Optimized API response handling — parallel API calls
Final Sprint Day 1:  Enhanced enrichment engine — full risk formula with severity
Final Sprint Day 2:  Optimized API execution — retry logic added
Final Sprint Day 3:  Improved risk scoring — bonus points, risk factors, recommended actions
Final Sprint Day 4:  Strengthened error handling — edge cases
                     - Private/reserved IP detection (192.168.x.x, 10.x.x.x, 127.x.x.x)
                     - Invalid IP format detection
                     - None/empty/whitespace IP handling
                     - API response field type validation
                     - Score out of range clamping (0-100)
                     - Partial enrichment flag if any API failed

Full Risk Formula:
    AbuseIPDB Score  x 0.40  (40%)
    VirusTotal Score x 0.40  (40%)
    Alert Severity   x 0.20  (20%)
    + Bonus points for high report count and many malicious engines
    ─────────────────────────────────────────────────────────────
    Final Risk Score = 0 to 100
"""

import re
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

TIMEOUT     = 10
MAX_RETRIES = 2
RETRY_DELAY = 1

SEVERITY_SCORE_MAP = {
    "critical": 100,
    "high":     75,
    "medium":   50,
    "low":      25,
    "info":     10
}

RECOMMENDED_ACTIONS = {
    "CRITICAL": "Auto-block IP immediately + create P1 incident + notify SOC",
    "HIGH":     "Block IP + create incident + alert SOC analyst",
    "MEDIUM":   "Flag for analyst review + monitor traffic",
    "LOW":      "Log and monitor — no immediate action needed",
    "SAFE":     "Whitelisted IP — allow traffic"
}

# Private/reserved IP prefixes — no point enriching these
PRIVATE_IP_PREFIXES = (
    "10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "0.", "255.", "169.254."
)

# Basic IPv4 pattern
IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


# ─────────────────────────────────────────
# IP VALIDATION — Day 4
# ─────────────────────────────────────────

def _validate_ip(ip_address):
    """
    Validate IP address format and check for private/reserved ranges.
    Returns: (is_valid, reason)
    """
    # Check type
    if not ip_address or not isinstance(ip_address, str):
        return False, "IP address must be a non-empty string"

    ip_address = ip_address.strip()

    # Check empty after strip
    if not ip_address:
        return False, "IP address cannot be empty or whitespace"

    # Check format
    match = IPV4_PATTERN.match(ip_address)
    if not match:
        return False, f"'{ip_address}' is not a valid IPv4 format"

    # Check each octet is 0-255
    octets = [int(match.group(i)) for i in range(1, 5)]
    for octet in octets:
        if octet > 255:
            return False, f"Invalid octet value in IP: {ip_address}"

    # Check private/reserved ranges
    for prefix in PRIVATE_IP_PREFIXES:
        if ip_address.startswith(prefix):
            return False, f"Private/reserved IP address: {ip_address}"

    return True, "Valid"


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
# SAFE VALUE HELPERS — Day 4
# ─────────────────────────────────────────

def _safe_int(value, default=0, min_val=0, max_val=100):
    """Safely convert value to int and clamp to range."""
    try:
        result = int(value)
        return max(min_val, min(max_val, result))
    except (TypeError, ValueError):
        return default

def _safe_str(value, default="Unknown"):
    """Safely convert value to string."""
    if value is None or value == "":
        return default
    return str(value).strip() or default

def _safe_bool(value, default=False):
    """Safely convert value to bool."""
    if isinstance(value, bool):
        return value
    return default


# ─────────────────────────────────────────
# 1. AbuseIPDB CHECK
# ─────────────────────────────────────────

def check_abuseipdb(ip_address):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.error("[AbuseIPDB] API key missing in .env file")
        return _default_abuseipdb()

    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params  = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = _make_request("GET", url, headers=headers, params=params)

        if response.status_code == 429:
            logger.warning("[AbuseIPDB] Rate limit hit — skipping")
            return _default_abuseipdb()
        if response.status_code != 200:
            logger.error(f"[AbuseIPDB] HTTP {response.status_code} for {ip_address}")
            return _default_abuseipdb()

        raw  = response.json()
        data = raw.get("data", {})

        if not data:
            logger.error("[AbuseIPDB] Empty data in response")
            return _default_abuseipdb()

        result = {
            "abuse_score":   _safe_int(data.get("abuseConfidenceScore"), 0, 0, 100),
            "total_reports": _safe_int(data.get("totalReports"), 0, 0, 999999),
            "country":       _safe_str(data.get("countryCode")),
            "isp":           _safe_str(data.get("isp")),
            "whitelisted":   _safe_bool(data.get("isWhitelisted"))
        }
        logger.info(f"[AbuseIPDB] Success for {ip_address} — score: {result['abuse_score']}")
        return result

    except requests.exceptions.Timeout:
        logger.error(f"[AbuseIPDB] All retries failed — timeout for {ip_address}")
        return _default_abuseipdb()
    except requests.exceptions.ConnectionError:
        logger.error("[AbuseIPDB] All retries failed — connection error")
        return _default_abuseipdb()
    except requests.exceptions.RequestException as e:
        logger.error(f"[AbuseIPDB] Request failed: {e}")
        return _default_abuseipdb()
    except (KeyError, ValueError, TypeError) as e:
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

    url     = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}

    try:
        response = _make_request("GET", url, headers=headers)

        if response.status_code == 404:
            logger.warning(f"[VirusTotal] IP {ip_address} not found")
            return _default_virustotal()
        if response.status_code == 429:
            logger.warning("[VirusTotal] Rate limit hit — skipping")
            return _default_virustotal()
        if response.status_code != 200:
            logger.error(f"[VirusTotal] HTTP {response.status_code} for {ip_address}")
            return _default_virustotal()

        raw   = response.json()
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        if not stats:
            logger.error("[VirusTotal] Empty stats in response")
            return _default_virustotal()

        malicious   = _safe_int(stats.get("malicious"), 0, 0, 999)
        suspicious  = _safe_int(stats.get("suspicious"), 0, 0, 999)
        harmless    = _safe_int(stats.get("harmless"), 0, 0, 999)
        undetected  = _safe_int(stats.get("undetected"), 0, 0, 999)
        total       = malicious + suspicious + harmless + undetected

        vt_score = 0
        if total > 0:
            vt_score = min(100, round((malicious + suspicious) / total * 100))

        logger.info(f"[VirusTotal] Success for {ip_address} — score: {vt_score}")
        return {
            "virustotal_score":   vt_score,
            "malicious_engines":  malicious,
            "suspicious_engines": suspicious,
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
    except (KeyError, ValueError, TypeError) as e:
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

        if not isinstance(data, dict):
            logger.error("[IPInfo] Unexpected response format")
            return _default_ipinfo()

        result = {
            "country":  _safe_str(data.get("country")),
            "city":     _safe_str(data.get("city")),
            "region":   _safe_str(data.get("region")),
            "org":      _safe_str(data.get("org")),
            "timezone": _safe_str(data.get("timezone"))
        }
        logger.info(f"[IPInfo] Success for {ip_address} — {result['city']}, {result['country']}")
        return result

    except requests.exceptions.Timeout:
        logger.error(f"[IPInfo] All retries failed — timeout for {ip_address}")
        return _default_ipinfo()
    except requests.exceptions.ConnectionError:
        logger.error("[IPInfo] All retries failed — connection error")
        return _default_ipinfo()
    except requests.exceptions.RequestException as e:
        logger.error(f"[IPInfo] Request failed: {e}")
        return _default_ipinfo()
    except (KeyError, ValueError, TypeError) as e:
        logger.error(f"[IPInfo] Failed to parse response: {e}")
        return _default_ipinfo()


# ─────────────────────────────────────────
# RISK SCORING
# ─────────────────────────────────────────

def _calculate_risk(abuse_data, vt_data, severity_score):
    risk_factors = []

    if abuse_data.get("whitelisted"):
        return 0, "SAFE", ["IP is whitelisted"], RECOMMENDED_ACTIONS["SAFE"]

    abuse_score = _safe_int(abuse_data.get("abuse_score"), 0, 0, 100)
    vt_score    = _safe_int(vt_data.get("virustotal_score"), 0, 0, 100)

    base_score = (
        abuse_score    * 0.40 +
        vt_score       * 0.40 +
        severity_score * 0.20
    )

    bonus = 0
    total_reports = _safe_int(abuse_data.get("total_reports"), 0, 0, 999999)
    if total_reports >= 50:
        bonus += 10
        risk_factors.append(f"High report count ({total_reports} reports)")
    elif total_reports >= 10:
        bonus += 5
        risk_factors.append(f"Multiple reports ({total_reports} reports)")

    malicious = _safe_int(vt_data.get("malicious_engines"), 0, 0, 999)
    if malicious >= 10:
        bonus += 10
        risk_factors.append(f"Flagged by {malicious} malicious engines")
    elif malicious >= 5:
        bonus += 5
        risk_factors.append(f"Flagged by {malicious} malicious engines")

    if abuse_score >= 80:
        risk_factors.append(f"Very high abuse score ({abuse_score})")
    elif abuse_score >= 50:
        risk_factors.append(f"High abuse score ({abuse_score})")

    if vt_score >= 50:
        risk_factors.append(f"High VirusTotal score ({vt_score})")

    risk_score = min(100, max(0, round(base_score + bonus)))

    if risk_score >= 90:
        risk_level = "CRITICAL"
    elif risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 45:
        risk_level = "MEDIUM"
    elif risk_score >= 20:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    if not risk_factors:
        risk_factors.append("No significant threat indicators found")

    recommended_action = RECOMMENDED_ACTIONS.get(risk_level, "Log and monitor")
    return risk_score, risk_level, risk_factors, recommended_action


# ─────────────────────────────────────────
# 4. MAIN FUNCTION
# ─────────────────────────────────────────

def enrich_ip(ip_address, alert_type="unknown", severity="medium"):
    """
    Main enrichment function with full edge case handling.

    Args:
        ip_address (str): The IP to enrich
        alert_type (str): e.g. brute_force, port_scan, malware
        severity   (str): critical, high, medium, low, info

    Returns:
        dict: Fully enriched alert or None if invalid IP
    """

    # ── EDGE CASE: IP VALIDATION ────────────
    is_valid, reason = _validate_ip(ip_address)
    if not is_valid:
        logger.error(f"[Enricher] Invalid IP — {reason}")
        return None

    ip_address = ip_address.strip()

    # ── EDGE CASE: ALERT TYPE ───────────────
    if not alert_type or not isinstance(alert_type, str):
        alert_type = "unknown"
    alert_type = alert_type.strip() or "unknown"

    # ── EDGE CASE: SEVERITY ─────────────────
    if not severity or not isinstance(severity, str):
        severity = "medium"
    severity = severity.lower().strip()
    if severity not in SEVERITY_SCORE_MAP:
        logger.warning(f"[Enricher] Unknown severity '{severity}' — defaulting to medium")
        severity = "medium"

    logger.info(f"[Enricher] Starting enrichment for {ip_address} | type={alert_type} | severity={severity}")
    start_time = time.time()

    # ── PARALLEL API CALLS ──────────────────
    results  = {}
    failures = []
    tasks    = {
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
                logger.error(f"[Enricher] {name} task failed: {e}")
                failures.append(name)
                if name == "abuse":
                    results[name] = _default_abuseipdb()
                elif name == "vt":
                    results[name] = _default_virustotal()
                else:
                    results[name] = _default_ipinfo()

    elapsed = round(time.time() - start_time, 2)

    abuse_data    = results.get("abuse",    _default_abuseipdb())
    vt_data       = results.get("vt",       _default_virustotal())
    location_data = results.get("location", _default_ipinfo())

    severity_score = SEVERITY_SCORE_MAP.get(severity, 50)

    risk_score, risk_level, risk_factors, recommended_action = _calculate_risk(
        abuse_data, vt_data, severity_score
    )

    # ── PARTIAL ENRICHMENT FLAG ─────────────
    partial_enrichment = len(failures) > 0

    logger.info(f"[Enricher] Done — risk_score: {risk_score}, risk_level: {risk_level}, time: {elapsed}s, partial: {partial_enrichment}")

    return {
        "ip":                  ip_address,
        "alert_type":          alert_type,
        "severity":            severity,
        "severity_score":      severity_score,
        "abuse_score":         abuse_data["abuse_score"],
        "total_reports":       abuse_data["total_reports"],
        "whitelisted":         abuse_data["whitelisted"],
        "isp":                 abuse_data["isp"],
        "virustotal_score":    vt_data["virustotal_score"],
        "malicious_engines":   vt_data["malicious_engines"],
        "suspicious_engines":  vt_data["suspicious_engines"],
        "total_engines":       vt_data["total_engines"],
        "country":             location_data["country"],
        "city":                location_data["city"],
        "region":              location_data["region"],
        "org":                 location_data["org"],
        "timezone":            location_data["timezone"],
        "risk_score":          risk_score,
        "risk_level":          risk_level,
        "risk_factors":        risk_factors,
        "recommended_action":  recommended_action,
        "partial_enrichment":  partial_enrichment,
        "enrichment_time_s":   elapsed
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
        # Edge cases
        {"ip": "192.168.1.1", "alert_type": "scan",        "severity": "low"},
        {"ip": "999.999.999.999", "alert_type": "scan",    "severity": "low"},
        {"ip": "",            "alert_type": "scan",        "severity": "low"},
    ]

    for case in test_cases:
        print(f"\nTesting IP: {case['ip']}")
        result = enrich_ip(
            ip_address=case["ip"],
            alert_type=case["alert_type"],
            severity=case["severity"]
        )
        if result:
            print(json.dumps(result, indent=2))
        else:
            print("Result: None (invalid IP — skipped)")
        print("─" * 50)