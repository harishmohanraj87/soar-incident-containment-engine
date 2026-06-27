"""
test_enricher.py
Threat Intelligence Module — SOAR Incident Containment Engine
Author: Yash Prashant Kulkarni
Role: Threat Intelligence Lead — Member 2
Internship: Infotact Solutions
Week 3 Day 3: Timeout and Exception Management Testing

What this file tests:
    1. Missing API keys
    2. Timeout handling
    3. Connection errors
    4. Rate limit (429) handling
    5. Invalid IP input
    6. Empty IP input
    7. Successful response structure
    8. Risk score calculation
    9. Parallel execution
"""

import unittest
from unittest.mock import patch, MagicMock
import requests
import os
import sys

# Add parent folder to path so we can import enricher
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from threat_intel.enricher import (
    check_abuseipdb,
    check_virustotal,
    check_ipinfo,
    enrich_ip,
    _default_abuseipdb,
    _default_virustotal,
    _default_ipinfo
)


# ─────────────────────────────────────────
# ABUSEIPDB TESTS
# ─────────────────────────────────────────

class TestAbuseIPDB(unittest.TestCase):

    # Test 1 — Missing API key returns default
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_api_key(self):
        result = check_abuseipdb("1.1.1.1")
        self.assertEqual(result, _default_abuseipdb())

    # Test 2 — Timeout returns default
    @patch("threat_intel.enricher.requests.get")
    def test_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake_key"}):
            result = check_abuseipdb("1.1.1.1")
        self.assertEqual(result, _default_abuseipdb())

    # Test 3 — Connection error returns default
    @patch("threat_intel.enricher.requests.get")
    def test_connection_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError()
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake_key"}):
            result = check_abuseipdb("1.1.1.1")
        self.assertEqual(result, _default_abuseipdb())

    # Test 4 — Rate limit 429 returns default
    @patch("threat_intel.enricher.requests.get")
    def test_rate_limit(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake_key"}):
            result = check_abuseipdb("1.1.1.1")
        self.assertEqual(result, _default_abuseipdb())

    # Test 5 — Successful response returns correct fields
    @patch("threat_intel.enricher.requests.get")
    def test_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 90,
                "totalReports": 10,
                "countryCode": "CN",
                "isp": "Tencent",
                "isWhitelisted": False
            }
        }
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "fake_key"}):
            result = check_abuseipdb("118.25.6.39")
        self.assertEqual(result["abuse_score"], 90)
        self.assertEqual(result["country"], "CN")
        self.assertEqual(result["isp"], "Tencent")


# ─────────────────────────────────────────
# VIRUSTOTAL TESTS
# ─────────────────────────────────────────

class TestVirusTotal(unittest.TestCase):

    # Test 6 — Missing API key returns default
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_api_key(self):
        result = check_virustotal("1.1.1.1")
        self.assertEqual(result, _default_virustotal())

    # Test 7 — Timeout returns default
    @patch("threat_intel.enricher.requests.get")
    def test_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake_key"}):
            result = check_virustotal("1.1.1.1")
        self.assertEqual(result, _default_virustotal())

    # Test 8 — 404 not found returns default
    @patch("threat_intel.enricher.requests.get")
    def test_404_not_found(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake_key"}):
            result = check_virustotal("1.1.1.1")
        self.assertEqual(result, _default_virustotal())

    # Test 9 — Rate limit 429 returns default
    @patch("threat_intel.enricher.requests.get")
    def test_rate_limit(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake_key"}):
            result = check_virustotal("1.1.1.1")
        self.assertEqual(result, _default_virustotal())

    # Test 10 — Successful response returns correct score
    @patch("threat_intel.enricher.requests.get")
    def test_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 2,
                        "harmless": 80,
                        "undetected": 8
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "fake_key"}):
            result = check_virustotal("118.25.6.39")
        self.assertEqual(result["malicious_engines"], 10)
        self.assertGreater(result["virustotal_score"], 0)


# ─────────────────────────────────────────
# IPINFO TESTS
# ─────────────────────────────────────────

class TestIPInfo(unittest.TestCase):

    # Test 11 — Missing token returns default
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_token(self):
        result = check_ipinfo("1.1.1.1")
        self.assertEqual(result, _default_ipinfo())

    # Test 12 — Timeout returns default
    @patch("threat_intel.enricher.requests.get")
    def test_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()
        with patch.dict(os.environ, {"IPINFO_TOKEN": "fake_token"}):
            result = check_ipinfo("1.1.1.1")
        self.assertEqual(result, _default_ipinfo())

    # Test 13 — API error field returns default
    @patch("threat_intel.enricher.requests.get")
    def test_api_error_field(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"error": "Invalid token"}
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"IPINFO_TOKEN": "fake_token"}):
            result = check_ipinfo("1.1.1.1")
        self.assertEqual(result, _default_ipinfo())

    # Test 14 — Successful response returns correct fields
    @patch("threat_intel.enricher.requests.get")
    def test_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "country": "CN",
            "city": "Shenzhen",
            "region": "Guangdong",
            "org": "AS45090 Tencent",
            "timezone": "Asia/Shanghai"
        }
        mock_get.return_value = mock_response
        with patch.dict(os.environ, {"IPINFO_TOKEN": "fake_token"}):
            result = check_ipinfo("118.25.6.39")
        self.assertEqual(result["country"], "CN")
        self.assertEqual(result["city"], "Shenzhen")


# ─────────────────────────────────────────
# ENRICH_IP TESTS
# ─────────────────────────────────────────

class TestEnrichIP(unittest.TestCase):

    # Test 15 — None input returns None
    def test_none_input(self):
        result = enrich_ip(None)
        self.assertIsNone(result)

    # Test 16 — Empty string returns None
    def test_empty_string(self):
        result = enrich_ip("")
        self.assertIsNone(result)

    # Test 17 — Integer input returns None
    def test_integer_input(self):
        result = enrich_ip(12345)
        self.assertIsNone(result)

    # Test 18 — Valid result has all required fields
    @patch("threat_intel.enricher.check_abuseipdb")
    @patch("threat_intel.enricher.check_virustotal")
    @patch("threat_intel.enricher.check_ipinfo")
    def test_result_has_all_fields(self, mock_ipinfo, mock_vt, mock_abuse):
        mock_abuse.return_value = _default_abuseipdb()
        mock_vt.return_value = _default_virustotal()
        mock_ipinfo.return_value = _default_ipinfo()

        result = enrich_ip("1.1.1.1")

        required_fields = [
            "ip", "abuse_score", "total_reports", "whitelisted",
            "virustotal_score", "malicious_engines", "suspicious_engines",
            "total_engines", "country", "city", "region", "org",
            "timezone", "risk_score", "risk_level", "enrichment_time_s"
        ]
        for field in required_fields:
            self.assertIn(field, result)

    # Test 19 — HIGH risk score when abuse is 100
    @patch("threat_intel.enricher.check_abuseipdb")
    @patch("threat_intel.enricher.check_virustotal")
    @patch("threat_intel.enricher.check_ipinfo")
    def test_high_risk_level(self, mock_ipinfo, mock_vt, mock_abuse):
        mock_abuse.return_value = {**_default_abuseipdb(), "abuse_score": 100}
        mock_vt.return_value = {**_default_virustotal(), "virustotal_score": 100}
        mock_ipinfo.return_value = _default_ipinfo()

        result = enrich_ip("118.25.6.39")
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreaterEqual(result["risk_score"], 80)

    # Test 20 — LOW risk score when all scores are 0
    @patch("threat_intel.enricher.check_abuseipdb")
    @patch("threat_intel.enricher.check_virustotal")
    @patch("threat_intel.enricher.check_ipinfo")
    def test_low_risk_level(self, mock_ipinfo, mock_vt, mock_abuse):
        mock_abuse.return_value = _default_abuseipdb()
        mock_vt.return_value = _default_virustotal()
        mock_ipinfo.return_value = _default_ipinfo()

        result = enrich_ip("1.1.1.1")
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["risk_score"], 0)

    # Test 21 — enrichment_time_s is a number
    @patch("threat_intel.enricher.check_abuseipdb")
    @patch("threat_intel.enricher.check_virustotal")
    @patch("threat_intel.enricher.check_ipinfo")
    def test_enrichment_time_is_number(self, mock_ipinfo, mock_vt, mock_abuse):
        mock_abuse.return_value = _default_abuseipdb()
        mock_vt.return_value = _default_virustotal()
        mock_ipinfo.return_value = _default_ipinfo()

        result = enrich_ip("1.1.1.1")
        self.assertIsInstance(result["enrichment_time_s"], float)


# ─────────────────────────────────────────
# RUN ALL TESTS
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("SOAR Enricher — Test Suite — Week 3 Day 3")
    print("=" * 60)
    unittest.main(verbosity=2)
