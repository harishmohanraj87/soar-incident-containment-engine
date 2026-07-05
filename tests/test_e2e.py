"""
test_e2e.py
End-to-End Integration Tests — SOAR Incident Containment Engine
Author: Yash Prashant Kulkarni
Role: Threat Intelligence Lead — Member 2
Internship: Infotact Solutions
Final Sprint Day 6: End-to-end validation testing

What this tests:
    Full pipeline simulation:
    Alert → enrich_ip() → Risk Score → Recommended Action

    Tests cover:
    1. Valid public IP enrichment flow
    2. Private IP rejection
    3. Invalid IP rejection
    4. All severity levels
    5. All alert types
    6. Output schema validation
    7. Risk level consistency
    8. Recommended action presence
    9. Partial enrichment flag
    10. Performance benchmark
"""

import unittest
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from threat_intel.enricher import enrich_ip, _validate_ip, SEVERITY_SCORE_MAP, RECOMMENDED_ACTIONS


# ─────────────────────────────────────────
# MOCK ALERT SCENARIOS
# Simulating real SOAR alerts
# ─────────────────────────────────────────

MOCK_ALERTS = [
    {
        "alert_id":   "ALT-001",
        "src_ip":     "118.25.6.39",
        "alert_type": "brute_force",
        "severity":   "high",
        "description": "Multiple failed SSH login attempts"
    },
    {
        "alert_id":   "ALT-002",
        "src_ip":     "45.33.32.156",
        "alert_type": "port_scan",
        "severity":   "medium",
        "description": "Port scanning detected on multiple ports"
    },
    {
        "alert_id":   "ALT-003",
        "src_ip":     "1.1.1.1",
        "alert_type": "dns_query",
        "severity":   "low",
        "description": "Unusual DNS query volume"
    },
    {
        "alert_id":   "ALT-004",
        "src_ip":     "8.8.8.8",
        "alert_type": "dns_lookup",
        "severity":   "info",
        "description": "DNS lookup from known IP"
    }
]

INVALID_ALERTS = [
    {"alert_id": "ALT-BAD-001", "src_ip": "192.168.1.1",     "alert_type": "scan", "severity": "high"},
    {"alert_id": "ALT-BAD-002", "src_ip": "10.0.0.1",        "alert_type": "scan", "severity": "high"},
    {"alert_id": "ALT-BAD-003", "src_ip": "127.0.0.1",       "alert_type": "scan", "severity": "high"},
    {"alert_id": "ALT-BAD-004", "src_ip": "999.999.999.999", "alert_type": "scan", "severity": "high"},
    {"alert_id": "ALT-BAD-005", "src_ip": "",                "alert_type": "scan", "severity": "high"},
    {"alert_id": "ALT-BAD-006", "src_ip": None,              "alert_type": "scan", "severity": "high"},
]

# Required fields in every enriched output
REQUIRED_OUTPUT_FIELDS = [
    "ip", "alert_type", "severity", "severity_score",
    "abuse_score", "total_reports", "whitelisted", "isp",
    "virustotal_score", "malicious_engines", "suspicious_engines", "total_engines",
    "country", "city", "region", "org", "timezone",
    "risk_score", "risk_level", "risk_factors", "recommended_action",
    "partial_enrichment", "enrichment_time_s"
]


# ─────────────────────────────────────────
# TEST CLASS 1 — IP VALIDATION
# ─────────────────────────────────────────

class TestIPValidation(unittest.TestCase):

    def test_valid_public_ip(self):
        valid, reason = _validate_ip("118.25.6.39")
        self.assertTrue(valid)

    def test_private_ip_192(self):
        valid, reason = _validate_ip("192.168.1.1")
        self.assertFalse(valid)
        self.assertIn("Private", reason)

    def test_private_ip_10(self):
        valid, reason = _validate_ip("10.0.0.1")
        self.assertFalse(valid)

    def test_private_ip_127(self):
        valid, reason = _validate_ip("127.0.0.1")
        self.assertFalse(valid)

    def test_invalid_format(self):
        valid, reason = _validate_ip("999.999.999.999")
        self.assertFalse(valid)

    def test_empty_string(self):
        valid, reason = _validate_ip("")
        self.assertFalse(valid)

    def test_none_input(self):
        valid, reason = _validate_ip(None)
        self.assertFalse(valid)

    def test_whitespace_only(self):
        valid, reason = _validate_ip("   ")
        self.assertFalse(valid)


# ─────────────────────────────────────────
# TEST CLASS 2 — INVALID ALERTS REJECTED
# ─────────────────────────────────────────

class TestInvalidAlerts(unittest.TestCase):

    def test_all_invalid_alerts_return_none(self):
        for alert in INVALID_ALERTS:
            result = enrich_ip(
                ip_address=alert["src_ip"],
                alert_type=alert["alert_type"],
                severity=alert["severity"]
            )
            self.assertIsNone(result, f"Expected None for IP: {alert['src_ip']}")


# ─────────────────────────────────────────
# TEST CLASS 3 — OUTPUT SCHEMA VALIDATION
# ─────────────────────────────────────────

class TestOutputSchema(unittest.TestCase):

    def setUp(self):
        from unittest.mock import patch, MagicMock
        self.patch = patch
        self.MagicMock = MagicMock

    def _mock_enrich(self, ip, alert_type, severity):
        from unittest.mock import patch
        from threat_intel.enricher import _default_abuseipdb, _default_virustotal, _default_ipinfo
        with patch("threat_intel.enricher.check_abuseipdb", return_value=_default_abuseipdb()), \
             patch("threat_intel.enricher.check_virustotal", return_value=_default_virustotal()), \
             patch("threat_intel.enricher.check_ipinfo", return_value=_default_ipinfo()):
            return enrich_ip(ip, alert_type, severity)

    def test_all_required_fields_present(self):
        result = self._mock_enrich("1.1.1.1", "port_scan", "medium")
        self.assertIsNotNone(result)
        for field in REQUIRED_OUTPUT_FIELDS:
            self.assertIn(field, result, f"Missing field: {field}")

    def test_risk_score_is_integer(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertIsInstance(result["risk_score"], int)

    def test_risk_score_in_range(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)

    def test_risk_level_is_valid(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertIn(result["risk_level"], ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"])

    def test_risk_factors_is_list(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertIsInstance(result["risk_factors"], list)
        self.assertGreater(len(result["risk_factors"]), 0)

    def test_recommended_action_is_string(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertIsInstance(result["recommended_action"], str)
        self.assertGreater(len(result["recommended_action"]), 0)

    def test_partial_enrichment_is_bool(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertIsInstance(result["partial_enrichment"], bool)

    def test_enrichment_time_is_float(self):
        result = self._mock_enrich("1.1.1.1", "scan", "low")
        self.assertIsInstance(result["enrichment_time_s"], float)


# ─────────────────────────────────────────
# TEST CLASS 4 — SEVERITY LEVELS
# ─────────────────────────────────────────

class TestSeverityLevels(unittest.TestCase):

    def _mock_enrich(self, severity):
        from unittest.mock import patch
        from threat_intel.enricher import _default_abuseipdb, _default_virustotal, _default_ipinfo
        with patch("threat_intel.enricher.check_abuseipdb", return_value=_default_abuseipdb()), \
             patch("threat_intel.enricher.check_virustotal", return_value=_default_virustotal()), \
             patch("threat_intel.enricher.check_ipinfo", return_value=_default_ipinfo()):
            return enrich_ip("1.1.1.1", "test", severity)

    def test_critical_severity(self):
        result = self._mock_enrich("critical")
        self.assertEqual(result["severity"], "critical")
        self.assertEqual(result["severity_score"], 100)

    def test_high_severity(self):
        result = self._mock_enrich("high")
        self.assertEqual(result["severity_score"], 75)

    def test_medium_severity(self):
        result = self._mock_enrich("medium")
        self.assertEqual(result["severity_score"], 50)

    def test_low_severity(self):
        result = self._mock_enrich("low")
        self.assertEqual(result["severity_score"], 25)

    def test_info_severity(self):
        result = self._mock_enrich("info")
        self.assertEqual(result["severity_score"], 10)

    def test_unknown_severity_defaults_to_medium(self):
        result = self._mock_enrich("invalid_severity")
        self.assertEqual(result["severity"], "medium")


# ─────────────────────────────────────────
# TEST CLASS 5 — ALERT TYPES
# ─────────────────────────────────────────

class TestAlertTypes(unittest.TestCase):

    def _mock_enrich(self, alert_type):
        from unittest.mock import patch
        from threat_intel.enricher import _default_abuseipdb, _default_virustotal, _default_ipinfo
        with patch("threat_intel.enricher.check_abuseipdb", return_value=_default_abuseipdb()), \
             patch("threat_intel.enricher.check_virustotal", return_value=_default_virustotal()), \
             patch("threat_intel.enricher.check_ipinfo", return_value=_default_ipinfo()):
            return enrich_ip("1.1.1.1", alert_type, "medium")

    def test_brute_force_alert(self):
        result = self._mock_enrich("brute_force")
        self.assertEqual(result["alert_type"], "brute_force")

    def test_port_scan_alert(self):
        result = self._mock_enrich("port_scan")
        self.assertEqual(result["alert_type"], "port_scan")

    def test_malware_alert(self):
        result = self._mock_enrich("malware")
        self.assertEqual(result["alert_type"], "malware")

    def test_none_alert_type_defaults(self):
        result = self._mock_enrich(None)
        self.assertEqual(result["alert_type"], "unknown")


# ─────────────────────────────────────────
# TEST CLASS 6 — PERFORMANCE
# ─────────────────────────────────────────

class TestPerformance(unittest.TestCase):

    def test_enrichment_completes_under_15_seconds(self):
        from unittest.mock import patch
        from threat_intel.enricher import _default_abuseipdb, _default_virustotal, _default_ipinfo
        with patch("threat_intel.enricher.check_abuseipdb", return_value=_default_abuseipdb()), \
             patch("threat_intel.enricher.check_virustotal", return_value=_default_virustotal()), \
             patch("threat_intel.enricher.check_ipinfo", return_value=_default_ipinfo()):
            start = time.time()
            result = enrich_ip("1.1.1.1", "scan", "medium")
            elapsed = time.time() - start
        self.assertLess(elapsed, 15)


# ─────────────────────────────────────────
# RUN ALL TESTS
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("SOAR Enricher — End-to-End Test Suite — Final Sprint Day 6")
    print("=" * 60)
    unittest.main(verbosity=2)
