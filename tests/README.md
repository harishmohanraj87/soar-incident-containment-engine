# Sample SIEM Alerts

## Purpose

This directory contains sample JSON alert files used to test the SOAR Incident Containment Engine. The alerts simulate common cybersecurity incidents without requiring a live SIEM or production environment.

These datasets allow developers to validate alert parsing, threat enrichment, automated playbook execution, and audit logging in a safe and repeatable manner.

---

# Supported Alert Types

The current dataset includes the following simulated attack scenarios:

| Alert Type        | Description                                                      |
| ----------------- | ---------------------------------------------------------------- |
| Brute Force       | Multiple failed authentication attempts from a single IP address |
| Malware Detection | Detection of malicious software on a host                        |
| Port Scan         | Multiple connection attempts against different ports             |
| Phishing          | Suspicious email containing malicious links or attachments       |
| Ransomware        | Encryption activity detected on an endpoint                      |
| Suspicious Login  | Login from an unusual location or device                         |

---

# JSON Format

Every alert file must follow a standardized JSON structure.

Required fields:

| Field      | Description                    |
| ---------- | ------------------------------ |
| alert_id   | Unique alert identifier        |
| timestamp  | ISO 8601 UTC timestamp         |
| alert_type | Type of security event         |
| severity   | Low, Medium, High, or Critical |
| source_ip  | Source IP address              |
| status     | Initial alert status           |

Example:

```json
{
    "alert_id": "ALT-1001",
    "timestamp": "2026-07-09T10:30:00Z",
    "alert_type": "Brute Force",
    "severity": "High",
    "source_ip": "192.168.1.50",
    "status": "New"
}
```

---

# Testing Workflow

Each sample alert should pass through the following workflow:

1. Load JSON alert
2. Validate JSON structure
3. Parse alert fields
4. Extract Indicators of Compromise (IoCs)
5. Execute threat enrichment
6. Calculate risk score
7. Trigger automated playbook
8. Record audit log
9. Update incident timeline

---

# Validation Checklist

Verify the following during testing:

* JSON file is valid
* Required fields are present
* Alert parser extracts all values correctly
* Threat enrichment completes successfully
* Risk score is generated
* Playbook executes without errors
* Audit event is recorded
* Incident timeline is updated

---

# Adding New Alert Scenarios

To maintain consistency when adding new alerts:

* Follow the existing JSON structure
* Use unique `alert_id` values
* Store timestamps in ISO 8601 UTC format
* Assign an appropriate severity level
* Include realistic but non-production data
* Validate the JSON before committing

---

# Expected Outcome

Every sample alert should successfully complete the SOAR processing pipeline without parsing errors. Test results should confirm that the parser, enrichment workflow, playbook execution, and audit logging components operate as expected.

This testing dataset helps ensure consistent and reliable validation of the Incident Containment Engine before deployment.
