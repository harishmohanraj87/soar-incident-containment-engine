# Simulator Testing & Workflow Validation Guide

## Overview
This document outlines the testing procedures for the Incident Containment Engine. The goal is to validate that the system correctly ingests alerts, successfully applies threat intelligence enrichment, and triggers the appropriate automated response workflows.

## 1. Alert Ingestion Testing
To verify the parser correctly reads standardized JSON data:
1. Navigate to the `tests/sample_alerts/` directory.
2. Select an alert scenario (e.g., `alert_phishing_01.json`).
3. Feed the JSON file into the alert parser script.
4. **Validation:** Ensure the parser successfully extracts the `alert_id`, `severity`, and `alert_type` without throwing schema errors.

## 2. Enrichment Validation
To test the threat intelligence lookups, use the dedicated enrichment test cases:
* **Run `alert_enrichment_malicious_01.json`:** 
  * **Expected Workflow:** The system must flag the IP as malicious and escalate the alert severity.
* **Run `alert_enrichment_safe_01.json`:**
  * **Expected Workflow:** The system must recognize the internal IT scanner IP and automatically close/suppress the alert as a false positive.

## 3. Playbook Workflow Validation
To ensure automated responses trigger correctly based on alert types:
* **High/Critical Malware Alerts:** Verify the workflow initiates "Workstation Isolation."
* **Phishing Alerts:** Verify the workflow initiates a "Credential Reset" prompt.
* **Low/Medium Port Scans:** Verify the workflow logs the event without triggering active containment.

---
*Note: Ensure all new alert templates follow the JSON schema defined in `tests/sample_alerts/README.md`.*