# Sample SIEM Alerts

## Purpose
This directory contains sample JSON files used to test the Incident Containment Engine simulator. These files represent fake security alerts (like Brute Force, Malware, and Port Scans) so we can safely test the automated response playbooks without needing a live SIEM connection.

## File Format
All alerts in this folder must follow standard JSON formatting and include the following key fields:
* `alert_id`: A unique identifier (e.g., ALT-90210)
* `timestamp`: ISO 8601 format
* `alert_type`: The category of the attack
* `severity`: Low, Medium, High, or Critical
* `source_ip` / `attacker_ip`: Relevant IP addresses
* `status`: Typically set to "New"

## How to Add a New Alert
I wanted to maintain strict formatting consistency, so I copied the structure and tweaked the payloads.