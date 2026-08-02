"""
Wazuh Alert Mapper

Converts a parsed Wazuh alert into the standard
SOAR alert schema used throughout the application.
"""

from wazuh.models import WazuhAlert


def map_to_soar(alert: WazuhAlert) -> dict:
    """
    Convert WazuhAlert into the SOAR alert format.
    """

    # -------------------------
    # Determine Alert Type
    # -------------------------

    description = alert.rule_description.lower()

    if "authentication" in description or "brute" in description:
        alert_type = "Brute Force"

    elif "malware" in description:
        alert_type = "Malware"

    elif "file integrity" in description:
        alert_type = "File Integrity"

    elif "powershell" in description:
        alert_type = "Suspicious PowerShell"

    else:
        alert_type = "Security Alert"

    # -------------------------
    # Determine Severity
    # -------------------------

    if alert.rule_level >= 12:
        severity = "CRITICAL"

    elif alert.rule_level >= 8:
        severity = "HIGH"

    elif alert.rule_level >= 5:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    # -------------------------
    # Return SOAR Alert
    # -------------------------

    return {

        "alert_id": f"WAZUH-{alert.rule_id}-{alert.agent_id}",

        "alert_type": alert_type,

        "severity": severity,

        "source_ip": alert.agent_ip,

        "attacker_ip": alert.attacker_ip,

        "description": alert.rule_description,

        "timestamp": alert.timestamp

    }