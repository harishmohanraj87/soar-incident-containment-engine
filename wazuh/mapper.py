"""
Wazuh Alert Mapper

Converts a parsed Wazuh alert into the standard
SOAR alert schema used throughout the application.

Responsibilities:

    WazuhAlert
        ↓
    Classification
        ↓
    Severity
        ↓
    Unique Alert ID
        ↓
    Standard SOAR Alert
"""


import hashlib

from wazuh.models import WazuhAlert


# ==========================================================
# HELPERS
# ==========================================================

def _clean(value):
    """
    Convert a value into a clean string.

    Returns an empty string for None or missing values.
    """

    if value is None:
        return ""

    return str(value).strip()


# ==========================================================
# ALERT TYPE CLASSIFICATION
# ==========================================================

def _determine_alert_type(description: str) -> str:
    """
    Determine the SOAR alert type from the Wazuh
    rule description.
    """

    text = description.lower()

    # ------------------------------------------------------
    # Brute Force / Authentication
    # ------------------------------------------------------

    brute_force_keywords = [
        "brute force",
        "bruteforce",
        "authentication failure",
        "authentication failed",
        "failed authentication",
        "login failure",
        "login failed",
        "multiple failed login",
        "password attack",
        "credential attack",
    ]

    if any(
        keyword in text
        for keyword in brute_force_keywords
    ):
        return "Brute Force"

    # ------------------------------------------------------
    # Malware
    # ------------------------------------------------------

    malware_keywords = [
        "malware",
        "trojan",
        "ransomware",
        "virus",
        "rootkit",
        "backdoor",
    ]

    if any(
        keyword in text
        for keyword in malware_keywords
    ):
        return "Malware"

    # ------------------------------------------------------
    # File Integrity
    # ------------------------------------------------------

    file_integrity_keywords = [
        "file integrity",
        "file modified",
        "file changed",
        "file added",
        "file deleted",
        "fim",
    ]

    if any(
        keyword in text
        for keyword in file_integrity_keywords
    ):
        return "File Integrity"

    # ------------------------------------------------------
    # PowerShell
    # ------------------------------------------------------

    powershell_keywords = [
        "powershell",
        "pwsh",
    ]

    if any(
        keyword in text
        for keyword in powershell_keywords
    ):
        return "Suspicious PowerShell"

    # ------------------------------------------------------
    # Command Execution
    # ------------------------------------------------------

    command_keywords = [
        "command execution",
        "command executed",
        "shell execution",
        "process execution",
    ]

    if any(
        keyword in text
        for keyword in command_keywords
    ):
        return "Command Execution"

    # ------------------------------------------------------
    # Network Attack
    # ------------------------------------------------------

    network_keywords = [
        "port scan",
        "port scanning",
        "network scan",
        "scan detected",
        "intrusion attempt",
        "network attack",
        "suspicious inbound connection",
        "inbound connection",
    ]

    if any(
        keyword in text
        for keyword in network_keywords
    ):
        return "Network Attack"

    return "Security Alert"


# ==========================================================
# SEVERITY
# ==========================================================

def _determine_severity(rule_level: int) -> str:
    """
    Convert Wazuh rule level into SOAR severity.
    """

    try:
        level = int(rule_level)

    except (TypeError, ValueError):

        level = 0

    if level >= 12:
        return "CRITICAL"

    if level >= 8:
        return "HIGH"

    if level >= 5:
        return "MEDIUM"

    return "LOW"


# ==========================================================
# UNIQUE ALERT ID
# ==========================================================

def _generate_alert_id(
    rule_id: str,
    agent_id: str,
    timestamp: str,
    attacker_ip: str,
    full_log: str
) -> str:
    """
    Generate a deterministic unique Wazuh alert ID.

    The ID is based on the actual event rather than only
    the Wazuh rule and agent.

    This prevents different alerts from being incorrectly
    treated as duplicates.

    If Wazuh retries the exact same event, the generated ID
    remains identical, allowing duplicate protection.
    """

    event_data = "|".join([
        rule_id,
        agent_id,
        timestamp,
        attacker_ip,
        full_log,
    ])

    event_hash = hashlib.sha256(
        event_data.encode("utf-8")
    ).hexdigest()[:12]

    return (
        f"WAZUH-"
        f"{rule_id or 'UNKNOWN'}-"
        f"{agent_id or 'UNKNOWN'}-"
        f"{event_hash}"
    )


# ==========================================================
# WAZUH → SOAR MAPPER
# ==========================================================

def map_to_soar(alert: WazuhAlert) -> dict:
    """
    Convert a parsed WazuhAlert into the standard
    SOAR alert dictionary.

    The returned dictionary is compatible with the
    existing SOAR alert-processing pipeline.
    """

    # ------------------------------------------------------
    # CLEAN INPUT
    # ------------------------------------------------------

    rule_id = _clean(
        alert.rule_id
    )

    agent_id = _clean(
        alert.agent_id
    )

    agent_name = _clean(
        alert.agent_name
    )

    agent_ip = _clean(
        alert.agent_ip
    )

    attacker_ip = _clean(
        alert.attacker_ip
    )

    timestamp = _clean(
        alert.timestamp
    )

    description = _clean(
        alert.rule_description
    )

    full_log = _clean(
        alert.full_log
    )

    # ------------------------------------------------------
    # RULE LEVEL
    # ------------------------------------------------------

    try:

        rule_level = int(
            alert.rule_level
        )

    except (
        TypeError,
        ValueError
    ):

        rule_level = 0

    # ------------------------------------------------------
    # CLASSIFICATION
    # ------------------------------------------------------

    alert_type = _determine_alert_type(
        description
    )

    severity = _determine_severity(
        rule_level
    )

    # ------------------------------------------------------
    # UNIQUE ALERT ID
    # ------------------------------------------------------

    alert_id = _generate_alert_id(
        rule_id=rule_id,
        agent_id=agent_id,
        timestamp=timestamp,
        attacker_ip=attacker_ip,
        full_log=full_log
    )

    # ------------------------------------------------------
    # STANDARD SOAR ALERT
    # ------------------------------------------------------

    soar_alert = {

        "alert_id":
            alert_id,

        "alert_type":
            alert_type,

        "severity":
            severity,

        "source_ip":
            agent_ip,

        "attacker_ip":
            attacker_ip,

        "description":
            description,

        "timestamp":
            timestamp,

        # --------------------------------------------------
        # Source
        # --------------------------------------------------

        "source":
            "Wazuh",

        # --------------------------------------------------
        # Wazuh Context
        # --------------------------------------------------

        "wazuh_rule_id":
            rule_id,

        "wazuh_rule_level":
            rule_level,

        "wazuh_rule_description":
            description,

        "wazuh_agent_id":
            agent_id,

        "wazuh_agent_name":
            agent_name,

        "wazuh_agent_ip":
            agent_ip,

        # --------------------------------------------------
        # Evidence
        # --------------------------------------------------

        "full_log":
            full_log,

        "evidence": {

            "source":
                "Wazuh",

            "rule_id":
                rule_id,

            "rule_level":
                rule_level,

            "rule_description":
                description,

            "agent_id":
                agent_id,

            "agent_name":
                agent_name,

            "agent_ip":
                agent_ip,

            "attacker_ip":
                attacker_ip,

            "full_log":
                full_log,

            "timestamp":
                timestamp,

        },
    }

    return soar_alert