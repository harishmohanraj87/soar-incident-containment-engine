"""
Wazuh Alert Parser

Parses raw Wazuh alert JSON into a WazuhAlert model.
"""

from wazuh.models import WazuhAlert


def _safe_int(value, default=0):
    """
    Safely convert a value to an integer.

    Wazuh normally sends rule.level as an integer,
    but this prevents the parser from crashing if
    the field is missing or malformed.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_dict(value):
    """
    Return a dictionary when the supplied value is a dictionary.

    Prevents parser failures when optional Wazuh sections
    are missing or have an unexpected type.
    """

    if isinstance(value, dict):
        return value

    return {}


def parse_wazuh_alert(alert: dict) -> WazuhAlert:
    """
    Parse raw Wazuh alert JSON into a WazuhAlert object.

    Expected Wazuh structure:

        {
            "timestamp": "...",
            "rule": {
                "id": "...",
                "level": 10,
                "description": "..."
            },
            "agent": {
                "id": "...",
                "name": "...",
                "ip": "..."
            },
            "data": {
                "srcip": "..."
            },
            "full_log": "..."
        }

    Returns:
        WazuhAlert
    """

    # ------------------------------------------------------
    # Validate top-level input
    # ------------------------------------------------------

    if not isinstance(alert, dict):
        raise ValueError(
            "Wazuh alert must be a JSON object"
        )

    # ------------------------------------------------------
    # Extract nested sections safely
    # ------------------------------------------------------

    rule = _safe_dict(
        alert.get("rule")
    )

    agent = _safe_dict(
        alert.get("agent")
    )

    data = _safe_dict(
        alert.get("data")
    )

    # ------------------------------------------------------
    # Extract attacker IP
    # ------------------------------------------------------

    attacker_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or alert.get("srcip")
        or alert.get("src_ip")
    )

    # ------------------------------------------------------
    # Build Wazuh model
    # ------------------------------------------------------

    return WazuhAlert(
        timestamp=str(
            alert.get("timestamp", "")
            or ""
        ),

        rule_id=str(
            rule.get("id", "")
            or ""
        ),

        rule_level=_safe_int(
            rule.get("level", 0)
        ),

        rule_description=str(
            rule.get("description", "")
            or ""
        ),

        agent_id=str(
            agent.get("id", "")
            or ""
        ),

        agent_name=str(
            agent.get("name", "")
            or ""
        ),

        agent_ip=str(
            agent.get("ip", "")
            or ""
        ),

        attacker_ip=attacker_ip,

        full_log=str(
            alert.get("full_log", "")
            or ""
        )
    )