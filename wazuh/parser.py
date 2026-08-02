"""
Wazuh Alert Parser

Parses raw Wazuh alert JSON into a WazuhAlert model.
"""

from wazuh.models import WazuhAlert


def parse_wazuh_alert(alert: dict) -> WazuhAlert:
    """
    Parse raw Wazuh alert JSON into a WazuhAlert object.
    """

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    return WazuhAlert(

        timestamp=alert.get("timestamp", ""),

        rule_id=str(rule.get("id", "")),
        rule_level=int(rule.get("level", 0)),
        rule_description=rule.get("description", ""),

        agent_id=str(agent.get("id", "")),
        agent_name=agent.get("name", ""),
        agent_ip=agent.get("ip", ""),

        attacker_ip=data.get("srcip"),

        full_log=alert.get("full_log", "")
    )