"""
engine.py

Playbook execution engine for the
SOAR Incident Containment Engine.
"""

from playbooks.rules import get_playbook

from playbooks.action import (
    block_ip,
    notify_soc,
    create_incident,
    log_event
)


def execute_playbook(alert):
    """
    Execute the appropriate playbook based on
    the calculated risk score.
    """

    if "ip" not in alert or "risk_score" not in alert:
        raise ValueError("Alert must contain 'ip' and 'risk_score'.")

    playbook = get_playbook(alert["risk_score"])

    print("=" * 50)
    print("SOAR PLAYBOOK ENGINE")
    print("=" * 50)

    print(f"Target IP        : {alert['ip']}")
    print(f"Risk Score       : {alert['risk_score']}")
    print(f"Selected Playbook: {playbook}")

    if playbook == "block_ip":
        result = block_ip(alert["ip"])

    elif playbook == "notify_soc":
        result = notify_soc(alert["ip"])

    elif playbook == "create_incident":
        result = create_incident(alert["ip"])

    else:
        result = log_event(alert["ip"])

    return result


if __name__ == "__main__":

    sample_alert = {
        "ip": "185.220.101.1",
        "risk_score": 95
    }

    result = execute_playbook(sample_alert)

    print("\nExecution Result")
    print(result)