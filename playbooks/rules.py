"""
rules.py
Defines playbook rules based on risk score.
"""

PLAYBOOK_RULES = {
    "critical": {
        "min_score": 90,
        "action": "block_ip"
    },
    "high": {
        "min_score": 70,
        "action": "notify_soc"
    },
    "medium": {
        "min_score": 40,
        "action": "create_incident"
    },
    "low": {
        "min_score": 0,
        "action": "log_event"
    }
}


def get_playbook(risk_score):
    """
    Returns the appropriate playbook action
    based on the calculated risk score.
    """

    if risk_score >= PLAYBOOK_RULES["critical"]["min_score"]:
        return PLAYBOOK_RULES["critical"]["action"]

    elif risk_score >= PLAYBOOK_RULES["high"]["min_score"]:
        return PLAYBOOK_RULES["high"]["action"]

    elif risk_score >= PLAYBOOK_RULES["medium"]["min_score"]:
        return PLAYBOOK_RULES["medium"]["action"]

    else:
        return PLAYBOOK_RULES["low"]["action"]