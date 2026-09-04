"""
rules.py

Defines risk-based playbook policies for the
SOAR Incident Containment Engine.
"""


PLAYBOOK_RULES = {
    "critical": {
        "min_score": 90,
        "action": "contain_host",
        "approval_required": True,
        "description": "Critical threat requiring host containment approval",
    },

    "high": {
        "min_score": 70,
        "action": "block_ip",
        "approval_required": False,
        "description": "High-risk source IP requiring network containment",
    },

    "medium": {
        "min_score": 40,
        "action": "notify_soc",
        "approval_required": False,
        "description": "Medium-risk alert requiring analyst attention",
    },

    "low": {
        "min_score": 0,
        "action": "log_event",
        "approval_required": False,
        "description": "Low-risk event recorded for monitoring",
    },
}


def get_playbook(risk_score):
    """
    Return the playbook policy for a given risk score.
    """

    try:
        risk_score = int(risk_score)
    except (TypeError, ValueError):
        raise ValueError("Risk score must be a number.")

    if risk_score < 0 or risk_score > 100:
        raise ValueError("Risk score must be between 0 and 100.")

    if risk_score >= PLAYBOOK_RULES["critical"]["min_score"]:
        return PLAYBOOK_RULES["critical"]

    if risk_score >= PLAYBOOK_RULES["high"]["min_score"]:
        return PLAYBOOK_RULES["high"]

    if risk_score >= PLAYBOOK_RULES["medium"]["min_score"]:
        return PLAYBOOK_RULES["medium"]

    return PLAYBOOK_RULES["low"]