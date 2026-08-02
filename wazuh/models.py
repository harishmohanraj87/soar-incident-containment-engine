"""
Wazuh Alert Data Models

Defines the standard data structures used to represent
incoming Wazuh security alerts before they are processed
by the SOAR engine.
"""

from pydantic import BaseModel
from typing import Optional


class WazuhAlert(BaseModel):
    """
    Standard model representing a Wazuh security alert.
    """

    timestamp: str

    rule_id: str
    rule_level: int
    rule_description: str

    agent_id: str
    agent_name: str
    agent_ip: str

    attacker_ip: Optional[str] = None

    event_type: Optional[str] = None
    severity: Optional[str] = None

    full_log: Optional[str] = None