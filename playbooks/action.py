"""
action.py

Mock incident response actions for the SOAR Incident Containment Engine.

These functions simulate automated containment actions.
In future versions, they can be replaced with real firewall,
EDR, cloud, or SIEM API integrations.
"""

import os
from datetime import datetime, timezone


def execute_action(action: str, target: str):
    """Run an explicitly labelled adapter; DEMO never changes external systems."""
    mode = os.getenv("SOAR_EXECUTION_MODE", "DEMO").strip().upper()
    timestamp = datetime.now(timezone.utc).isoformat()
    if mode == "DEMO":
        return {"status": "success", "action": action, "target": target,
                "timestamp": timestamp, "execution_mode": "DEMO", "simulated": True,
                "containment_verified": False,
                "message": f"DEMO: {action} was simulated; no external system was changed."}
    if mode == "INTEGRATION":
        return {"status": "failed", "action": action, "target": target,
                "timestamp": timestamp, "execution_mode": "INTEGRATION", "simulated": False,
                "containment_verified": False,
                "message": "No integration adapter is configured for this action."}
    return {"status": "failed", "action": action, "target": target,
            "timestamp": timestamp, "execution_mode": mode, "simulated": False,
            "containment_verified": False, "message": "Unsupported execution mode."}


def block_ip(ip_address):
    """Simulate blocking a malicious IP address."""

    return execute_action("block_ip", ip_address)


def notify_soc(ip_address):
    """Simulate notifying the SOC analyst."""

    return execute_action("notify_soc", ip_address)


def create_incident(ip_address):
    """Simulate creating an incident ticket."""

    return execute_action("create_incident", ip_address)


def log_event(ip_address):
    """Simulate logging an event."""

    return execute_action("log_event", ip_address)
    
def contain_host(host_address):
    """Simulate isolating a compromised host."""

    return execute_action("contain_host", host_address)
