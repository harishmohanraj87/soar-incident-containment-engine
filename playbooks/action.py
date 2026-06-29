"""
action.py

Mock incident response actions for the SOAR Incident Containment Engine.

These functions simulate automated containment actions.
In future versions, they can be replaced with real firewall,
EDR, cloud, or SIEM API integrations.
"""

from datetime import datetime


def block_ip(ip_address):
    """Simulate blocking a malicious IP address."""

    print(f"[{datetime.now()}] ACTION: Blocking IP {ip_address}")

    return {
        "status": "success",
        "action": "block_ip",
        "target": ip_address,
        "timestamp": str(datetime.now())
    }


def notify_soc(ip_address):
    """Simulate notifying the SOC analyst."""

    print(f"[{datetime.now()}] ACTION: Notifying SOC Analyst about {ip_address}")

    return {
        "status": "success",
        "action": "notify_soc",
        "target": ip_address,
        "timestamp": str(datetime.now())
    }


def create_incident(ip_address):
    """Simulate creating an incident ticket."""

    print(f"[{datetime.now()}] ACTION: Creating incident for {ip_address}")

    return {
        "status": "success",
        "action": "create_incident",
        "target": ip_address,
        "timestamp": str(datetime.now())
    }


def log_event(ip_address):
    """Simulate logging an event."""

    print(f"[{datetime.now()}] ACTION: Logging event for {ip_address}")

    return {
        "status": "success",
        "action": "log_event",
        "target": ip_address,
        "timestamp": str(datetime.now())
    }