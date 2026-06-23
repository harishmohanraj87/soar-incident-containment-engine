def parse_alert(alert):

    return {
        "alert_id": alert.get("alert_id"),
        "alert_type": alert.get("alert_type"),
        "severity": alert.get("severity"),
        "source_ip": alert.get("source_ip"),
        "attacker_ip": alert.get("attacker_ip")
    }
