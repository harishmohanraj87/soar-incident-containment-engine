def normalize_alert(parsed_alert):
    """
    Convert alerts into a standard format.
    """

    return {
        "id": parsed_alert.get("alert_id"),
        "type": parsed_alert.get("alert_type"),
        "severity": str(parsed_alert.get("severity")).upper(),
        "ip": parsed_alert.get("source_ip")
    }