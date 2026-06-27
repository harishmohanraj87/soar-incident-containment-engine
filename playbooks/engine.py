from rules import get_playbook

alert = {
    "ip": "185.220.101.1",
    "risk_score": 95
}

action = get_playbook(alert["risk_score"])

print(f"Selected Playbook: {action}")
