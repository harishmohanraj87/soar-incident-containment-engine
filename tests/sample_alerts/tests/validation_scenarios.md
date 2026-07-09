# Validation Scenarios

## Scenario 1

Attack:
Malware Detection

Expected Result

- Alert parsed successfully
- IOC extracted
- Threat enrichment executed
- Playbook triggered
- Host isolated

Status

PASS

---

## Scenario 2

Attack:
Brute Force Attack

Expected Result

- Alert received
- Failed login count extracted
- IP reputation checked
- Firewall blocks attacker IP

Status

PASS

---

## Scenario 3

Attack:
Phishing Email

Expected Result

- Email indicators extracted
- URL reputation checked
- Alert logged

Status

PASS

---

## Scenario 4

Attack:
Ransomware

Expected Result

- Endpoint isolated
- Incident marked Critical
- Timeline updated

Status

PASS