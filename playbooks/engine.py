"""
engine.py

SOAR Playbook Execution Engine

Workflow:

    Alert
      ↓
    Risk Score
      ↓
    Playbook Selection
      ↓
    ┌───────────────────────────────┐
    │                               │
    │ Low / Medium Risk             │ Critical / High Impact
    │                               │
    ↓                               ↓
Automated Action              Approval Required
                                    ↓
                              SOC Analyst Review
                                    ↓
                              APPROVED / REJECTED
                                    ↓
                              Approved Execution
                                    ↓
                              Incident Update
                                    ↓
                              Audit Trail
                                    ↓
                              SOC Notification
"""

from playbooks.rules import get_playbook

from playbooks.action import (
    block_ip,
    contain_host,
    notify_soc,
    create_incident,
    log_event
)

from database.crud import (
    create_playbook_approval,
    get_playbook_approval,
    mark_playbook_approval_executed,
    update_incident_status,
    log_incident_activity,
    create_notification
)


# ==========================================================
# NORMAL PLAYBOOK EXECUTION
# ==========================================================

def execute_playbook(alert):
    """
    Select and execute the appropriate playbook.

    High-impact actions requiring approval are NOT executed
    immediately. An approval request is created instead.
    """

    # ------------------------------------------------------
    # VALIDATE ALERT
    # ------------------------------------------------------

    if not isinstance(alert, dict):
        raise ValueError(
            "Alert must be a dictionary."
        )

    if "ip" not in alert:
        raise ValueError(
            "Alert must contain 'ip'."
        )

    if "risk_score" not in alert:
        raise ValueError(
            "Alert must contain 'risk_score'."
        )

    ip_address = alert["ip"]
    risk_score = alert["risk_score"]

    if not ip_address:
        raise ValueError(
            "Alert IP address cannot be empty."
        )

    try:
        risk_score = int(risk_score)
    except (TypeError, ValueError):
        raise ValueError(
            "Risk score must be a number."
        )

    # ------------------------------------------------------
    # SELECT PLAYBOOK
    # ------------------------------------------------------

    playbook = get_playbook(
        risk_score
    )

    approval_required = playbook[
        "approval_required"
    ]

    description = playbook[
        "description"
    ]

    action = playbook[
        "action"
    ]

    print("=" * 50)
    print("SOAR PLAYBOOK ENGINE")
    print("=" * 50)

    print(
        f"Target IP        : {ip_address}"
    )

    print(
        f"Risk Score       : {risk_score}"
    )

    print(
        f"Selected Playbook: {action}"
    )

    print(
        f"Approval Required: "
        f"{'YES' if approval_required else 'NO'}"
    )

    # ======================================================
    # APPROVAL REQUIRED
    # ======================================================

    if approval_required:

        incident_id = alert.get(
            "incident_id"
        )

        alert_id = alert.get(
            "alert_id"
        )

        if not incident_id:
            raise ValueError(
                "Critical playbook requires incident_id."
            )

        approval = create_playbook_approval(
            incident_id=incident_id,
            alert_id=alert_id,
            action=action,
            target=ip_address,
            risk_score=risk_score
        )

        # --------------------------------------------------
        # SOC NOTIFICATION
        # --------------------------------------------------

        create_notification(
            notification_type="PLAYBOOK",
            severity="CRITICAL",
            title="Playbook Approval Required",
            message=(
                f"High-impact playbook '{action}' "
                f"requires SOC analyst approval for "
                f"{ip_address}. "
                f"Risk score: {risk_score}. "
                f"Approval ID: {approval['id']}."
            ),
            alert_id=alert_id,
            incident_id=incident_id
        )

        # --------------------------------------------------
        # AUDIT TRAIL
        # --------------------------------------------------

        log_incident_activity(
            incident_id=incident_id,
            activity_type="PLAYBOOK_APPROVAL_REQUESTED",
            activity=(
                f"Playbook '{action}' requested approval "
                f"for target {ip_address}. "
                f"Risk score: {risk_score}. "
                f"Approval ID: {approval['id']}."
            ),
            performed_by="SOAR Engine"
        )

        print(
            "Execution Status : PENDING_APPROVAL"
        )

        print(
            "Reason           : "
            "High-impact containment requires approval"
        )

        print(
            f"Approval ID      : {approval['id']}"
        )

        return {
            "status": "pending_approval",
            "action": action,
            "target": ip_address,
            "risk_score": risk_score,
            "approval_required": True,
            "approval_id": approval["id"],
            "incident_id": incident_id,
            "alert_id": alert_id,
            "description": description
        }

    # ======================================================
    # AUTOMATED ACTIONS
    # ======================================================

    print(
        "Execution Mode   : AUTOMATED"
    )

    if action == "block_ip":

        result = block_ip(
            ip_address
        )

    elif action == "notify_soc":

        result = notify_soc(
            ip_address
        )

    elif action == "create_incident":

        result = create_incident(
            ip_address
        )

    elif action == "log_event":

        result = log_event(
            ip_address
        )

    else:

        raise ValueError(
            f"Unsupported playbook action: {action}"
        )

    # ------------------------------------------------------
    # VERIFY AUTOMATED ACTION
    # ------------------------------------------------------

    if not isinstance(result, dict):
        raise RuntimeError(
            "Playbook action returned an invalid result."
        )

    if result.get("status") != "success":
        raise RuntimeError(
            f"Playbook action '{action}' failed."
        )

    # ------------------------------------------------------
    # AUTOMATED ACTION NOTIFICATION
    # ------------------------------------------------------

    create_notification(
        notification_type="PLAYBOOK",
        severity="HIGH" if risk_score >= 70 else "MEDIUM",
        title="Automated Playbook Executed",
        message=(
            f"Automated playbook '{action}' "
            f"successfully executed against "
            f"{ip_address}. "
            f"Risk score: {risk_score}."
        ),
        alert_id=alert.get("alert_id"),
        incident_id=alert.get("incident_id")
    )

    # ------------------------------------------------------
    # AUDIT TRAIL
    # ------------------------------------------------------

    if alert.get("incident_id"):

        log_incident_activity(
            incident_id=alert["incident_id"],
            activity_type="PLAYBOOK_EXECUTED",
            activity=(
                f"Automated playbook '{action}' "
                f"executed against {ip_address}. "
                f"Risk score: {risk_score}."
            ),
            performed_by="SOAR Engine"
        )

    return result


# ==========================================================
# APPROVED PLAYBOOK EXECUTION
# ==========================================================

def execute_approved_playbook(
    approval_id: int,
    executed_by: str = "System"
):
    """
    Execute a playbook after SOC analyst approval.

    Security workflow:

        PENDING
            ↓
        APPROVED
            ↓
        Atomic execution claim
            ↓
        Execute containment
            ↓
        Update incident
            ↓
        Audit activity
            ↓
        SOC notification
            ↓
        EXECUTED

    Important:
        An APPROVED approval can only be executed once.
    """

    # ======================================================
    # VALIDATE INPUT
    # ======================================================

    if approval_id is None:
        raise ValueError(
            "Approval ID is required."
        )

    try:
        approval_id = int(approval_id)
    except (TypeError, ValueError):
        raise ValueError(
            "Approval ID must be an integer."
        )

    if not executed_by:
        executed_by = "System"

    # ======================================================
    # LOAD APPROVAL
    # ======================================================

    approval = get_playbook_approval(
        approval_id
    )

    if approval is None:

        raise ValueError(
            "Playbook approval not found."
        )

    # ======================================================
    # VERIFY APPROVAL STATUS
    # ======================================================

    if approval["status"] != "APPROVED":

        if approval["status"] == "EXECUTED":

            raise ValueError(
                "This playbook approval has already been executed."
            )

        if approval["status"] == "REJECTED":

            raise ValueError(
                "This playbook approval was rejected."
            )

        if approval["status"] == "PENDING":

            raise ValueError(
                "Playbook approval is still pending."
            )

        raise ValueError(
            f"Playbook approval cannot be executed "
            f"from status '{approval['status']}'."
        )

    # ======================================================
    # LOAD APPROVAL DATA
    # ======================================================

    action = approval["action"]
    target = approval["target"]
    incident_id = approval["incident_id"]
    alert_id = approval["alert_id"]
    risk_score = approval["risk_score"]

    print("=" * 50)
    print("APPROVED PLAYBOOK EXECUTION")
    print("=" * 50)

    print(
        f"Approval ID     : {approval_id}"
    )

    print(
        f"Action          : {action}"
    )

    print(
        f"Target          : {target}"
    )

    print(
        f"Risk Score      : {risk_score}"
    )

    print(
        f"Approved By     : {approval['reviewed_by']}"
    )

    print(
        f"Executed By     : {executed_by}"
    )

    # ======================================================
    # CLAIM APPROVAL
    # ======================================================
    #
    # This changes:
    #
    # APPROVED → EXECUTED
    #
    # before allowing another execution.
    #
    # The CRUD function performs the update only when the
    # current status is APPROVED.
    #
    # ======================================================

    claimed = mark_playbook_approval_executed(
        approval_id=approval_id,
        executed_by=executed_by
    )

    if not claimed:

        raise RuntimeError(
            "Playbook approval could not be claimed. "
            "It may have already been executed."
        )

    # ======================================================
    # EXECUTE APPROVED ACTION
    # ======================================================

    try:

        if action == "contain_host":

            result = contain_host(
                target
            )

        elif action == "block_ip":

            result = block_ip(
                target
            )

        elif action == "notify_soc":

            result = notify_soc(
                target
            )

        elif action == "create_incident":

            result = create_incident(
                target
            )

        elif action == "log_event":

            result = log_event(
                target
            )

        else:

            raise ValueError(
                f"Unsupported approved playbook action: {action}"
            )

    except Exception as error:

        # --------------------------------------------------
        # FAILURE AUDIT
        # --------------------------------------------------

        log_incident_activity(
            incident_id=incident_id,
            activity_type="PLAYBOOK_EXECUTION_FAILED",
            activity=(
                f"Approved playbook '{action}' "
                f"failed against {target}. "
                f"Approval ID: {approval_id}. "
                f"Error: {error}"
            ),
            performed_by=executed_by
        )

        create_notification(
            notification_type="PLAYBOOK",
            severity="CRITICAL",
            title="Approved Playbook Failed",
            message=(
                f"Approved playbook '{action}' "
                f"failed against {target}. "
                f"Approval ID: {approval_id}."
            ),
            alert_id=alert_id,
            incident_id=incident_id
        )

        raise RuntimeError(
            f"Approved playbook execution failed: {error}"
        )

    # ======================================================
    # VERIFY ACTION RESULT
    # ======================================================

    if not isinstance(result, dict):

        raise RuntimeError(
            "Approved playbook returned an invalid result."
        )

    if result.get("status") != "success":

        raise RuntimeError(
            "Approved playbook action failed."
        )

    # ======================================================
    # UPDATE INCIDENT
    # ======================================================

    incident_status = "UNCHANGED"

    if action == "contain_host":

        updated = update_incident_status(
            incident_id,
            "CONTAINED"
        )

        if not updated:

            raise RuntimeError(
                f"Unable to update incident "
                f"{incident_id} to CONTAINED."
            )

        incident_status = "CONTAINED"

    # ======================================================
    # AUDIT TRAIL
    # ======================================================

    log_incident_activity(
        incident_id=incident_id,
        activity_type="PLAYBOOK_EXECUTED",
        activity=(
            f"Approved playbook '{action}' "
            f"executed successfully against {target}. "
            f"Approval ID: {approval_id}. "
            f"Risk score: {risk_score}. "
            f"Approved by: {approval['reviewed_by']}."
        ),
        performed_by=executed_by
    )

    # ======================================================
    # SOC NOTIFICATION
    # ======================================================

    notification_severity = (
        "CRITICAL"
        if action == "contain_host"
        else "HIGH"
    )

    create_notification(
        notification_type="CONTAINMENT"
        if action == "contain_host"
        else "PLAYBOOK",
        severity=notification_severity,
        title=(
            "Host Containment Executed"
            if action == "contain_host"
            else "Approved Playbook Executed"
        ),
        message=(
            f"Approved playbook '{action}' "
            f"was successfully executed against "
            f"{target}. "
            f"Approval ID: {approval_id}. "
            f"Executed by: {executed_by}."
        ),
        alert_id=alert_id,
        incident_id=incident_id
    )

    # ======================================================
    # FINAL OUTPUT
    # ======================================================

    print(
        "Execution Status : SUCCESS"
    )

    print(
        f"Incident Status  : {incident_status}"
    )

    print(
        "Approval Status  : EXECUTED"
    )

    return {
        "status": "success",
        "action": action,
        "target": target,
        "risk_score": risk_score,
        "approval_id": approval_id,
        "incident_id": incident_id,
        "alert_id": alert_id,
        "executed_by": executed_by,
        "incident_status": incident_status,
        "approval_status": "EXECUTED"
    }


# ==========================================================
# TEST
# ==========================================================

if __name__ == "__main__":

    sample_alert = {
        "ip": "185.220.101.1",
        "risk_score": 95,
        "incident_id": "INC-TEST-001",
        "alert_id": "ALERT-TEST-001"
    }

    result = execute_playbook(
        sample_alert
    )

    print("\nExecution Result")
    print(result)