from database.database import create_connection


# ==========================================================
# ALERT MANAGEMENT
# ==========================================================

# ----------------------------------------------------------
# CREATE ALERT
# ----------------------------------------------------------

def save_alert(alert):

    conn = create_connection()
    cursor = conn.cursor()

    print("=" * 60)
    print("SAVING ALERT")
    print(alert)
    print("=" * 60)

    cursor.execute("""
        INSERT INTO alerts (
            alert_id,
            alert_type,
            severity,
            source_ip,
            attacker_ip,
            risk_score,
            risk_level,
            action_taken,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("id"),
        alert.get("type"),
        alert.get("severity"),
        alert.get("source_ip"),
        alert.get("attacker_ip"),
        alert.get("risk_score", 0),
        alert.get("risk_level", "LOW"),
        alert.get("action_taken", "Pending"),
        alert.get("status", "NEW")
    ))

    saved_alert_id = alert.get("id")

    conn.commit()
    conn.close()

    return saved_alert_id


# ----------------------------------------------------------
# READ ALERTS
# ----------------------------------------------------------

def get_all_alerts():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY created_at DESC
    """)

    alerts = cursor.fetchall()

    conn.close()

    return alerts


def get_alert_by_id(alert_id):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        WHERE alert_id = ?
    """, (alert_id,))

    alert = cursor.fetchone()

    conn.close()

    return alert


# ----------------------------------------------------------
# UPDATE ALERT
# ----------------------------------------------------------

def update_alert_status(alert_id, status):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alerts
        SET status = ?
        WHERE alert_id = ?
    """, (status, alert_id))

    conn.commit()
    conn.close()


def update_action(alert_id, action):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE alerts
        SET action_taken = ?
        WHERE alert_id = ?
    """, (action, alert_id))

    conn.commit()
    conn.close()


# ----------------------------------------------------------
# DELETE ALERT
# ----------------------------------------------------------

def delete_alert(alert_id):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM alerts
        WHERE alert_id = ?
    """, (alert_id,))

    conn.commit()
    conn.close()


# ==========================================================
# DASHBOARD STATISTICS
# ==========================================================

def get_total_alerts():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


def get_high_risk_alerts():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE risk_level IN ('HIGH', 'CRITICAL')
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


def get_critical_alerts():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'CRITICAL'
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


def get_playbook_executions():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE action_taken IS NOT NULL
          AND action_taken != 'Pending'
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


def get_blocked_ips():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE action_taken = 'Block IP'
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total


def get_mttr():
    """
    Placeholder for Mean Time To Respond.
    Will be calculated from incidents
    in a future sprint.
    """
    return "2.4 min"


def get_recent_alerts(limit=10):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            alert_id,
            source_ip,
            severity,
            risk_score,
            status,
            created_at
        FROM alerts
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))

    alerts = cursor.fetchall()

    conn.close()

    return alerts
# ==========================================================
# INCIDENT MANAGEMENT
# ==========================================================

# ----------------------------------------------------------
# CREATE INCIDENT
# ----------------------------------------------------------

def create_incident(incident):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incidents (
            incident_id,
            alert_id,
            title,
            priority,
            incident_status,
            assigned_to,
            analyst_notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        incident.get("incident_id"),
        incident.get("alert_id"),
        incident.get("title"),
        incident.get("priority", "P3"),
        incident.get("incident_status", "NEW"),
        incident.get("assigned_to", "Unassigned"),
        incident.get("analyst_notes", "")
    ))

    conn.commit()
    conn.close()


# ----------------------------------------------------------
# READ INCIDENTS
# ----------------------------------------------------------

def get_all_incidents():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY created_at DESC
    """)

    incidents = cursor.fetchall()

    conn.close()

    return incidents


def get_incident_by_id(incident_id):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    incident = cursor.fetchone()

    conn.close()

    return incident


# ----------------------------------------------------------
# UPDATE INCIDENT
# ----------------------------------------------------------

def update_incident_status(incident_id, status):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET incident_status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE incident_id = ?
    """, (status, incident_id))

    conn.commit()
    conn.close()


def assign_analyst(incident_id, analyst):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET assigned_to = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE incident_id = ?
    """, (analyst, incident_id))

    conn.commit()
    conn.close()


def add_analyst_note(incident_id, note):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET analyst_notes =
            COALESCE(analyst_notes, '')
            || '\n\n'
            || ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE incident_id = ?
    """, (note, incident_id))

    conn.commit()
    conn.close()


# ----------------------------------------------------------
# DELETE INCIDENT
# ----------------------------------------------------------

def delete_incident(incident_id):
    """
    TODO:
    Replace hard delete with soft delete
    after the Audit Log module is implemented.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE
        FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    conn.commit()
    conn.close()


# ----------------------------------------------------------
# INCIDENT DASHBOARD STATISTICS
# ----------------------------------------------------------

def get_open_incidents():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE incident_status IN (
            'NEW',
            'INVESTIGATING',
            'CONTAINED'
        )
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total
# ==========================================================
# INCIDENT API HELPERS
# ==========================================================

def incident_exists(incident_id):
    """
    Check whether an incident exists.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 1
        FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    exists = cursor.fetchone() is not None

    conn.close()

    return exists


def get_incident_summary():
    """
    Lightweight incident information
    used by dashboards and REST APIs.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            incident_id,
            alert_id,
            title,
            priority,
            incident_status,
            assigned_to,
            created_at
        FROM incidents
        ORDER BY created_at DESC
    """)

    incidents = cursor.fetchall()

    conn.close()

    return incidents


def get_incidents_by_status(status):
    """
    Retrieve incidents by status.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE incident_status = ?
        ORDER BY created_at DESC
    """, (status,))

    incidents = cursor.fetchall()

    conn.close()

    return incidents


def get_incidents_by_analyst(analyst):
    """
    Retrieve incidents assigned
    to a specific SOC analyst.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE assigned_to = ?
        ORDER BY created_at DESC
    """, (analyst,))

    incidents = cursor.fetchall()

    conn.close()

    return incidents


def get_incident_counts():
    """
    Dashboard statistics for incidents.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            incident_status,
            COUNT(*)
        FROM incidents
        GROUP BY incident_status
    """)

    rows = cursor.fetchall()

    conn.close()

    return {
        row[0]: row[1]
        for row in rows
    }


def resolve_incident(incident_id):
    """
    Mark an incident as resolved.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE incidents
        SET incident_status = 'RESOLVED',
            resolved_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE incident_id = ?
    """, (incident_id,))

    conn.commit()
    conn.close()
    # ----------------------------------------
# INCIDENT ACTIVITY LOG
# ----------------------------------------

def log_incident_activity(
    incident_id,
    activity_type,
    activity,
    performed_by="System"
):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incident_activity (
            incident_id,
            activity_type,
            activity,
            performed_by
        )
        VALUES (?, ?, ?, ?)
    """, (
        incident_id,
        activity_type,
        activity,
        performed_by
    ))

    conn.commit()
    conn.close()


def get_incident_activity(incident_id):
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            activity_type,
            activity,
            performed_by,
            created_at
        FROM incident_activity
        WHERE incident_id = ?
        ORDER BY created_at DESC
    """, (incident_id,))

    activities = cursor.fetchall()

    conn.close()

    return activities
# ==========================================================
# DASHBOARD ANALYTICS
# ==========================================================

def get_alerts_by_severity():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            severity,
            COUNT(*)
        FROM alerts
        GROUP BY severity
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_incidents_by_status_chart():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            incident_status,
            COUNT(*)
        FROM incidents
        GROUP BY incident_status
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_daily_alerts():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            DATE(created_at),
            COUNT(*)
        FROM alerts
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def get_risk_distribution():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            risk_level,
            COUNT(*)
        FROM alerts
        GROUP BY risk_level
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows
# ==========================================================
# REPORTING
# ==========================================================

def export_incidents():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            incident_id,
            alert_id,
            title,
            priority,
            incident_status,
            assigned_to,
            created_at
        FROM incidents
        ORDER BY created_at DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows