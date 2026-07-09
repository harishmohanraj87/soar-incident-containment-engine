from database.database import create_connection


# -----------------------------
# CREATE
# -----------------------------

def save_alert(alert):

    conn = create_connection()
    cursor = conn.cursor()

    print("=" * 50)
    print("SAVING ALERT")
    print(alert)
    print("=" * 50)

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
# -----------------------------
# READ
# -----------------------------

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


# -----------------------------
# UPDATE
# -----------------------------

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


# -----------------------------
# DELETE
# -----------------------------

def delete_alert(alert_id):

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM alerts
        WHERE alert_id = ?
    """, (alert_id,))

    conn.commit()
    conn.close()


# -----------------------------
# DASHBOARD STATISTICS
# -----------------------------

def get_total_alerts():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM alerts")

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


def get_open_incidents():

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE status IN ('NEW', 'INVESTIGATING')
    """)

    total = cursor.fetchone()[0]

    conn.close()

    return total

# -----------------------------
# ADVANCED DASHBOARD STATISTICS
# -----------------------------

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

    Later this will be calculated using
    incident timestamps.
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

# -----------------------------
# INCIDENT MANAGEMENT
# -----------------------------

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
        SET analyst_notes = COALESCE(analyst_notes, '') || '\n\n' || ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE incident_id = ?
    """, (note, incident_id))

    conn.commit()
    conn.close()

def delete_incident(incident_id):
    """
    TODO:
    Replace hard delete with soft delete
    after Audit Log module is implemented.
    """

    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    conn.commit()
    conn.close()