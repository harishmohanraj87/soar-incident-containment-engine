from database.database import create_connection


# -----------------------------
# CREATE
# -----------------------------

def save_alert(alert):

    conn = create_connection()
    cursor = conn.cursor()

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
        alert["id"],
        alert["type"],
        alert["severity"],
        alert["source_ip"],
        alert["attacker_ip"],
        alert["risk_score"],
        alert["risk_level"],
        alert["action_taken"],
        alert["status"]
    ))

    conn.commit()
    conn.close()


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