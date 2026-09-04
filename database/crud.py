import sqlite3
import csv
import io

from database.database import create_connection
from backend.auth import verify_password

from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet


# ==========================================================
# HELPER
# ==========================================================

def rows_to_dicts(rows):
    """
    Convert SQLite rows to dictionaries.
    """

    return [
        dict(row)
        for row in rows
    ]


# ==========================================================
# ALERT MANAGEMENT
# ==========================================================

def save_alert(alert: dict):
    """
    Save a normalized alert.

    Geographic threat intelligence is also persisted when
    available so the Attack Map can use the data later.

    Returns:
        {
            "alert_id": "...",
            "created": True/False,
            "duplicate": True/False
        }
    """

    alert_id = alert.get("id")

    if not alert_id:
        raise ValueError(
            "Cannot save alert: missing alert ID"
        )

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 1
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,)
        )

        if cursor.fetchone():
            print(
                f"Alert {alert_id} already exists."
            )

            return {
                "alert_id": alert_id,
                "created": False,
                "duplicate": True
            }

        cursor.execute(
            """
            INSERT INTO alerts (
                alert_id,
                alert_type,
                severity,
                source_ip,
                attacker_ip,
                risk_score,
                risk_level,
                action_taken,
                status,
                country,
                city,
                region,
                latitude,
                longitude,
                org
            )
            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?
            )
            """,
            (
                alert_id,
                alert.get("type"),
                alert.get("severity"),
                alert.get("source_ip"),
                alert.get("attacker_ip"),
                alert.get("risk_score", 0),
                alert.get("risk_level", "LOW"),
                alert.get("action_taken", "Pending"),
                alert.get("status", "NEW"),
                alert.get("country"),
                alert.get("city"),
                alert.get("region"),
                alert.get("latitude"),
                alert.get("longitude"),
                alert.get("org")
            )
        )

        conn.commit()

        print(
            f"Alert {alert_id} saved successfully."
        )

        return {
            "alert_id": alert_id,
            "created": True,
            "duplicate": False
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def delete_alert(alert_id: str):

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,)
        )

        conn.commit()

        return cursor.rowcount > 0

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# ==========================================================
# ADVANCED ALERT SEARCH & FILTERING
# ==========================================================

def search_alerts(
    query=None,
    search=None,
    severity=None,
    risk_level=None,
    status=None,
    alert_type=None,
    source_ip=None,
    attacker_ip=None,
    alert_id=None,
    incident_id=None,
    date_from=None,
    date_to=None,
    limit=50,
    offset=0
):
    """
    Advanced alert search and filtering.

    Supports the parameter names used by backend/main.py while
    retaining ``search`` as a backwards-compatible alias for ``query``.

    Returns a list of alert dictionaries so the existing API response
    can safely calculate ``len(results)`` and serialize the results.
    """

    if query is None:
        query = search

    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 50

    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0

    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    conditions = []
    parameters = []

    if query and str(query).strip():
        value = f"%{str(query).strip()}%"
        conditions.append("""
            (
                alert_id LIKE ?
                OR alert_type LIKE ?
                OR source_ip LIKE ?
                OR attacker_ip LIKE ?
                OR country LIKE ?
                OR city LIKE ?
                OR region LIKE ?
                OR org LIKE ?
            )
        """)
        parameters.extend([value] * 8)

    if severity and str(severity).strip():
        conditions.append("UPPER(severity) = UPPER(?)")
        parameters.append(str(severity).strip())

    if risk_level and str(risk_level).strip():
        conditions.append("UPPER(risk_level) = UPPER(?)")
        parameters.append(str(risk_level).strip())

    if status and str(status).strip():
        conditions.append("UPPER(status) = UPPER(?)")
        parameters.append(str(status).strip())

    if alert_type and str(alert_type).strip():
        conditions.append("UPPER(alert_type) = UPPER(?)")
        parameters.append(str(alert_type).strip())

    if source_ip and str(source_ip).strip():
        conditions.append("source_ip LIKE ?")
        parameters.append(f"%{str(source_ip).strip()}%")

    if attacker_ip and str(attacker_ip).strip():
        conditions.append("attacker_ip LIKE ?")
        parameters.append(f"%{str(attacker_ip).strip()}%")

    if alert_id and str(alert_id).strip():
        conditions.append("alert_id LIKE ?")
        parameters.append(f"%{str(alert_id).strip()}%")

    if incident_id and str(incident_id).strip():
        conditions.append("""
            EXISTS (
                SELECT 1
                FROM incidents i
                WHERE i.alert_id = alerts.alert_id
                  AND i.incident_id LIKE ?
            )
        """)
        parameters.append(f"%{str(incident_id).strip()}%")

    if date_from and str(date_from).strip():
        conditions.append("DATE(created_at) >= DATE(?)")
        parameters.append(str(date_from).strip())

    if date_to and str(date_to).strip():
        conditions.append("DATE(created_at) <= DATE(?)")
        parameters.append(str(date_to).strip())

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            f"""
            SELECT
                alert_id,
                alert_type,
                severity,
                source_ip,
                attacker_ip,
                risk_score,
                risk_level,
                action_taken,
                status,
                country,
                city,
                region,
                latitude,
                longitude,
                org,
                created_at
            FROM alerts
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            parameters + [limit, offset]
        )

        return rows_to_dicts(cursor.fetchall())

    finally:
        conn.close()


# ==========================================================
# ALERT QUERIES
# ==========================================================

def get_total_alerts():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


def get_high_risk_alerts():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE risk_level
            IN ('HIGH', 'CRITICAL')
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


def get_critical_alerts():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = 'CRITICAL'
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


def get_playbook_executions():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE action_taken IS NOT NULL
            AND action_taken != 'Pending'
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


def get_blocked_ips():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE action_taken = 'Block IP'
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


def get_mttr():
    """
    Current placeholder.

    This will be replaced with actual
    Detection -> Containment / Resolution
    time calculation in a later sprint.
    """

    return "2.4 min"


# ==========================================================
# RECENT ALERTS
# ==========================================================

def get_recent_alerts(limit=10):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                alert_id,
                alert_type,
                source_ip,
                attacker_ip,
                severity,
                risk_score,
                risk_level,
                status,
                action_taken,
                created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


# ==========================================================
# ATTACK MAP / GEOGRAPHIC THREAT INTELLIGENCE
# ==========================================================

def get_threat_map_data(limit=500):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                alert_id,
                alert_type,
                severity,
                attacker_ip,
                source_ip,
                risk_score,
                risk_level,
                status,
                action_taken,
                country,
                city,
                region,
                latitude,
                longitude,
                org,
                created_at
            FROM alerts
            WHERE attacker_ip IS NOT NULL
              AND attacker_ip != ''
              AND latitude IS NOT NULL
              AND longitude IS NOT NULL
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


# ==========================================================
# GEOGRAPHIC THREAT SUMMARY
# ==========================================================

def get_threat_map_summary():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
            """
        )

        total_mapped = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(DISTINCT country)
            FROM alerts
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND country IS NOT NULL
              AND country != ''
              AND country != 'Unknown'
            """
        )

        unique_countries = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND risk_level = 'CRITICAL'
            """
        )

        critical_mapped = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE latitude IS NOT NULL
              AND longitude IS NOT NULL
              AND risk_level = 'HIGH'
            """
        )

        high_mapped = cursor.fetchone()[0]

        return {
            "total_mapped_threats": total_mapped,
            "unique_countries": unique_countries,
            "critical_threats": critical_mapped,
            "high_risk_threats": high_mapped
        }

    finally:
        conn.close()


# ==========================================================
# INCIDENT MANAGEMENT
# ==========================================================

def create_incident(incident: dict):

    incident_id = incident.get("incident_id")
    alert_id = incident.get("alert_id")

    if not incident_id:
        raise ValueError(
            "Cannot create incident: missing incident ID"
        )

    if not alert_id:
        raise ValueError(
            "Cannot create incident: missing alert ID"
        )

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 1
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        if cursor.fetchone():

            print(
                f"Incident {incident_id} already exists."
            )

            return {
                "incident_id": incident_id,
                "created": False,
                "duplicate": True
            }

        cursor.execute(
            """
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
            """,
            (
                incident_id,
                alert_id,
                incident.get(
                    "title",
                    "Security Incident"
                ),
                incident.get(
                    "priority",
                    "P3"
                ),
                incident.get(
                    "incident_status",
                    "NEW"
                ),
                incident.get(
                    "assigned_to",
                    "Unassigned"
                ),
                incident.get(
                    "analyst_notes",
                    ""
                )
            )
        )

        conn.commit()

        print(
            f"Incident {incident_id} created successfully."
        )

        return {
            "incident_id": incident_id,
            "created": True,
            "duplicate": False
        }

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def get_all_incidents():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM incidents
            ORDER BY created_at DESC
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_incident_by_id(
    incident_id: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


def update_incident_status(
    incident_id: str,
    status: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE incidents
            SET incident_status = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            """,
            (
                status,
                incident_id
            )
        )

        conn.commit()

        return cursor.rowcount > 0

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def assign_analyst(
    incident_id: str,
    analyst: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE incidents
            SET assigned_to = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            """,
            (
                analyst,
                incident_id
            )
        )

        conn.commit()

        return cursor.rowcount > 0

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def add_analyst_note(
    incident_id: str,
    note: str
):

    if not note or not note.strip():

        raise ValueError(
            "Analyst note cannot be empty"
        )

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE incidents
            SET analyst_notes =
                CASE
                    WHEN analyst_notes IS NULL
                    OR analyst_notes = ''
                    THEN ?
                    ELSE analyst_notes
                    || '\n\n'
                    || ?
                END,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            """,
            (
                note.strip(),
                note.strip(),
                incident_id
            )
        )

        conn.commit()

        return cursor.rowcount > 0

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def delete_incident(
    incident_id: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM incident_activity
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        cursor.execute(
            """
            DELETE FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        deleted = cursor.rowcount > 0

        conn.commit()

        return deleted

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def get_open_incidents():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM incidents
            WHERE incident_status IN (
                'NEW',
                'INVESTIGATING',
                'CONTAINED'
            )
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


# ==========================================================
# INCIDENT API HELPERS
# ==========================================================

def incident_exists(
    incident_id: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 1
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        return (
            cursor.fetchone()
            is not None
        )

    finally:
        conn.close()


def get_incident_summary():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                incident_id,
                alert_id,
                title,
                priority,
                incident_status,
                assigned_to,
                created_at,
                updated_at
            FROM incidents
            ORDER BY created_at DESC
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_incidents_by_status(
    status: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM incidents
            WHERE incident_status = ?
            ORDER BY created_at DESC
            """,
            (status,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_incidents_by_analyst(
    analyst: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM incidents
            WHERE assigned_to = ?
            ORDER BY created_at DESC
            """,
            (analyst,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_incident_counts():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                incident_status,
                COUNT(*) AS count
            FROM incidents
            GROUP BY incident_status
            """
        )

        rows = cursor.fetchall()

        return {
            row["incident_status"]:
            row["count"]
            for row in rows
        }

    finally:
        conn.close()


def resolve_incident(
    incident_id: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE incidents
            SET incident_status = 'RESOLVED',
                resolved_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        conn.commit()

        return cursor.rowcount > 0

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


# ==========================================================
# INCIDENT ACTIVITY LOG
# ==========================================================

def log_incident_activity(
    incident_id: str,
    activity_type: str,
    activity: str,
    performed_by="System"
):

    if not incident_id:

        raise ValueError(
            "Cannot log activity: missing incident ID"
        )

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO incident_activity (
                incident_id,
                activity_type,
                activity,
                performed_by
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                incident_id,
                activity_type,
                activity,
                performed_by
            )
        )

        conn.commit()

        return True

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def get_incident_activity(
    incident_id: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                activity_type,
                activity,
                performed_by,
                created_at
            FROM incident_activity
            WHERE incident_id = ?
            ORDER BY created_at ASC
            """,
            (incident_id,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


# ==========================================================
# ADVANCED INCIDENT INVESTIGATION
# ==========================================================

def get_incident_investigation(
    incident_id: str
):
    """
    Return the complete investigation workspace dataset.

    Combines:

        Incident
            +
        Related Alert Evidence
            +
        Investigation Activity Timeline
    """

    if not incident_id:
        return None

    conn = create_connection()

    try:

        cursor = conn.cursor()

        # --------------------------------------------------
        # INCIDENT + RELATED ALERT
        # --------------------------------------------------

        cursor.execute(
            """
            SELECT
                i.incident_id,
                i.alert_id,
                i.title,
                i.priority,
                i.incident_status,
                i.assigned_to,
                i.analyst_notes,
                i.created_at,
                i.updated_at,
                i.resolved_at,

                a.alert_type,
                a.severity,
                a.source_ip,
                a.attacker_ip,
                a.risk_score,
                a.risk_level,
                a.action_taken,
                a.status AS alert_status,
                a.country,
                a.city,
                a.region,
                a.latitude,
                a.longitude,
                a.org,
                a.created_at AS alert_created_at

            FROM incidents i

            LEFT JOIN alerts a
                ON i.alert_id = a.alert_id

            WHERE i.incident_id = ?
            """,
            (incident_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        investigation = dict(row)

        # --------------------------------------------------
        # ACTIVITY TIMELINE
        # --------------------------------------------------

        cursor.execute(
            """
            SELECT
                activity_type,
                activity,
                performed_by,
                created_at
            FROM incident_activity
            WHERE incident_id = ?
            ORDER BY created_at ASC
            """,
            (incident_id,)
        )

        investigation["activity"] = rows_to_dicts(
            cursor.fetchall()
        )

        # --------------------------------------------------
        # INVESTIGATION METADATA
        # --------------------------------------------------

        investigation["has_alert_evidence"] = (
            investigation.get("alert_id") is not None
        )

        investigation["has_attacker_ip"] = bool(
            investigation.get("attacker_ip")
        )

        investigation["has_geolocation"] = (
            investigation.get("latitude") is not None
            and
            investigation.get("longitude") is not None
        )

        return investigation

    finally:
        conn.close()


# ==========================================================
# DASHBOARD ANALYTICS
# ==========================================================
def get_alerts_by_severity():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                severity,
                COUNT(*) AS count
            FROM alerts
            GROUP BY severity
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_incidents_by_status_chart():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                incident_status,
                COUNT(*) AS count
            FROM incidents
            GROUP BY incident_status
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_daily_alerts():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                DATE(created_at) AS date,
                COUNT(*) AS count
            FROM alerts
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at)
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_risk_distribution():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                risk_level,
                COUNT(*) AS count
            FROM alerts
            GROUP BY risk_level
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


# ==========================================================
# ADVANCED SOC DASHBOARD ANALYTICS
# ==========================================================

def get_top_attacker_ips(limit=10):
    """
    Return the most frequent attacker IP addresses.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                attacker_ip,
                COUNT(*) AS alert_count,
                MAX(risk_score) AS max_risk_score
            FROM alerts
            WHERE attacker_ip IS NOT NULL
              AND attacker_ip != ''
            GROUP BY attacker_ip
            ORDER BY alert_count DESC, max_risk_score DESC
            LIMIT ?
            """,
            (limit,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_top_threat_countries(limit=10):
    """
    Return countries generating the most alerts.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                country,
                COUNT(*) AS alert_count,
                COUNT(DISTINCT attacker_ip) AS unique_attackers
            FROM alerts
            WHERE country IS NOT NULL
              AND country != ''
              AND country != 'Unknown'
            GROUP BY country
            ORDER BY alert_count DESC
            LIMIT ?
            """,
            (limit,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_alert_type_distribution():
    """
    Return distribution of security alert types.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                alert_type,
                COUNT(*) AS count
            FROM alerts
            WHERE alert_type IS NOT NULL
              AND alert_type != ''
            GROUP BY alert_type
            ORDER BY count DESC
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_recent_critical_alerts(limit=8):
    """
    Return the most recent HIGH and CRITICAL alerts.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                alert_id,
                alert_type,
                severity,
                attacker_ip,
                source_ip,
                risk_score,
                risk_level,
                status,
                action_taken,
                country,
                city,
                org,
                created_at
            FROM alerts
            WHERE severity IN ('HIGH', 'CRITICAL')
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_dashboard_metrics():
    """
    Return the main SOC Command Center metrics
    in a single database call.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_alerts,

                SUM(
                    CASE
                        WHEN severity = 'CRITICAL'
                        THEN 1
                        ELSE 0
                    END
                ) AS critical_alerts,

                SUM(
                    CASE
                        WHEN severity = 'HIGH'
                        THEN 1
                        ELSE 0
                    END
                ) AS high_alerts,

                SUM(
                    CASE
                        WHEN risk_level IN ('HIGH', 'CRITICAL')
                        THEN 1
                        ELSE 0
                    END
                ) AS high_risk_alerts,

                SUM(
                    CASE
                        WHEN action_taken = 'Block IP'
                        THEN 1
                        ELSE 0
                    END
                ) AS blocked_ips,

                SUM(
                    CASE
                        WHEN action_taken IS NOT NULL
                         AND action_taken != 'Pending'
                        THEN 1
                        ELSE 0
                    END
                ) AS playbook_runs

            FROM alerts
            """
        )

        row = cursor.fetchone()

        metrics = dict(row)

        for key, value in metrics.items():

            if value is None:
                metrics[key] = 0

        return metrics

    finally:
        conn.close()


def get_incident_dashboard_metrics():
    """
    Return incident posture metrics for the SOC dashboard.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_incidents,

                SUM(
                    CASE
                        WHEN incident_status = 'NEW'
                        THEN 1
                        ELSE 0
                    END
                ) AS new_incidents,

                SUM(
                    CASE
                        WHEN incident_status = 'INVESTIGATING'
                        THEN 1
                        ELSE 0
                    END
                ) AS investigating_incidents,

                SUM(
                    CASE
                        WHEN incident_status = 'CONTAINED'
                        THEN 1
                        ELSE 0
                    END
                ) AS contained_incidents,

                SUM(
                    CASE
                        WHEN incident_status = 'RESOLVED'
                        THEN 1
                        ELSE 0
                    END
                ) AS resolved_incidents,

                SUM(
                    CASE
                        WHEN incident_status = 'CLOSED'
                        THEN 1
                        ELSE 0
                    END
                ) AS closed_incidents

            FROM incidents
            """
        )

        row = cursor.fetchone()

        metrics = dict(row)

        for key, value in metrics.items():

            if value is None:
                metrics[key] = 0

        return metrics

    finally:
        conn.close()


def get_dashboard_overview():
    """
    Build the complete SOC Command Center dataset.

    This is the primary backend data source for
    the advanced dashboard.
    """

    return {

        "metrics":
            get_dashboard_metrics(),

        "incidents":
            get_incident_dashboard_metrics(),

        "severity":
            get_alerts_by_severity(),

        "risk":
            get_risk_distribution(),

        "alert_types":
            get_alert_type_distribution(),

        "daily_alerts":
            get_daily_alerts(),

        "top_attackers":
            get_top_attacker_ips(),

        "top_countries":
            get_top_threat_countries(),

        "recent_critical":
            get_recent_critical_alerts(),

        "threat_map":
            get_threat_map_data(),

        "threat_map_summary":
            get_threat_map_summary()

    }


# ==========================================================
# REAL-TIME SOC NOTIFICATIONS
# ==========================================================

def create_notification(
    notification_type: str,
    title: str,
    message: str,
    severity: str = "INFO",
    alert_id: str = None,
    incident_id: str = None
):
    """
    Create a SOC notification.

    Notification types:
        ALERT
        INCIDENT
        PLAYBOOK
        CONTAINMENT
        SYSTEM

    Notifications start as unread.
    """

    if not notification_type:

        raise ValueError(
            "Notification type is required"
        )

    if not title:

        raise ValueError(
            "Notification title is required"
        )

    if not message:

        raise ValueError(
            "Notification message is required"
        )

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO notifications (
                notification_type,
                severity,
                title,
                message,
                alert_id,
                incident_id,
                is_read
            )
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """,
            (
                notification_type,
                severity,
                title,
                message,
                alert_id,
                incident_id
            )
        )

        notification_id = cursor.lastrowid

        conn.commit()

        print(
            f"Notification {notification_id} created."
        )

        return {

            "id":
                notification_id,

            "notification_type":
                notification_type,

            "severity":
                severity,

            "title":
                title,

            "message":
                message,

            "alert_id":
                alert_id,

            "incident_id":
                incident_id,

            "is_read":
                0

        }

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def get_notifications(
    limit=20,
    unread_only=False
):
    """
    Return recent SOC notifications.
    """

    try:

        limit = int(limit)

    except (
        TypeError,
        ValueError
    ):

        limit = 20

    limit = max(
        1,
        min(limit, 100)
    )

    conn = create_connection()

    try:

        cursor = conn.cursor()

        if unread_only:

            cursor.execute(
                """
                SELECT
                    id,
                    notification_type,
                    severity,
                    title,
                    message,
                    alert_id,
                    incident_id,
                    is_read,
                    created_at
                FROM notifications
                WHERE is_read = 0
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,)
            )

        else:

            cursor.execute(
                """
                SELECT
                    id,
                    notification_type,
                    severity,
                    title,
                    message,
                    alert_id,
                    incident_id,
                    is_read,
                    created_at
                FROM notifications
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,)
            )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_unread_notification_count():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM notifications
            WHERE is_read = 0
            """
        )

        return cursor.fetchone()[0]

    finally:
        conn.close()


def mark_notification_read(
    notification_id: int
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE notifications
            SET is_read = 1
            WHERE id = ?
            """,
            (notification_id,)
        )

        updated = cursor.rowcount > 0

        conn.commit()

        return updated

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def mark_all_notifications_read():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE notifications
            SET is_read = 1
            WHERE is_read = 0
            """
        )

        updated_count = cursor.rowcount

        conn.commit()

        return {
            "updated":
                updated_count
        }

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def delete_notification(
    notification_id: int
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM notifications
            WHERE id = ?
            """,
            (notification_id,)
        )

        deleted = cursor.rowcount > 0

        conn.commit()

        return deleted

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


# ==========================================================
# REPORTING
# ==========================================================

def export_incidents(format=None):
    """
    Export incidents as CSV text, PDF bytes, or raw dictionaries.

    ``backend/main.py`` uses ``format="csv"`` and ``format="pdf"``.
    Calling this function without a format preserves the original raw
    incident-list behaviour.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                incident_id,
                alert_id,
                title,
                priority,
                incident_status,
                assigned_to,
                analyst_notes,
                created_at,
                updated_at
            FROM incidents
            ORDER BY created_at DESC
            """
        )

        incidents = rows_to_dicts(cursor.fetchall())

    finally:
        conn.close()

    if not format:
        return incidents

    export_format = str(format).lower().strip()

    if export_format == "csv":
        output = io.StringIO()
        fieldnames = [
            "incident_id",
            "alert_id",
            "title",
            "priority",
            "incident_status",
            "assigned_to",
            "analyst_notes",
            "created_at",
            "updated_at"
        ]

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames
        )
        writer.writeheader()
        writer.writerows(incidents)

        return output.getvalue()

    if export_format == "pdf":
        buffer = io.BytesIO()

        document = SimpleDocTemplate(
            buffer,
            pagesize=landscape(letter),
            rightMargin=24,
            leftMargin=24,
            topMargin=24,
            bottomMargin=24
        )

        styles = getSampleStyleSheet()
        title = Paragraph(
            "SOAR Incident Report",
            styles["Title"]
        )

        headers = [
            "Incident ID",
            "Alert ID",
            "Title",
            "Priority",
            "Status",
            "Assigned To",
            "Created",
            "Updated"
        ]

        table_data = [headers]

        for incident in incidents:
            table_data.append([
                str(incident.get("incident_id") or ""),
                str(incident.get("alert_id") or ""),
                str(incident.get("title") or ""),
                str(incident.get("priority") or ""),
                str(incident.get("incident_status") or ""),
                str(incident.get("assigned_to") or ""),
                str(incident.get("created_at") or ""),
                str(incident.get("updated_at") or "")
            ])

        table = Table(
            table_data,
            repeatRows=1
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")])
        ]))

        document.build([title, table])

        return buffer.getvalue()

    raise ValueError(
        "Unsupported export format. Use 'csv', 'pdf', or None."
    )


# ==========================================================
# USER MANAGEMENT
# ==========================================================

def create_user(user: dict):

    username = user.get("username")

    if not username:

        raise ValueError(
            "Cannot create user: missing username"
        )

    if user_exists(username):

        return False

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                full_name,
                role
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                user.get("password_hash"),
                user.get("full_name", username),
                user.get("role", "ANALYST")
            )
        )

        conn.commit()

        return True

    except sqlite3.IntegrityError:

        conn.rollback()

        return False

    except Exception:

        conn.rollback()
        raise

    finally:
        conn.close()


def get_user(
    username: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


def get_all_users():

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                username,
                full_name,
                role,
                created_at
            FROM users
            ORDER BY username
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def user_exists(
    username: str
):

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT 1
            FROM users
            WHERE username = ?
            """,
            (username,)
        )

        return (
            cursor.fetchone()
            is not None
        )

    finally:
        conn.close()


# ==========================================================
# AUTHENTICATION
# ==========================================================

def authenticate_user(
    username: str,
    password: str
):

    user = get_user(username)

    if not user:
        return None

    if not verify_password(
        password,
        user["password_hash"]
    ):
        return None

    return user

# ==========================================================
# PLAYBOOK APPROVALS
# ==========================================================

def create_playbook_approval(
    incident_id: str,
    alert_id: str,
    action: str,
    target: str,
    risk_score: int,
    requested_by: str = "SOAR Engine"
):
    """
    Create a pending approval request for a high-impact
    SOAR playbook action.

    The referenced incident must exist before an approval
    can be created.
    """

    if not incident_id:
        raise ValueError("Missing incident ID")

    if not action:
        raise ValueError("Missing playbook action")

    if not target:
        raise ValueError("Missing containment target")

    if alert_id is None:
        raise ValueError("Missing alert ID")

    conn = create_connection()

    try:
        cursor = conn.cursor()

        # --------------------------------------------------
        # VERIFY INCIDENT
        # --------------------------------------------------

        cursor.execute(
            """
            SELECT 1
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,)
        )

        if cursor.fetchone() is None:
            raise ValueError(
                f"Incident '{incident_id}' does not exist."
            )

        # --------------------------------------------------
        # VERIFY ALERT
        # --------------------------------------------------

        cursor.execute(
            """
            SELECT 1
            FROM alerts
            WHERE alert_id = ?
            """,
            (alert_id,)
        )

        if cursor.fetchone() is None:
            raise ValueError(
                f"Alert '{alert_id}' does not exist."
            )

        # --------------------------------------------------
        # PREVENT DUPLICATE PENDING APPROVAL
        # --------------------------------------------------

        cursor.execute(
            """
            SELECT *
            FROM playbook_approvals
            WHERE incident_id = ?
              AND action = ?
              AND target = ?
              AND status = 'PENDING'
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (
                incident_id,
                action,
                target
            )
        )

        existing = cursor.fetchone()

        if existing:
            return dict(existing)

        # --------------------------------------------------
        # CREATE APPROVAL
        # --------------------------------------------------

        cursor.execute(
            """
            INSERT INTO playbook_approvals (
                incident_id,
                alert_id,
                action,
                target,
                risk_score,
                status,
                requested_by
            )
            VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
            """,
            (
                incident_id,
                alert_id,
                action,
                target,
                risk_score,
                requested_by
            )
        )

        approval_id = cursor.lastrowid

        conn.commit()

        print(
            f"Playbook approval {approval_id} created."
        )

        return {
            "id": approval_id,
            "incident_id": incident_id,
            "alert_id": alert_id,
            "action": action,
            "target": target,
            "risk_score": risk_score,
            "status": "PENDING",
            "requested_by": requested_by
        }

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_playbook_approval(
    approval_id: int
):
    """
    Retrieve a single playbook approval request.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM playbook_approvals
            WHERE id = ?
            """,
            (approval_id,)
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


def get_pending_playbook_approvals():
    """
    Return all pending playbook approval requests.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM playbook_approvals
            WHERE status = 'PENDING'
            ORDER BY requested_at DESC
            """
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def get_incident_playbook_approvals(
    incident_id: str
):
    """
    Return all playbook approvals associated
    with an incident.
    """

    if not incident_id:
        raise ValueError("Missing incident ID")

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM playbook_approvals
            WHERE incident_id = ?
            ORDER BY requested_at DESC
            """,
            (incident_id,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def review_playbook_approval(
    approval_id: int,
    status: str,
    reviewed_by: str,
    reviewer_comment: str = ""
):
    """
    Approve or reject a pending playbook action.

    Valid statuses:
        APPROVED
        REJECTED

    Only PENDING approvals can be reviewed.
    """

    if not approval_id:
        raise ValueError(
            "Missing approval ID"
        )

    if not reviewed_by:
        raise ValueError(
            "Reviewer identity is required"
        )

    status = str(status).upper().strip()

    if status not in (
        "APPROVED",
        "REJECTED"
    ):
        raise ValueError(
            "Approval status must be APPROVED or REJECTED"
        )

    conn = create_connection()

    try:
        cursor = conn.cursor()

        # --------------------------------------------------
        # VERIFY APPROVAL EXISTS
        # --------------------------------------------------

        cursor.execute(
            """
            SELECT *
            FROM playbook_approvals
            WHERE id = ?
            """,
            (approval_id,)
        )

        approval = cursor.fetchone()

        if approval is None:
            raise ValueError(
                f"Playbook approval {approval_id} not found."
            )

        approval = dict(approval)

        # --------------------------------------------------
        # PREVENT DOUBLE REVIEW
        # --------------------------------------------------

        if approval["status"] != "PENDING":
            raise ValueError(
                f"Approval {approval_id} has already been "
                f"reviewed with status "
                f"'{approval['status']}'."
            )

        # --------------------------------------------------
        # REVIEW APPROVAL
        # --------------------------------------------------

        cursor.execute(
            """
            UPDATE playbook_approvals
            SET
                status = ?,
                reviewed_by = ?,
                reviewer_comment = ?,
                reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND status = 'PENDING'
            """,
            (
                status,
                reviewed_by,
                reviewer_comment or "",
                approval_id
            )
        )

        if cursor.rowcount == 0:
            raise RuntimeError(
                "Playbook approval could not be updated."
            )

        conn.commit()

        print(
            f"Playbook approval {approval_id} "
            f"reviewed as {status} by {reviewed_by}."
        )

        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def mark_playbook_approval_executed(
    approval_id: int,
    executed_by: str = "System"
):
    """
    Mark an APPROVED playbook approval as EXECUTED.

    This prevents the same approval from being executed
    repeatedly.
    """

    if not approval_id:
        raise ValueError(
            "Missing approval ID"
        )

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE playbook_approvals
            SET
                status = 'EXECUTED',
                reviewed_by = COALESCE(
                    reviewed_by,
                    ?
                ),
                reviewed_at = COALESCE(
                    reviewed_at,
                    CURRENT_TIMESTAMP
                )
            WHERE id = ?
              AND status = 'APPROVED'
            """,
            (
                executed_by,
                approval_id
            )
        )

        updated = cursor.rowcount > 0

        conn.commit()

        if updated:
            print(
                f"Playbook approval {approval_id} "
                f"marked EXECUTED."
            )

        return updated

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_executed_playbook_approvals(
    limit: int = 50
):
    """
    Return recently executed playbook approvals.
    """

    try:
        limit = int(limit)
    except (
        TypeError,
        ValueError
    ):
        limit = 50

    limit = max(
        1,
        min(limit, 200)
    )

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM playbook_approvals
            WHERE status = 'EXECUTED'
            ORDER BY reviewed_at DESC
            LIMIT ?
            """,
            (limit,)
        )

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


def reject_playbook_approval(
    approval_id: int,
    reviewed_by: str,
    reviewer_comment: str = ""
):
    """
    Convenience function for rejecting a playbook approval.
    """

    return review_playbook_approval(
        approval_id=approval_id,
        status="REJECTED",
        reviewed_by=reviewed_by,
        reviewer_comment=reviewer_comment
    )


def approve_playbook_approval(
    approval_id: int,
    reviewed_by: str,
    reviewer_comment: str = ""
):
    """
    Convenience function for approving a playbook approval.
    """

    return review_playbook_approval(
        approval_id=approval_id,
        status="APPROVED",
        reviewed_by=reviewed_by,
        reviewer_comment=reviewer_comment
    )
