import sqlite3

from database.database import create_connection
from backend.auth import verify_password


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
    search=None,
    severity=None,
    risk_level=None,
    status=None,
    alert_type=None,
    date_from=None,
    date_to=None,
    limit=50,
    offset=0
):
    """
    Advanced alert search and filtering.

    Supported filters:

    search:
        Searches across:
        - alert ID
        - alert type
        - source IP
        - attacker IP
        - country
        - city
        - region
        - organization

    severity:
        CRITICAL / HIGH / MEDIUM / LOW

    risk_level:
        CRITICAL / HIGH / MEDIUM / LOW

    status:
        NEW / INVESTIGATING / CONTAINED /
        RESOLVED / CLOSED

    alert_type:
        Exact alert type match.

    date_from:
        Inclusive start date in YYYY-MM-DD format.

    date_to:
        Inclusive end date in YYYY-MM-DD format.

    limit:
        Maximum number of returned alerts.

    offset:
        Pagination offset.

    Returns:
        {
            "alerts": [...],
            "total": 0,
            "limit": 50,
            "offset": 0
        }
    """

    # ------------------------------------------------------
    # Protect the database from unreasonable pagination.
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # Build WHERE conditions dynamically.
    # Values are always parameterized.
    # ------------------------------------------------------

    conditions = []
    parameters = []

    # ------------------------------------------------------
    # General search
    # ------------------------------------------------------

    if search and search.strip():

        search_value = f"%{search.strip()}%"

        conditions.append(
            """
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
            """
        )

        parameters.extend(
            [
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
                search_value,
                search_value
            ]
        )

    # ------------------------------------------------------
    # Severity
    # ------------------------------------------------------

    if severity and severity.strip():

        conditions.append(
            "UPPER(severity) = UPPER(?)"
        )

        parameters.append(
            severity.strip()
        )

    # ------------------------------------------------------
    # Risk level
    # ------------------------------------------------------

    if risk_level and risk_level.strip():

        conditions.append(
            "UPPER(risk_level) = UPPER(?)"
        )

        parameters.append(
            risk_level.strip()
        )

    # ------------------------------------------------------
    # Alert status
    # ------------------------------------------------------

    if status and status.strip():

        conditions.append(
            "UPPER(status) = UPPER(?)"
        )

        parameters.append(
            status.strip()
        )

    # ------------------------------------------------------
    # Alert type
    # ------------------------------------------------------

    if alert_type and alert_type.strip():

        conditions.append(
            "UPPER(alert_type) = UPPER(?)"
        )

        parameters.append(
            alert_type.strip()
        )

    # ------------------------------------------------------
    # Date range
    # ------------------------------------------------------

    if date_from and date_from.strip():

        conditions.append(
            "DATE(created_at) >= DATE(?)"
        )

        parameters.append(
            date_from.strip()
        )

    if date_to and date_to.strip():

        conditions.append(
            "DATE(created_at) <= DATE(?)"
        )

        parameters.append(
            date_to.strip()
        )

    # ------------------------------------------------------
    # Build WHERE clause.
    # ------------------------------------------------------

    where_clause = ""

    if conditions:
        where_clause = (
            "WHERE "
            + " AND ".join(conditions)
        )

    conn = create_connection()

    try:
        cursor = conn.cursor()

        # --------------------------------------------------
        # Total matching records
        # --------------------------------------------------

        count_query = f"""
            SELECT COUNT(*)
            FROM alerts
            {where_clause}
        """

        cursor.execute(
            count_query,
            parameters
        )

        total = cursor.fetchone()[0]

        # --------------------------------------------------
        # Matching alert records
        # --------------------------------------------------

        alert_query = f"""
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
        """

        alert_parameters = list(parameters)

        alert_parameters.extend(
            [
                limit,
                offset
            ]
        )

        cursor.execute(
            alert_query,
            alert_parameters
        )

        alerts = rows_to_dicts(
            cursor.fetchall()
        )

        return {
            "alerts": alerts,
            "total": total,
            "limit": limit,
            "offset": offset
        }

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
    """
    Return geographically enriched attacker alerts
    for the SOC Attack Map.
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

        return rows_to_dicts(cursor.fetchall())

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

        return rows_to_dicts(cursor.fetchall())

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

        return rows_to_dicts(cursor.fetchall())

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

        return rows_to_dicts(cursor.fetchall())

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
        "metrics": get_dashboard_metrics(),

        "incidents": get_incident_dashboard_metrics(),

        "severity": get_alerts_by_severity(),

        "risk": get_risk_distribution(),

        "alert_types": get_alert_type_distribution(),

        "daily_alerts": get_daily_alerts(),

        "top_attackers": get_top_attacker_ips(),

        "top_countries": get_top_threat_countries(),

        "recent_critical": get_recent_critical_alerts(),

        "threat_map": get_threat_map_data(),

        "threat_map_summary": get_threat_map_summary()
    }

# ==========================================================
# REPORTING
# ==========================================================

def export_incidents():

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

        return rows_to_dicts(
            cursor.fetchall()
        )

    finally:
        conn.close()


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