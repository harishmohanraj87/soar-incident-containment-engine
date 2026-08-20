from database.database import create_connection


# ==========================================================
# ALERTS TABLE
# ==========================================================

def create_alerts_table():
    """
    Create the alerts table.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_id TEXT UNIQUE NOT NULL,

            alert_type TEXT NOT NULL,

            severity TEXT NOT NULL,

            source_ip TEXT,

            attacker_ip TEXT,

            risk_score INTEGER DEFAULT 0,

            risk_level TEXT DEFAULT 'LOW',

            action_taken TEXT DEFAULT 'Pending',

            status TEXT DEFAULT 'NEW',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        conn.commit()

    finally:
        conn.close()


# ==========================================================
# INCIDENTS TABLE
# ==========================================================

def create_incidents_table():
    """
    Create the incidents table.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT UNIQUE NOT NULL,

            alert_id TEXT NOT NULL,

            title TEXT NOT NULL,

            priority TEXT DEFAULT 'P3',

            incident_status TEXT DEFAULT 'NEW',

            assigned_to TEXT DEFAULT 'Unassigned',

            analyst_notes TEXT DEFAULT '',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            resolved_at TIMESTAMP,

            FOREIGN KEY (alert_id)
            REFERENCES alerts(alert_id)
            ON DELETE CASCADE
        )
        """)

        conn.commit()

    finally:
        conn.close()


# ==========================================================
# INCIDENT ACTIVITY TABLE
# ==========================================================

def create_incident_activity_table():
    """
    Create the incident activity table.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_activity (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT NOT NULL,

            activity_type TEXT NOT NULL,

            activity TEXT NOT NULL,

            performed_by TEXT DEFAULT 'System',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (incident_id)
            REFERENCES incidents(incident_id)
            ON DELETE CASCADE
        )
        """)

        conn.commit()

    finally:
        conn.close()


# ==========================================================
# USERS TABLE
# ==========================================================

def create_users_table():
    """
    Create the users table.
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            full_name TEXT NOT NULL,

            role TEXT NOT NULL DEFAULT 'ANALYST',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        conn.commit()

    finally:
        conn.close()


# ==========================================================
# INITIALIZE ALL DATABASE TABLES
# ==========================================================

def initialize_database():
    """
    Initialize all required SOAR database tables.

    Order is important because some tables
    contain foreign key relationships.
    """

    create_alerts_table()

    create_incidents_table()

    create_incident_activity_table()

    create_users_table()

    print(
        "SOAR database initialized successfully."
    )