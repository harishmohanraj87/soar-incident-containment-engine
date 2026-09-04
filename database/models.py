from database.database import create_connection


# ==========================================================
# HELPER — ADD COLUMN SAFELY
# ==========================================================

def add_column_if_not_exists(cursor, table_name, column_name, column_definition):
    """
    Add a column to an existing SQLite table if it does not exist.
    This allows safe database upgrades without deleting existing data.
    """
    cursor.execute(f"PRAGMA table_info({table_name})")

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    if column_name not in existing_columns:
        cursor.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {column_definition}
            """
        )


# ==========================================================
# ALERTS TABLE
# ==========================================================

def create_alerts_table():
    """
    Create the alerts table and safely upgrade existing databases
    with geographic threat intelligence fields.
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

            country TEXT,

            city TEXT,

            region TEXT,

            latitude REAL,

            longitude REAL,

            org TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # --------------------------------------------------
        # SAFE MIGRATION FOR EXISTING DATABASES
        # --------------------------------------------------

        add_column_if_not_exists(
            cursor,
            "alerts",
            "country",
            "TEXT"
        )

        add_column_if_not_exists(
            cursor,
            "alerts",
            "city",
            "TEXT"
        )

        add_column_if_not_exists(
            cursor,
            "alerts",
            "region",
            "TEXT"
        )

        add_column_if_not_exists(
            cursor,
            "alerts",
            "latitude",
            "REAL"
        )

        add_column_if_not_exists(
            cursor,
            "alerts",
            "longitude",
            "REAL"
        )

        add_column_if_not_exists(
            cursor,
            "alerts",
            "org",
            "TEXT"
        )

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
# PLAYBOOK APPROVALS TABLE
# ==========================================================

def create_playbook_approvals_table():
    """
    Store approval requests for high-impact SOAR actions.
    """

    conn = create_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS playbook_approvals (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            incident_id TEXT NOT NULL,

            alert_id TEXT,

            action TEXT NOT NULL,

            target TEXT NOT NULL,

            risk_score INTEGER NOT NULL,

            status TEXT NOT NULL DEFAULT 'PENDING',

            requested_by TEXT DEFAULT 'SOAR Engine',

            reviewed_by TEXT,

            reviewer_comment TEXT,

            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            reviewed_at TIMESTAMP,

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
# NOTIFICATIONS TABLE
# ==========================================================

def create_notifications_table():
    """
    Create the real-time SOC notifications table.

    Notifications are generated by security events such as:
    - HIGH / CRITICAL alerts
    - Incident creation
    - SOAR playbook execution
    - Containment actions
    """

    conn = create_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            notification_type TEXT NOT NULL,

            severity TEXT DEFAULT 'INFO',

            title TEXT NOT NULL,

            message TEXT NOT NULL,

            alert_id TEXT,

            incident_id TEXT,

            is_read INTEGER DEFAULT 0,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # --------------------------------------------------
        # PERFORMANCE INDEXES
        # --------------------------------------------------

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_is_read
        ON notifications(is_read)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_created_at
        ON notifications(created_at)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_alert_id
        ON notifications(alert_id)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_notifications_incident_id
        ON notifications(incident_id)
        """)

        conn.commit()

    finally:
        conn.close()


# ==========================================================
# INITIALIZE ALL DATABASE TABLES
# ==========================================================

def initialize_database():
    """
    Initialize and upgrade all required SOAR database tables.

    Order matters because incidents and incident activity
    depend on the alerts and incidents tables.
    """

    create_alerts_table()

    create_incidents_table()

    create_incident_activity_table()
    
    create_playbook_approvals_table()
    
    create_users_table()

    # Sprint 2 — Feature 4
    create_notifications_table()

    print(
        "SOAR database initialized and upgraded successfully."
    )
    