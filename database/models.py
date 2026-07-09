from database.database import create_connection


def create_alerts_table():
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        alert_id TEXT UNIQUE NOT NULL,

        alert_type TEXT NOT NULL,

        severity TEXT NOT NULL,

        source_ip TEXT NOT NULL,

        attacker_ip TEXT,

        risk_score INTEGER DEFAULT 0,

        risk_level TEXT,

        action_taken TEXT DEFAULT 'Pending',

        status TEXT DEFAULT 'NEW',

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    )
    """)

    conn.commit()
    conn.close()


def create_incidents_table():
    conn = create_connection()
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

        analyst_notes TEXT,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        resolved_at TIMESTAMP,

        CONSTRAINT fk_alert
        FOREIGN KEY (alert_id)
        REFERENCES alerts(alert_id)
        ON DELETE CASCADE

    )
    """)

    conn.commit()
    conn.close()