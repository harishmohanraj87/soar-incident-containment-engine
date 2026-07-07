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