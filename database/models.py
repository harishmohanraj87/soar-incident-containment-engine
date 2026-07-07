from database.database import create_connection


def create_alerts_table():
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        alert_id TEXT UNIQUE,

        alert_type TEXT,

        severity TEXT,

        source_ip TEXT,

        attacker_ip TEXT,

        risk_score INTEGER,

        risk_level TEXT,

        action_taken TEXT,

        status TEXT,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    )
    """)

    conn.commit()
    conn.close()