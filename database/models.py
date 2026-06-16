from database import create_connection

def create_alerts_table():
    conn = create_connection()

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT,
        severity TEXT,
        source_ip TEXT,
        status TEXT
    )
    """)

    conn.commit()
    conn.close()