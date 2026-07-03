def save_alert(alert):

    print("========== SAVE ALERT ==========")
    print(alert)

    conn = create_connection()
    cursor = conn.cursor()

    try:

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

        print("✅ Saved successfully!")

    except Exception as e:

        print("❌ Database Error:", e)

    finally:

        conn.close()