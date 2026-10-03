from app.database.connection import get_connection


def log_security_event(prompt, result):
    conn = get_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO security_logs (
                    prompt,
                    is_malicious,
                    detection_source,
                    ml_prediction,
                    ml_confidence,
                    risk_score,
                    severity,
                    action,
                    reasons
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    prompt,
                    result["is_malicious"],
                    result["detection_source"],
                    result["ml_prediction"],
                    result["ml_confidence"],
                    result["risk_score"],
                    result["severity"],
                    result["action"],
                    " | ".join(result["reasons"])
                )
            )

        conn.commit()

    finally:
        conn.close()