from app.database.connection import get_connection


try:
    conn = get_connection()

    print("PostgreSQL connection successful!")

    conn.close()

except Exception as e:
    print("Connection failed:")
    print(e)