import psycopg2
import time

def run_attack():
    try:
        conn = psycopg2.connect(
            dbname="university", user="postgres", password="postgres",
            host="db", port=5432
        )
        cur = conn.cursor()
        print("ULTRA-Noisy attack session started...")

        # Phase 1: Mass bulk SELECT across all high-value tables — simulates
        # a full database dump attempt (PII, financial data, admin users)
        sensitive_tables = [
            "students",
            "student_records",
            "financial_records",
            "system_users",
            "faculty",
        ]
        for _ in range(100):
            table = sensitive_tables[_ % len(sensitive_tables)]
            cur.execute(f"SELECT * FROM {table} LIMIT 1000;")

        # Phase 2: Probe for hidden / privileged tables that don't exist —
        # simulates an attacker mapping the schema after initial access
        for i in range(30):
            try:
                cur.execute(f"SELECT * FROM table_{i}_not_exists;")
            except:
                conn.rollback()

        # Phase 3: DDL churn — simulates privilege abuse or schema manipulation
        # (CREATE + DROP in quick succession to test write permissions)
        for i in range(20):
            try:
                cur.execute(f"CREATE TABLE dummy_{i} (id int); DROP TABLE dummy_{i};")
            except:
                conn.rollback()

        time.sleep(10)
        conn.commit()
        conn.close()
        print("ULTRA-Noisy attack session complete.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run_attack()