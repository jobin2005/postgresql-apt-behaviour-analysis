import psycopg2

def run_attack():
    try:
        conn = psycopg2.connect(
            dbname="university", user="postgres", password="postgres",
            host="db", port=5432
        )
        cur = conn.cursor()
        print("Noisy attack session started...")

        # Phase 1: Bulk recon on student PII — simulates low-and-slow exfiltration
        for i in range(50):
            cur.execute("SELECT * FROM students LIMIT 1000;")

        # Phase 2: Probe for tables that shouldn't be accessible
        for i in range(15):
            try:
                cur.execute(f"SELECT * FROM access_fail_{i};")
            except:
                conn.rollback()

        conn.commit()
        conn.close()
        print("Noisy attack session complete.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run_attack()