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
        for i in range(100):
            cur.execute("SELECT * FROM student_records LIMIT 1000;")
        for i in range(30):
            try:
                cur.execute(f"SELECT * FROM table_{i}_not_exists;")
            except:
                conn.rollback()
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
