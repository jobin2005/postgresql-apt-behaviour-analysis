"""
user_profile_builder.py
----------------------
Builds/updates apt_user_profile from apt_sessions.
"""

import psycopg2
import os 

# ─────────────────────────────────────────────
# DB CONNECTION
# ─────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5433"),
        database=os.getenv("DB_NAME", "postgres"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres")
    )

# ─────────────────────────────────────────────
# UPDATE USER PROFILES
# ─────────────────────────────────────────────
def update_user_profiles(conn):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO apt_user_profile (
                user_id,
                avg_queries_per_session,
                avg_rows_accessed,
                avg_session_duration,
                normal_tables_accessed
            )
            SELECT
                 user_id,
                 ROUND(AVG(query_count)::numeric, 2),
                 ROUND(AVG(total_rows_accessed)::numeric, 2),
                 ROUND(AVG(session_duration)::numeric, 2),
                 ROUND(AVG(unique_tables)::numeric, 2)
            FROM apt_sessions
            GROUP BY user_id
            ON CONFLICT (user_id)
            DO UPDATE SET
                avg_queries_per_session = EXCLUDED.avg_queries_per_session,
                avg_rows_accessed = EXCLUDED.avg_rows_accessed,
                avg_session_duration = EXCLUDED.avg_session_duration,
                normal_tables_accessed = EXCLUDED.normal_tables_accessed;
        """)
    conn.commit()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def run_builder():
    conn = get_conn()
    update_user_profiles(conn)
    conn.close()
    print("User profiles updated successfully.")


if __name__ == "__main__":
    run_builder()