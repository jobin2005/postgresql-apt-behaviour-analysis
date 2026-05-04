"""
session_builder.py (IMPROVED)
----------------------------
Sliding window session builder with:
- privilege escalation detection
- anomaly score using user profile
"""

import psycopg2
from collections import defaultdict

from datetime import timedelta
import os

WINDOW_SIZE = 10
TIME_THRESHOLD = timedelta(minutes=5)


# ─────────────────────────────────────────────
# DB CONNECTION
# ─────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        database=os.getenv("DB_NAME", "university"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres")
    )


# ─────────────────────────────────────────────
# FETCH EVENTS
# ─────────────────────────────────────────────
def fetch_events(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT user_id, event_time, query_type,
                   query_text, rows_accessed,
                   success_flag, table_names
            FROM apt_events
            ORDER BY user_id, event_time
        """)
        rows = cur.fetchall()

    events_by_user = defaultdict(list)

    for r in rows:
        events_by_user[r[0]].append({
            "time": r[1],
            "type": r[2],
            "query": r[3] or "",
            "rows": r[4] or 0,
            "success": r[5],
            "tables": r[6] or []
        })

    return events_by_user


# ─────────────────────────────────────────────
# SESSIONS CREATION 
# ─────────────────────────────────────────────
def build_sessions(events):
    sessions = []
    current_session = []

    for ev in events:
        if not current_session:
            current_session.append(ev)
            continue

        last_event = current_session[-1]
        time_gap = ev["time"] - last_event["time"]

        # 🔥 HYBRID CONDITION
        if len(current_session) >= WINDOW_SIZE or time_gap > TIME_THRESHOLD:
            sessions.append(current_session)
            current_session = [ev]
        else:
            current_session.append(ev)

    if current_session:
        sessions.append(current_session)

    return sessions


# ─────────────────────────────────────────────
# PRIVILEGE ESCALATION DETECTION
# ─────────────────────────────────────────────
def detect_privilege_escalation(session):
    keywords = ["GRANT", "ALTER ROLE", "CREATE ROLE", "SET ROLE"]

    for e in session:
        q = (e["query"] or "").upper()
        t = (e["type"] or "").upper()

        if any(k in q for k in keywords) or t in keywords:
            return True

    return False


# ─────────────────────────────────────────────
# FETCH USER PROFILE
# ─────────────────────────────────────────────
def fetch_user_profile(conn, user_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT avg_queries_per_session,
                   avg_rows_accessed,
                   avg_session_duration
            FROM apt_user_profile
            WHERE user_id = %s
        """, (user_id,))
        row = cur.fetchone()

    if not row:
        return {
            "avg_q": 10,
            "avg_rows": 1000,
            "avg_duration": 60
        }

    return {
        "avg_q": row[0] or 10,
        "avg_rows": row[1] or 1000,
        "avg_duration": row[2] or 60
    }


# ─────────────────────────────────────────────
# ANOMALY SCORE
# ─────────────────────────────────────────────
def compute_anomaly(session, profile):
    query_count = len(session)
    total_rows = sum(e["rows"] for e in session)
    duration = (session[-1]["time"] - session[0]["time"]).total_seconds()

    # deviation ratios
    dq = abs(query_count - profile["avg_q"]) / (profile["avg_q"] + 1)
    dr = abs(total_rows - profile["avg_rows"]) / (profile["avg_rows"] + 1)
    dd = abs(duration - profile["avg_duration"]) / (profile["avg_duration"] + 1)

    return min((dq + dr + dd) / 3, 1.0)


# ─────────────────────────────────────────────
# COMPUTE SESSION FEATURES
# ─────────────────────────────────────────────
def compute_features(conn, user_id, session):
    start = session[0]["time"]
    end = session[-1]["time"]

    query_count = len(session)
    failed = sum(1 for e in session if not e["success"])
    total_rows = sum(e["rows"] for e in session)

    all_tables = [t for e in session for t in e["tables"]]
    unique_tables = len(set(all_tables))

    duration = (end - start).total_seconds()

    privilege_flag = detect_privilege_escalation(session)

    profile = fetch_user_profile(conn, user_id)
    anomaly_score = compute_anomaly(session, profile)

    return {
        "user_id": user_id,
        "start": start,
        "end": end,
        "query_count": query_count,
        "failed": failed,
        "total_rows": total_rows,
        "unique_tables": unique_tables,
        "duration": duration,
        "privilege_flag": privilege_flag,
        "anomaly_score": anomaly_score
    }


# ─────────────────────────────────────────────
# INSERT SESSION
# ─────────────────────────────────────────────
def insert_session(conn, data):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO apt_sessions (
                user_id, start_time, end_time,
                query_count, failed_query_count,
                total_rows_accessed, unique_tables,
                privilege_escalation_flag,
                anomaly_score, session_duration
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data["user_id"],
            data["start"],
            data["end"],
            data["query_count"],
            data["failed"],
            data["total_rows"],
            data["unique_tables"],
            data["privilege_flag"],
            data["anomaly_score"],
            data["duration"]
        ))
    conn.commit()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def run_builder():
    conn = get_conn()
    events_by_user = fetch_events(conn)

    for user, events in events_by_user.items():
        sessions = build_sessions(events)

        for s in sessions:
            data = compute_features(conn, user, s)
            insert_session(conn, data)

    conn.close()


if __name__ == "__main__":
    run_builder()