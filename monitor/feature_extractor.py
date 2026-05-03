"""
feature_extractor.py (FINAL - SESSION BASED)
-------------------------------------------
Creates a state vector from apt_sessions + user_profile + sequence_patterns
"""

import psycopg2
import numpy as np


# ─────────────────────────────────────────────
# DB CONNECTION
# ─────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        host="localhost",
        port=5433,
        database="postgres",
        user="postgres",
        password="postgres"
    )


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
        return (10, 1000, 60)

    return row


# ─────────────────────────────────────────────
# FETCH SEQUENCE RISK (OPTIONAL)
# ─────────────────────────────────────────────
def fetch_sequence_risk(conn, session_id):
    """
    Simple version:
    Match most recent 3 query types
    """

    with conn.cursor() as cur:
        cur.execute("""
            SELECT query_type
            FROM apt_events
            WHERE session_id = %s
            ORDER BY event_time DESC
            LIMIT 3
        """, (session_id,))

        rows = cur.fetchall()

    if len(rows) < 3:
        return 0.0

    seq = "->".join(r[0].upper() for r in reversed(rows))

    with conn.cursor() as cur:
        cur.execute("""
            SELECT risk_score
            FROM apt_sequence_patterns
            WHERE sequence = %s
        """, (seq,))
        res = cur.fetchone()

    return res[0] if res else 0.0


# ─────────────────────────────────────────────
# COMPUTE ANOMALY (SESSION vs BASELINE)
# ─────────────────────────────────────────────
def compute_anomaly(session, profile):
    avg_q, avg_rows, avg_dur = profile

    dq = abs(session["query_count"] - avg_q) / (avg_q + 1)
    dr = abs(session["total_rows"] - avg_rows) / (avg_rows + 1)
    dd = abs(session["duration"] - avg_dur) / (avg_dur + 1)

    return min((dq + dr + dd) / 3, 1.0)


# ─────────────────────────────────────────────
# MAIN FEATURE EXTRACTION
# ─────────────────────────────────────────────
def extract_state(conn, session):
    """
    session: dict from apt_sessions
    """

    user_id = session["user_id"]

    # baseline
    profile = fetch_user_profile(conn, user_id)

    # anomaly
    anomaly = compute_anomaly(session, profile)

    # sequence risk
    seq_risk = fetch_sequence_risk(conn, session["session_id"])

    # final state vector
    state = np.array([
        session["query_count"],
        session["failed_query_count"],
        session["total_rows"],
        session["duration"],
        session["unique_tables"],
        anomaly,
        seq_risk
    ], dtype=np.float32)

    return state


def state_dim():
    return 7