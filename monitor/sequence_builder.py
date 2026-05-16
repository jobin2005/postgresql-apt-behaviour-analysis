"""
sequence_builder.py
-------------------
Builds sequence patterns from apt_events and stores them in apt_sequence_patterns.
"""

import psycopg2
from collections import defaultdict, Counter
import os

WINDOW_SIZE = 3   # length of sequence (can tune later)


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
            SELECT user_id, event_time, query_type
            FROM apt_events
            ORDER BY user_id, event_time
        """)
        rows = cur.fetchall()

    events_by_user = defaultdict(list)

    for r in rows:
        events_by_user[r[0]].append({
            "time": r[1],
            "type": (r[2] or "OTHER").upper()
        })

    return events_by_user


# ─────────────────────────────────────────────
# BUILD SEQUENCES (SLIDING WINDOW)
# ─────────────────────────────────────────────
def build_sequences(events):
    sequences = []

    for i in range(len(events) - WINDOW_SIZE + 1):
        window = events[i:i + WINDOW_SIZE]
        seq = "->".join(e["type"] for e in window)
        sequences.append(seq)

    return sequences


# ─────────────────────────────────────────────
# ASSIGN RISK SCORE
# ─────────────────────────────────────────────
def compute_risk(sequence):
    """
    Simple heuristic:
    - GRANT / ALTER / CREATE ROLE → high risk
    - DELETE → medium risk
    - Others → low risk
    """

    seq = sequence.upper()

    if "GRANT" in seq or "ALTER" in seq or "CREATE ROLE" in seq:
        return 0.9
    elif "DELETE" in seq:
        return 0.6
    else:
        return 0.2


# ─────────────────────────────────────────────
# STORE SEQUENCES
# ─────────────────────────────────────────────
def insert_sequences(conn, sequence_counts):
    with conn.cursor() as cur:
        for seq, freq in sequence_counts.items():
            risk = compute_risk(seq)

            cur.execute("""
                INSERT INTO apt_sequence_patterns (sequence, frequency, risk_score)
                VALUES (%s, %s, %s)
                ON CONFLICT (sequence)
                DO UPDATE SET
                    frequency = apt_sequence_patterns.frequency + EXCLUDED.frequency,
                    risk_score = EXCLUDED.risk_score
            """, (seq, freq, risk))

    conn.commit()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def run_builder():
    conn = get_conn()

    events_by_user = fetch_events(conn)
    all_sequences = []

    for user, events in events_by_user.items():
        seqs = build_sequences(events)
        all_sequences.extend(seqs)

    # Count frequency
    sequence_counts = Counter(all_sequences)

    insert_sequences(conn, sequence_counts)

    conn.close()
    print("Sequence patterns updated successfully.")


if __name__ == "__main__":
    run_builder()