"""
simulate_apt.py
---------------
Injects synthetic APT attack sequences and benign workloads into the
apt_sessions / apt_events tables to generate labelled training data.

Usage:
    python data/simulate_apt.py [--sessions N] [--apt-ratio 0.3]
"""

import os
import sys
import time
import random
import argparse
import hashlib
from datetime import datetime, timedelta, timezone

import psycopg2
from dotenv import load_dotenv

load_dotenv()

# ── DB connection ────────────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode=os.getenv("DB_SSL_MODE", "prefer")
    )


# ── APT Stage Definitions ────────────────────────────────────────────────────
# Each stage is a list of (command_type, object_schema, object_name, rows)

APT_STAGES = {
    "recon": [
        ("SELECT", "information_schema", "tables", 50),
        ("SELECT", "information_schema", "columns", 120),
        ("SELECT", "pg_catalog", "pg_user", 10),
        ("SELECT", "pg_catalog", "pg_roles", 10),
        ("SELECT", "public", "users", 5),
    ],
    "lateral_movement": [
        ("SELECT", "public", "sessions", 3),
        ("SELECT", "public", "auth_tokens", 2),
        ("UPDATE", "public", "users", 1),
        ("SELECT", "public", "admin_logs", 8),
    ],
    "privilege_escalation": [
        ("ALTER ROLE", "pg_catalog", "pg_roles", 0),
        ("GRANT", "public", "users", 0),
        ("CREATE", "public", "backdoor_role", 0),
    ],
    "exfiltration": [
        ("SELECT", "public", "credit_cards", 50000),
        ("SELECT", "public", "personal_data", 80000),
        ("COPY", "public", "credit_cards", 50000),
        ("SELECT", "public", "salaries", 30000),
    ],
}

BENIGN_EVENTS = [
    ("SELECT", "public", "products", 10),
    ("SELECT", "public", "orders", 25),
    ("INSERT", "public", "orders", 1),
    ("UPDATE", "public", "inventory", 3),
    ("SELECT", "public", "customers", 7),
    ("DELETE", "public", "sessions", 1),
    ("SELECT", "public", "reports", 15),
]

USERS = ["alice", "bob", "charlie", "dave", "eve_attacker"]


def _hash_query(cmd, schema, obj, high_entropy=False):
    """Generate query hash with controllable entropy level."""
    raw = f"{cmd}|{schema}|{obj}"
    if high_entropy:
        # APT: add randomness to simulate obfuscated / injected SQL
        raw += f"|{random.randint(0, 999999)}|{random.random()}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _insert_session(cur, user, label, base_time):
    cur.execute(
        """INSERT INTO apt_sessions (user_name, client_addr, start_time, threat_label)
           VALUES (%s, %s, %s, %s) RETURNING session_id""",
        (user, "192.168.1." + str(random.randint(1, 254)), base_time, label),
    )
    return cur.fetchone()[0]


def _insert_event(cur, session_id, cmd, schema, obj, rows, ts, high_entropy=False):
    """Insert an event with entropy-aware hash and realistic duration."""
    if high_entropy:
        # APT tools run fast automated queries
        duration = round(random.uniform(0.1, 5.0), 2)
    else:
        # Normal users have moderate query times
        duration = round(random.uniform(20.0, 500.0), 2)

    cur.execute(
        """INSERT INTO apt_events
               (session_id, event_time, command_type, object_schema, object_name,
                rows_affected, query_hash, duration_ms)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (session_id, ts, cmd, schema, obj, rows,
         _hash_query(cmd, schema, obj, high_entropy=high_entropy),
         duration),
    )


def simulate_benign(conn, n=20, live=False):
    """Insert n benign sessions with varied lengths."""
    with conn:
        with conn.cursor() as cur:
            for _ in range(n):
                user = random.choice(USERS[:4])
                base = datetime.now(tz=timezone.utc)
                if not live:
                    base -= timedelta(hours=random.randint(1, 48))
                
                sid = _insert_session(cur, user, 0, base)
                # Varied session length (3 to 25 events)
                num_events = random.randint(3, 25)
                for j in range(num_events):
                    cmd, schema, obj, rows = random.choice(BENIGN_EVENTS)
                    # Random time gaps (5s to 120s)
                    ts = base + timedelta(seconds=j * random.randint(5, 120))
                    _insert_event(cur, sid, cmd, schema, obj, rows, ts, high_entropy=False)
    print(f"[Simulator] Inserted {n} benign sessions with varied lengths.")


def simulate_apt(conn, n=7, live=False):
    """Insert n multi-stage APT sessions with noise and partial completion."""
    with conn:
        with conn.cursor() as cur:
            for i in range(n):
                user = "eve_attacker"
                base = datetime.now(tz=timezone.utc)
                if not live:
                    base -= timedelta(hours=random.randint(1, 72))
                
                # Some attacks are caught early or failed (Label 1 = suspicious, 2 = confirmed APT)
                is_partial = random.random() < 0.3
                label = 1 if is_partial else 2
                sid = _insert_session(cur, user, label, base)
                
                stages = ["recon", "lateral_movement", "privilege_escalation", "exfiltration"]
                if is_partial:
                    # Partial attacks only complete 1 or 2 stages
                    stages = stages[:random.randint(1, 2)]

                offset_sec = 0
                for stage_name in stages:
                    # APTs are slow — minutes to hours between stages
                    offset_sec += random.randint(300, 3600)
                    
                    # Randomly insert 0-3 benign "noise" events to hide the attack
                    noise_count = random.randint(0, 3)
                    for _ in range(noise_count):
                        cmd, schema, obj, rows = random.choice(BENIGN_EVENTS)
                        ts = base + timedelta(seconds=offset_sec)
                        offset_sec += random.randint(10, 60)
                        _insert_event(cur, sid, cmd, schema, obj, rows, ts, high_entropy=False)

                    # Actual attack stage events
                    for cmd, schema, obj, rows in APT_STAGES[stage_name]:
                        ts = base + timedelta(seconds=offset_sec)
                        # attackers might wait between commands too
                        offset_sec += random.randint(30, 600)
                        _insert_event(cur, sid, cmd, schema, obj, rows, ts, high_entropy=True)
                    
    print(f"[Simulator] Inserted {n} APT sessions (partials included, with added noise).")


def main():
    parser = argparse.ArgumentParser(description="APT Behaviour Simulator")
    parser.add_argument("--sessions", type=int, default=50,
                        help="Total sessions to generate (default: 50)")
    parser.add_argument("--apt-ratio", type=float, default=0.3,
                        help="Fraction of sessions that are APT (default: 0.3)")
    parser.add_argument("--live", action="store_true",
                        help="Use current timestamps for real-time monitoring")
    args = parser.parse_args()

    n_apt = max(1, int(args.sessions * args.apt_ratio))
    n_benign = args.sessions - n_apt

    conn = get_conn()
    try:
        simulate_benign(conn, n=n_benign, live=args.live)
        simulate_apt(conn, n=n_apt, live=args.live)
        print(f"[Simulator] Done. Total sessions: {args.sessions} "
              f"(benign={n_benign}, apt={n_apt})")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
