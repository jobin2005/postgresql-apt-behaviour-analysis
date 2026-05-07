"""
simulate_apt.py
---------------
Injects synthetic APT attack sequences and benign workloads into the
apt_sessions / apt_events tables.

Compatible with your CURRENT schema.

Usage:
    python simulate_apt.py
    python simulate_apt.py --sessions 100 --apt-ratio 0.3 --live
"""

import os
import random
import argparse
from datetime import datetime, timedelta, timezone

import psycopg2
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# DB Connection
# ─────────────────────────────────────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5433"),
        database=os.getenv("DB_NAME", "postgres"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Attack Profiles
# ─────────────────────────────────────────────────────────────────────────────
APT_STAGES = {
    "recon": [
        ("SELECT", "users", 50),
        ("SELECT", "roles", 120),
        ("SELECT", "sessions", 10),
    ],

    "lateral_movement": [
        ("SELECT", "auth_tokens", 5),
        ("UPDATE", "users", 1),
        ("SELECT", "admin_logs", 15),
    ],

    "privilege_escalation": [
        ("ALTER", "roles", 0),
        ("GRANT", "permissions", 0),
        ("CREATE", "backdoor_role", 0),
    ],

    "exfiltration": [
        ("SELECT", "credit_cards", 50000),
        ("SELECT", "personal_data", 80000),
        ("COPY", "financial_records", 40000),
    ],
}


BENIGN_EVENTS = [
    ("SELECT", "products", 10),
    ("SELECT", "orders", 25),
    ("INSERT", "orders", 1),
    ("UPDATE", "inventory", 3),
    ("SELECT", "customers", 7),
    ("DELETE", "sessions", 1),
    ("SELECT", "reports", 15),
]

USERS = [
    "alice",
    "bob",
    "charlie",
    "dave",
    "eve_attacker",
]


# ─────────────────────────────────────────────────────────────────────────────
# Session Insert
# ─────────────────────────────────────────────────────────────────────────────
def _insert_session(cur, user, base_time):
    cur.execute(
        """
        INSERT INTO apt_sessions (
            user_id,
            start_time
        )
        VALUES (%s, %s)
        RETURNING session_id
        """,
        (
            user,
            base_time,
        ),
    )

    return cur.fetchone()[0]


# ─────────────────────────────────────────────────────────────────────────────
# Event Insert
# ─────────────────────────────────────────────────────────────────────────────
def _insert_event(
    cur,
    session_id,
    user,
    cmd,
    table_name,
    rows,
    ts,
    success=True,
):
    """
    Insert one synthetic event into apt_events.
    """

    # Simulated SQL text
    query_text = f"{cmd} FROM {table_name}"

    # Random duration
    duration = round(random.uniform(1.0, 300.0), 2)

    # Simulated IP
    ip_addr = f"192.168.1.{random.randint(1,254)}"

    cur.execute(
        """
        INSERT INTO apt_events (
            session_id,
            user_id,
            query_type,
            query_text,
            table_names,
            event_time,
            duration_ms,
            rows_accessed,
            success_flag,
            error_code,
            ip_address
        )
        VALUES (
            %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
        )
        """,
        (
            session_id,
            user,
            cmd,
            query_text,
            [table_name],
            ts,
            duration,
            rows,
            success,
            None if success else "SIM_ERROR",
            ip_addr,
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Benign Sessions
# ─────────────────────────────────────────────────────────────────────────────
def simulate_benign(conn, n=20, live=False):

    with conn:
        with conn.cursor() as cur:

            for _ in range(n):

                user = random.choice(USERS[:4])

                base = datetime.now(tz=timezone.utc)

                if not live:
                    base -= timedelta(hours=random.randint(1, 48))

                sid = _insert_session(cur, user, base)

                num_events = random.randint(3, 25)

                for j in range(num_events):

                    cmd, table_name, rows = random.choice(BENIGN_EVENTS)

                    ts = base + timedelta(
                        seconds=j * random.randint(5, 120)
                    )

                    _insert_event(
                        cur,
                        sid,
                        user,
                        cmd,
                        table_name,
                        rows,
                        ts,
                        success=True,
                    )

    print(f"[Simulator] Inserted {n} benign sessions.")


# ─────────────────────────────────────────────────────────────────────────────
# APT Sessions
# ─────────────────────────────────────────────────────────────────────────────
def simulate_apt(conn, n=10, live=False):

    with conn:
        with conn.cursor() as cur:

            for _ in range(n):

                user = "eve_attacker"

                base = datetime.now(tz=timezone.utc)

                if not live:
                    base -= timedelta(hours=random.randint(1, 72))

                sid = _insert_session(cur, user, base)

                stages = [
                    "recon",
                    "lateral_movement",
                    "privilege_escalation",
                    "exfiltration",
                ]

                # Some attacks partial
                if random.random() < 0.3:
                    stages = stages[: random.randint(1, 2)]

                offset_sec = 0

                for stage in stages:

                    offset_sec += random.randint(300, 3600)

                    # Add noise
                    noise_count = random.randint(0, 3)

                    for _ in range(noise_count):

                        cmd, table_name, rows = random.choice(BENIGN_EVENTS)

                        ts = base + timedelta(seconds=offset_sec)

                        offset_sec += random.randint(10, 60)

                        _insert_event(
                            cur,
                            sid,
                            user,
                            cmd,
                            table_name,
                            rows,
                            ts,
                            success=True,
                        )

                    # Actual attack stage
                    for cmd, table_name, rows in APT_STAGES[stage]:

                        ts = base + timedelta(seconds=offset_sec)

                        offset_sec += random.randint(30, 600)

                        # Attackers may fail commands sometimes
                        success = random.random() > 0.15

                        _insert_event(
                            cur,
                            sid,
                            user,
                            cmd,
                            table_name,
                            rows,
                            ts,
                            success=success,
                        )

    print(f"[Simulator] Inserted {n} APT sessions.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():

    parser = argparse.ArgumentParser(
        description="APT Behaviour Simulator"
    )

    parser.add_argument(
        "--sessions",
        type=int,
        default=50,
    )

    parser.add_argument(
        "--apt-ratio",
        type=float,
        default=0.3,
    )

    parser.add_argument(
        "--live",
        action="store_true",
    )

    args = parser.parse_args()

    n_apt = max(1, int(args.sessions * args.apt_ratio))
    n_benign = args.sessions - n_apt

    conn = get_conn()

    try:

        simulate_benign(
            conn,
            n=n_benign,
            live=args.live,
        )

        simulate_apt(
            conn,
            n=n_apt,
            live=args.live,
        )

        print(
            f"[Simulator] Done. "
            f"Total={args.sessions} "
            f"benign={n_benign} "
            f"apt={n_apt}"
        )

    finally:
        conn.close()


if __name__ == "__main__":
    main()