"""
monitor.py (FINAL - SESSION BASED)
---------------------------------
"""

import time
import logging
import psycopg2
import torch
import math

from monitor.feature_extractor import extract_state, state_dim
from agent.dqn_model import DQN
from defense.actions import execute_action


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apt.monitor")


import os
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# DB CONNECTION
# ─────────────────────────────────────────────
def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode=os.getenv("DB_SSL_MODE", "prefer")
    )


# ─────────────────────────────────────────────
# FETCH SESSIONS
# ─────────────────────────────────────────────
def fetch_sessions(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT session_id, user_id,
                   query_count, failed_query_count,
                   total_rows_accessed,
                   unique_tables,
                   session_duration
            FROM apt_sessions
        """)
        rows = cur.fetchall()

    sessions = []
    for r in rows:
        sessions.append({
            "session_id": r[0],
            "user_id": r[1],
            "query_count": r[2],
            "failed_query_count": r[3],
            "total_rows": r[4],
            "unique_tables": r[5],
            "duration": r[6]
        })

    return sessions


# ─────────────────────────────────────────────
# LOAD MODEL
# ─────────────────────────────────────────────
def load_agent(path):
    model = DQN(state_dim())
    model.load_state_dict(torch.load(path, map_location="cpu"))
    model.eval()
    return model


# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
def run_monitor():
    conn = get_conn()
    agent = load_agent("checkpoints/dqn_best.pt")

    while True:
        sessions = fetch_sessions(conn)

        for s in sessions:
            state = extract_state(conn, s)

            q_vals = agent.q_values(state)
            action = int(max(range(len(q_vals)), key=lambda i: q_vals[i]))
            threat = 1 / (1 + math.exp(-max(q_vals)))

            logger.info(
                "session=%d action=%d threat=%.3f",
                s["session_id"], action, threat
            )

            execute_action(action, s["session_id"], threat, q_vals)

        time.sleep(5)


if __name__ == "__main__":
    run_monitor()