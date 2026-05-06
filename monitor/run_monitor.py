"""
monitor.py (FINAL - SESSION BASED)
---------------------------------
"""

import time
import logging
import psycopg2
import torch
import math
import os

from agent.dqn_model import DQN
from defense.actions import execute_action
from monitor.session_builder import run_builder as run_session_pipeline
from monitor.userprofile_builder import run_builder as run_profiles
from monitor.sequence_builder import run_builder as run_sequences
from monitor.feature_extractor import extract_state, state_dim

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("apt.monitor")


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
# LOAD MODEL (kept but unused for now)
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

    print("MONITOR STARTED", flush=True)
    print("MONITOR DB:", conn.get_dsn_parameters(), flush=True)

    
    # agent = load_agent("checkpoints/dqn_best.pt")

    last_pipeline_run = 0

    while True:
        print("🔁 MONITOR LOOP RUNNING", flush=True)

        # ─────────────────────────────────────────────
        # 1. RUN FULL APT PIPELINE PERIODICALLY
        # ─────────────────────────────────────────────
        if time.time() - last_pipeline_run > 10:
            print("⚡ Running session pipeline...", flush=True)

            run_session_pipeline()
            run_profiles()
            run_sequences()

            last_pipeline_run = time.time()

        # ─────────────────────────────────────────────
        # 2. FETCH SESSIONS
        # ─────────────────────────────────────────────
        sessions = fetch_sessions(conn)

        print(f" SESSIONS FOUND: {len(sessions)}", flush=True)

        for s in sessions:
            print(f"➡ Processing session: {s['session_id']}", flush=True)

            
            # state = extract_state(conn, s)
            # q_vals = agent.q_values(state)
            # action = int(max(range(len(q_vals)), key=lambda i: q_vals[i]))
            # threat = 1 / (1 + math.exp(-max(q_vals)))

            # logger.info(
            #     "session=%d action=%d threat=%.3f",
            #     s["session_id"], action, threat
            # )

            # execute_action(action, s["session_id"], threat, q_vals)

        time.sleep(5)  #  IMPORTANT (prevent CPU overload)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print(" STARTING MONITOR...", flush=True)
    run_monitor()