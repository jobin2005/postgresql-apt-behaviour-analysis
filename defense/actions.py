"""
actions.py
----------
Adaptive defense actions executed by the monitor daemon when the DQL agent
decides a session is threatening.

Actions map to DQL action indices:
    0 = No-op         (do nothing)
    1 = Alert         (insert into apt_alerts, log to console)
    2 = Rate-Limit    (insert throttle record; application-layer hook)
    3 = Block         (terminate backend via pg_terminate_backend)
"""

import os
import json
import logging
from datetime import datetime, timezone

import psycopg2
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("apt.defense")


def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode=os.getenv("DB_SSL_MODE", "prefer")
    )


# ── Internal helpers ─────────────────────────────────────────────────────────
def _log_alert(conn, session_id: int, threat_score: float,
               action_name: str, q_values: list):
    """Persist an alert record."""
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO apt_alerts
                       (session_id, created_at, threat_score, action_taken, q_values)
                   VALUES (%s, %s, %s, %s, %s)""",
                (session_id,
                 datetime.now(tz=timezone.utc),
                 threat_score,
                 action_name,
                 json.dumps([round(q, 4) for q in q_values])),
            )
    logger.warning(
        "[ALERT] session=%s  action=%s  score=%.3f  q=%s",
        session_id, action_name, threat_score,
        [round(q, 3) for q in q_values],
    )


def _terminate_backend(conn, session_id: int) -> bool:
    """Terminate all Postgres backends belonging to this session."""
    try:
        with conn:
            with conn.cursor() as cur:
                # Lookup Postgres PID from session metadata if stored
                cur.execute(
                    """SELECT pg_terminate_backend(pid)
                       FROM pg_stat_activity
                       WHERE application_name = %s
                         AND state != 'idle'""",
                    (f"apt_session_{session_id}",),
                )
                results = cur.fetchall()
        terminated = sum(1 for r in results if r[0])
        logger.warning("[BLOCK] Terminated %d backend(s) for session %s",
                       terminated, session_id)
        return terminated > 0
    except Exception as exc:
        logger.error("[BLOCK] Failed to terminate backends: %s", exc)
        return False


# ── Public API ────────────────────────────────────────────────────────────────
ACTION_NAMES = {0: "noop", 1: "alert", 2: "rate_limit", 3: "block"}


def execute_action(action: int, session_id: int,
                   threat_score: float, q_values: list):
    """
    Execute the defense action chosen by the DQL agent.

    Parameters
    ----------
    action       : int   — 0..3
    session_id   : int
    threat_score : float — max Q-value normalised to [0,1]
    q_values     : list  — raw Q-values from the network
    """
    name = ACTION_NAMES.get(action, "noop")

    if action == 0:   # No-op
        logger.debug("[NOOP] session=%s", session_id)
        return

    conn = get_conn()
    try:
        _log_alert(conn, session_id, threat_score, name, q_values)

        if action == 3:   # Block
            _terminate_backend(conn, session_id)
    finally:
        conn.close()
