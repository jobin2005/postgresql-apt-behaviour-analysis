"""
actions.py
----------
Adaptive defense actions executed by the monitor daemon when the DQL agent
decides a session is threatening.

Actions map to DQL action indices:
    0 = No-op         (do nothing)
    1 = Alert         (insert into apt_alerts, log to console)
    2 = Rate-Limit    (insert throttle record into apt_rate_limits)
    3 = Block         (terminate backend via pg_terminate_backend)
"""

import os
import logging
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras   # needed for JSONB support
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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _threat_level(score: float) -> str:
    """Convert a numeric threat score to a human-readable level for apt_alerts."""
    if score >= 0.8:
        return "critical"
    elif score >= 0.6:
        return "high"
    elif score >= 0.4:
        return "medium"
    return "low"


def _log_alert(conn, session_id: int, threat_score: float,
               action_name: str, q_values: list):
    """
    Persist an alert record to apt_alerts.
    q_values is stored as JSONB — pass the list directly, psycopg2 serialises it.
    threat_level is derived from threat_score to fill the new column.
    """
    level = _threat_level(threat_score)
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO apt_alerts
                       (session_id, created_at, threat_score, threat_level,
                        action_taken, q_values)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    session_id,
                    datetime.now(tz=timezone.utc),
                    threat_score,
                    level,
                    action_name,
                    psycopg2.extras.Json([round(q, 4) for q in q_values]),
                ),
            )
    logger.warning(
        "[ALERT] session=%s  action=%s  level=%s  score=%.3f  q=%s",
        session_id, action_name, level, threat_score,
        [round(q, 3) for q in q_values],
    )


def _send_notification(session_id: int, threat_score: float, channel: str = "log"):
    """
    Send an out-of-band threat notification.
    Currently logs to console. Extend to Slack/email/webhook as needed.
    """
    logger.warning(
        "[THREAT NOTIFICATION] session=%s  score=%.3f  channel=%s",
        session_id, threat_score, channel,
    )
    # TODO: add Slack webhook / email / SIEM integration here


def _rate_limit_session(conn, session_id: int, max_qps: int = 5):
    """
    Upsert a rate-limit record for this session and tag it as suspicious.
    Requires apt_rate_limits.session_id to have a UNIQUE constraint — see schema note.
    """
    with conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO apt_rate_limits (session_id, max_qps, active)
                   VALUES (%s, %s, TRUE)
                   ON CONFLICT (session_id) DO UPDATE
                       SET active  = TRUE,
                           max_qps = EXCLUDED.max_qps""",
                (session_id, max_qps),
            )
            # Tag session as suspicious so analysts can filter it
            cur.execute(
                "UPDATE apt_sessions SET threat_label = 1 WHERE session_id = %s",
                (session_id,),
            )
    logger.warning("[RATE-LIMIT] session=%s capped at %d QPS", session_id, max_qps)


def _terminate_backend(conn, session_id: int) -> bool:
    """
    Terminate all active Postgres backends for this session.
    Looks up user_id + client_addr from apt_sessions (matches new schema).
    """
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id, client_addr FROM apt_sessions WHERE session_id = %s",
                    (session_id,),
                )
                row = cur.fetchone()
                if not row:
                    logger.warning("[BLOCK] session=%s not found in apt_sessions", session_id)
                    return False

                user_id, client_addr = row

                cur.execute(
                    """SELECT pg_terminate_backend(pid)
                       FROM pg_stat_activity
                       WHERE usename     = %s
                         AND client_addr = %s
                         AND state      != 'idle'""",
                    (user_id, client_addr),
                )
                results = cur.fetchall()

        terminated = sum(1 for r in results if r[0])
        logger.warning(
            "[BLOCK] Terminated %d backend(s) for session=%s user=%s",
            terminated, session_id, user_id,
        )
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
        # Every non-noop action logs an alert record
        _log_alert(conn, session_id, threat_score, name, q_values)

        if action == 1:   # Alert — also send out-of-band notification
            _send_notification(session_id, threat_score, channel="log")

        elif action == 2:   # Rate-Limit
            _rate_limit_session(conn, session_id, max_qps=5)

        elif action == 3:   # Block
            _terminate_backend(conn, session_id)

    finally:
        conn.close()