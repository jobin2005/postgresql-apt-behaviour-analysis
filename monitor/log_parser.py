"""
log_parser.py
-------------
Reads recent events from the apt_events table (or a pg_audit CSV log file)
and yields structured event dicts ready for the feature extractor.

For live monitoring the parser queries the DB directly.
For offline training it can also parse a pg_audit CSV log file.
"""

import os
import csv
import io
from datetime import datetime, timezone

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode=os.getenv("DB_SSL_MODE", "prefer")
    )


# ── DB-based ingestion ────────────────────────────────────────────────────────
def fetch_session_events(conn, session_id: int, limit: int = 50, since_id: int = 0) -> list[dict]:
    """
    Return events for a session. If since_id is given, returns events newer than that.
    Else returns the most recent `limit` events.
    """
    with conn.cursor() as cur:
        if since_id > 0:
            cur.execute(
                """SELECT event_time, command_type, object_schema, object_name,
                          rows_affected, duration_ms, query_hash, event_id
                   FROM apt_events
                   WHERE session_id = %s AND event_id > %s
                   ORDER BY event_id ASC""",
                (session_id, since_id),
            )
        else:
            cur.execute(
                """SELECT event_time, command_type, object_schema, object_name,
                          rows_affected, duration_ms, query_hash, event_id
                   FROM apt_events
                   WHERE session_id = %s
                   ORDER BY event_time DESC
                   LIMIT %s""",
                (session_id, limit),
            )
        rows = cur.fetchall()
    
    events = []
    # If using limit, rows are DESC (newest first), so we reverse to get oldest first
    # If using since_id, rows are already ASC.
    if since_id == 0:
        rows = reversed(rows)

    for row in rows:
        events.append({
            "event_time":    row[0],
            "command_type":  row[1],
            "object_schema": row[2],
            "object_name":   row[3],
            "rows_affected": row[4],
            "duration_ms":   row[5],
            "query_hash":    row[6],
            "event_id":      row[7],
        })
    return events


def fetch_active_sessions(conn) -> list[int]:
    """Return session IDs with activity in the last 3 days (to pick up simulation data)."""
    with conn.cursor() as cur:
        cur.execute(
            """SELECT DISTINCT session_id
               FROM apt_events
               WHERE event_time > NOW() - INTERVAL '3 days'"""
        )
        return [r[0] for r in cur.fetchall()]


def fetch_all_labelled_sessions(conn) -> list[dict]:
    """
    Load all sessions with their events for offline training.
    Returns list of {session_id, label, events:[...]}.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT session_id, threat_label FROM apt_sessions ORDER BY session_id")
        sessions = cur.fetchall()

    dataset = []
    for sid, label in sessions:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT event_time, command_type, object_schema, object_name,
                          rows_affected, duration_ms, query_hash
                   FROM apt_events
                   WHERE session_id = %s
                   ORDER BY event_time""",
                (sid,),
            )
            rows = cur.fetchall()
        events = [
            {"event_time": r[0], "command_type": r[1], "object_schema": r[2],
             "object_name": r[3], "rows_affected": r[4], "duration_ms": r[5],
             "query_hash": r[6]}
            for r in rows
        ]
        if events:
            dataset.append({"session_id": sid, "label": label, "events": events})
    return dataset


# ── File-based ingestion (pg_audit CSV) ───────────────────────────────────────
_PGAUDIT_FIELDS = [
    "log_time", "user_name", "database_name", "process_id", "connection_from",
    "session_id", "session_line_num", "command_tag", "session_start_time",
    "virtual_transaction_id", "transaction_id", "error_severity", "sql_state_code",
    "message", "detail", "hint", "internal_query", "internal_query_pos",
    "context", "query", "query_pos", "location", "application_name",
]


def parse_pgaudit_line(line: str) -> dict | None:
    """Parse a single pg_audit CSV log line into an event dict."""
    try:
        reader = csv.reader(io.StringIO(line))
        fields = next(reader)
        if len(fields) < len(_PGAUDIT_FIELDS):
            return None
        rec = dict(zip(_PGAUDIT_FIELDS, fields))
        try:
            ts = datetime.strptime(rec["log_time"][:23], "%Y-%m-%d %H:%M:%S.%f")
            ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = datetime.now(tz=timezone.utc)
        return {
            "event_time":    ts,
            "command_type":  rec.get("command_tag", "OTHER").upper(),
            "object_schema": None,
            "object_name":   None,
            "rows_affected": 0,
            "duration_ms":   0.0,
        }
    except Exception:
        return None
