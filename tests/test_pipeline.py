#!/usr/bin/env python3
"""
test_pipeline.py
----------------
End-to-end test for the APT Guard pipeline.

Tests that:
  1. Benign traffic is captured by the C extension → logged to apt_events
  2. Malicious traffic triggers the DQN → alert written to apt_alerts
  3. Both are visible via the Flask API (/api/threats, /api/stats)

Run inside the ml_service container:
    python tests/test_pipeline.py

Or with options:
    python tests/test_pipeline.py --host db --api http://localhost:5000 --timeout 90
"""

import argparse
import time
import json
import sys
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def fail(msg): print(f"  {RED}✗{RESET}  {msg}")
def info(msg): print(f"  {CYAN}→{RESET}  {msg}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")
def section(title):
    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*60}{RESET}")


# ── DB helpers ─────────────────────────────────────────────────────────────────
def get_conn(host, dbname="university", user="postgres", password="postgres", port=5432):
    return psycopg2.connect(
        dbname=dbname, user=user, password=password,
        host=host, port=port,
        cursor_factory=RealDictCursor,
    )

def count_rows(conn, table, where=""):
    with conn.cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS n FROM {table} {where}")
        return cur.fetchone()["n"]


# ── Traffic generators ─────────────────────────────────────────────────────────

def run_benign_traffic(host):
    """
    Simulates a normal university staff member doing routine lookups.
    Low query count, no failures, small result sets — should be classified safe.
    """
    conn = get_conn(host)
    conn.autocommit = True
    cur = conn.cursor()

    info("Running benign session (normal staff queries)...")

    # Routine reads — the kind a lecturer or registrar would do
    benign_queries = [
        "SELECT student_id, full_name, email FROM students LIMIT 10;",
        "SELECT course_id, title, credits FROM courses;",
        "SELECT e.student_id, c.title, e.grade FROM enrollments e JOIN courses c ON e.course_id = c.course_id;",
        "SELECT student_id, gpa, academic_status FROM student_records WHERE academic_status = 'active';",
        "SELECT COUNT(*) FROM students;",
        "SELECT AVG(gpa) FROM student_records;",
        "SELECT * FROM enrollments ORDER BY enrollment_id DESC LIMIT 5;",
    ]

    for q in benign_queries:
        try:
            cur.execute(q)
            cur.fetchall()
            time.sleep(0.2)   # realistic pacing — not a bot
        except Exception as e:
            conn.rollback()
            warn(f"Benign query failed (unexpected): {e}")

    cur.close()
    conn.close()
    ok(f"Benign session complete ({len(benign_queries)} queries, no failures)")


def run_malicious_traffic(host):
    """
    Simulates an APT actor:
      Phase 1 — mass exfiltration (100 bulk SELECTs on sensitive table)
      Phase 2 — probing for hidden tables (30 intentional failures)
      Phase 3 — schema manipulation (20 CREATE/DROP cycles)
    These map directly to the 3 features the DQN weights most heavily:
      high query_count, high failed_query_count, privilege_escalation_flag.
    """
    conn = get_conn(host)
    conn.autocommit = True
    cur = conn.cursor()

    info("Running malicious session (APT attack pattern)...")

    # Phase 1: Bulk exfiltration
    info("  Phase 1/3 — bulk SELECT exfiltration (100×)")
    for i in range(100):
        try:
            cur.execute("SELECT * FROM student_records LIMIT 1000;")
            cur.fetchall()
        except Exception as e:
            conn.rollback()

    # Phase 2: Table probing (intentional failures)
    info("  Phase 2/3 — table probing / failed queries (30×)")
    for i in range(30):
        try:
            cur.execute(f"SELECT * FROM hidden_table_{i}_not_exists;")
        except psycopg2.errors.UndefinedTable:
            conn.rollback()
        except Exception:
            conn.rollback()

    # Phase 3: DDL churn (schema manipulation)
    info("  Phase 3/3 — DDL CREATE/DROP cycles (20×)")
    for i in range(20):
        try:
            cur.execute(f"CREATE TABLE apt_test_dummy_{i} (id int);")
            cur.execute(f"DROP TABLE apt_test_dummy_{i};")
        except Exception:
            conn.rollback()

    time.sleep(5)
    cur.close()
    conn.close()
    ok("Malicious session complete (100 bulk reads, 30 failures, 20 DDL ops)")


# ── Verification helpers ────────────────────────────────────────────────────────

def wait_for_monitor(conn, test_start_iso, timeout_sec, poll_interval=5):
    """
    Poll apt_sessions until at least 2 sessions appear after test_start,
    meaning the monitor has completed at least one cycle.
    """
    info(f"Waiting for monitor to process sessions (up to {timeout_sec}s)...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM apt_sessions WHERE start_time >= %s",
                (test_start_iso,)
            )
            n = cur.fetchone()["n"]
        if n >= 2:
            ok(f"Monitor processed sessions (found {n} sessions since test start)")
            return True
        remaining = int(deadline - time.time())
        print(f"    waiting... ({n} sessions so far, {remaining}s remaining)", end="\r")
        time.sleep(poll_interval)
    print()
    return False


def check_events(conn, test_start_iso):
    section("1  RAW EVENT CAPTURE  (C Extension)")
    with conn.cursor() as cur:
        cur.execute(
            """SELECT query_type, COUNT(*) AS n, SUM(rows_accessed) AS rows
               FROM apt_events
               WHERE event_time >= %s
               GROUP BY query_type ORDER BY n DESC""",
            (test_start_iso,)
        )
        rows = cur.fetchall()

    total_events = sum(r["n"] for r in rows)
    if total_events == 0:
        fail("No events captured — is the apt_guard extension installed?")
        return False

    ok(f"Extension captured {total_events} events")
    for r in rows:
        info(f"  {r['query_type']:15s}  count={r['n']:4d}  rows={r['rows'] or 0:,}")
    return True


def check_sessions(conn, test_start_iso):
    section("2  SESSION BUILDING  (monitor daemon)")
    with conn.cursor() as cur:
        cur.execute(
            """SELECT session_id, user_id, query_count, failed_query_count,
                      total_rows_accessed, anomaly_score
               FROM apt_sessions
               WHERE start_time >= %s
               ORDER BY query_count DESC""",
            (test_start_iso,)
        )
        sessions = cur.fetchall()

    if not sessions:
        fail("No sessions built — monitor may not be running or checkpoint missing")
        return []

    ok(f"Monitor built {len(sessions)} session(s)")
    for s in sessions:
        tag = f"[queries={s['query_count']}, failures={s['failed_query_count']}, anomaly={s['anomaly_score']:.2f}]"
        info(f"  session_id={s['session_id']} user={s['user_id']}  {tag}")

    return [dict(s) for s in sessions]


def check_alerts(conn, test_start_iso, sessions):
    section("3  DQN CLASSIFICATION  (alert table)")
    session_ids = [s["session_id"] for s in sessions]

    if not session_ids:
        fail("No sessions to check alerts for")
        return False

    with conn.cursor() as cur:
        cur.execute(
            """SELECT a.alert_id, a.session_id, a.threat_level,
                      a.threat_score, a.action_taken
               FROM apt_alerts a
               WHERE a.session_id = ANY(%s)
               ORDER BY a.threat_score DESC""",
            (session_ids,)
        )
        alerts = cur.fetchall()

    ok(f"Found {len(alerts)} alert(s) for test sessions")

    alerted_sessions = {a["session_id"] for a in alerts}
    safe_sessions = [s for s in sessions if s["session_id"] not in alerted_sessions]

    if alerts:
        for a in alerts:
            info(f"  alert_id={a['alert_id']}  session={a['session_id']}"
                 f"  level={a['threat_level']}  score={a['threat_score']}"
                 f"  action={a['action_taken']}")
    else:
        warn("No alerts raised — model may need retraining or monitor isn't running")

    if safe_sessions:
        ok(f"{len(safe_sessions)} session(s) classified as safe (no alert — expected for benign)")
        for s in safe_sessions:
            info(f"  session_id={s['session_id']} queries={s['query_count']} → safe ✓")

    # Validation: the high-query session should have an alert
    high_query = max(sessions, key=lambda s: s["query_count"])
    if high_query["session_id"] in alerted_sessions:
        ok(f"Malicious session (id={high_query['session_id']}, queries={high_query['query_count']}) was correctly flagged")
        return True
    else:
        warn(f"Malicious session (id={high_query['session_id']}, queries={high_query['query_count']}) was NOT flagged")
        warn("This may indicate the model needs more training or different thresholds")
        return False


def check_api(api_base):
    section("4  DASHBOARD API  (Flask endpoints)")
    passed = 0

    endpoints = [
        ("/api/stats",          "stats"),
        ("/api/threats?hours=1","recent threats"),
        ("/api/alerts",         "unresolved alerts"),
    ]

    for path, label in endpoints:
        url = api_base.rstrip("/") + path
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                ok(f"GET {path} → 200  ({label})")
                if isinstance(data, dict):
                    for k, v in data.items():
                        info(f"    {k}: {v}")
                elif isinstance(data, list):
                    info(f"    returned {len(data)} item(s)")
                passed += 1
            else:
                fail(f"GET {path} → {r.status_code}: {r.text[:200]}")
        except requests.exceptions.ConnectionError:
            warn(f"GET {path} — could not reach {url} (dashboard may not be running)")
        except Exception as e:
            fail(f"GET {path} → {e}")

    return passed == len(endpoints)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="APT Guard end-to-end pipeline test")
    parser.add_argument("--host",    default="db",                   help="Postgres host (default: db)")
    parser.add_argument("--api",     default="http://localhost:5000", help="Dashboard base URL")
    parser.add_argument("--timeout", default=90, type=int,           help="Max seconds to wait for monitor (default: 90)")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  APT Guard — End-to-End Pipeline Test{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  DB host : {args.host}")
    print(f"  API     : {args.api}")
    print(f"  Timeout : {args.timeout}s")

    # ── Connect ────────────────────────────────────────────────────────────────
    try:
        conn = get_conn(args.host)
        ok("Connected to university database")
    except Exception as e:
        fail(f"Cannot connect to database: {e}")
        sys.exit(1)

    test_start = datetime.now(tz=timezone.utc)
    test_start_iso = test_start.isoformat()

    # ── Snapshot baselines before test ─────────────────────────────────────────
    events_before  = count_rows(conn, "apt_events")
    sessions_before = count_rows(conn, "apt_sessions")
    alerts_before  = count_rows(conn, "apt_alerts")
    info(f"Baseline — events={events_before}, sessions={sessions_before}, alerts={alerts_before}")

    # ── Run traffic ────────────────────────────────────────────────────────────
    section("0  TRAFFIC GENERATION")
    run_benign_traffic(args.host)
    time.sleep(1)
    run_malicious_traffic(args.host)

    # ── Wait for monitor ───────────────────────────────────────────────────────
    section("   WAITING FOR MONITOR CYCLE")
    monitor_ran = wait_for_monitor(conn, test_start_iso, args.timeout)

    if not monitor_ran:
        warn("Monitor didn't process sessions in time.")
        warn("Check: docker compose logs ml_service | tail -30")
        warn("Ensure checkpoint exists: checkpoints/dqn_best.pt")

    # ── Checks ─────────────────────────────────────────────────────────────────
    events_ok  = check_events(conn, test_start_iso)
    sessions   = check_sessions(conn, test_start_iso)
    alerts_ok  = check_alerts(conn, test_start_iso, sessions) if sessions else False
    api_ok     = check_api(args.api)

    # ── Summary ────────────────────────────────────────────────────────────────
    section("SUMMARY")
    results = {
        "C extension captures events": events_ok,
        "Monitor builds sessions":     bool(sessions),
        "DQN flags malicious session": alerts_ok,
        "Dashboard API responds":      api_ok,
    }

    all_passed = True
    for label, passed in results.items():
        if passed:
            ok(label)
        else:
            fail(label)
            all_passed = False

    events_after  = count_rows(conn, "apt_events")
    sessions_after = count_rows(conn, "apt_sessions")
    alerts_after  = count_rows(conn, "apt_alerts")

    print()
    info(f"New events   : +{events_after  - events_before}")
    info(f"New sessions : +{sessions_after - sessions_before}")
    info(f"New alerts   : +{alerts_after  - alerts_before}")

    conn.close()

    print(f"\n{BOLD}{'='*60}{RESET}")
    if all_passed:
        print(f"{GREEN}{BOLD}  ALL CHECKS PASSED ✓{RESET}")
    else:
        print(f"{YELLOW}{BOLD}  SOME CHECKS FAILED — see details above{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()