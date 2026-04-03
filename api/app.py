"""
app.py
------
Flask REST API + real-time dashboard backend for APT threat monitoring.

Endpoints:
    GET  /              — Dashboard HTML
    GET  /api/threats   — Last N threat events with scores
    GET  /api/alerts    — Active (unresolved) alerts
    POST /api/feedback  — Human-in-the-loop label correction
    GET  /api/stats     — Summary statistics
"""

import os
import sys
import json
from datetime import datetime, timezone, timedelta

from flask import Flask, render_template, jsonify, request
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)


def get_conn():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        sslmode=os.getenv("DB_SSL_MODE", "prefer"),
        cursor_factory=RealDictCursor,
    )


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/threats")
def get_threats():
    limit = request.args.get("limit", 50, type=int)
    since_hours = request.args.get("hours", 24, type=int)
    since = datetime.now(tz=timezone.utc) - timedelta(hours=since_hours)

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT a.alert_id, a.session_id, a.created_at,
                          a.threat_score, a.action_taken, a.q_values,
                          s.user_name, s.client_addr
                   FROM apt_alerts a
                   JOIN apt_sessions s ON a.session_id = s.session_id
                   WHERE a.created_at >= %s
                   ORDER BY a.created_at DESC
                   LIMIT %s""",
                (since, limit),
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    items = []
    for r in rows:
        item = dict(r)
        item["created_at"]  = item["created_at"].isoformat()
        item["client_addr"] = str(item["client_addr"]) if item["client_addr"] else None
        items.append(item)
    return jsonify(items)


@app.route("/api/alerts")
def get_alerts():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT a.*, s.user_name
                   FROM apt_alerts a
                   JOIN apt_sessions s ON a.session_id = s.session_id
                   WHERE a.resolved = FALSE
                   ORDER BY a.created_at DESC
                   LIMIT 100"""
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    result = []
    for r in rows:
        d = dict(r)
        d["created_at"] = d["created_at"].isoformat()
        result.append(d)
    return jsonify(result)


@app.route("/api/stats")
def get_stats():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS total_sessions FROM apt_sessions")
            total_sessions = cur.fetchone()["total_sessions"]
            cur.execute("SELECT COUNT(*) AS total_alerts FROM apt_alerts")
            total_alerts = cur.fetchone()["total_alerts"]
            cur.execute(
                "SELECT COUNT(*) AS apt_sessions FROM apt_sessions WHERE threat_label >= 1"
            )
            apt_sessions = cur.fetchone()["apt_sessions"]
            cur.execute(
                "SELECT AVG(threat_score) AS avg_score FROM apt_alerts WHERE created_at > NOW() - INTERVAL '1 hour'"
            )
            row = cur.fetchone()
            avg_score = float(row["avg_score"]) if row["avg_score"] else 0.0
    finally:
        conn.close()

    return jsonify({
        "total_sessions": total_sessions,
        "apt_sessions":   apt_sessions,
        "total_alerts":   total_alerts,
        "avg_threat_score_1h": round(avg_score, 3),
    })


@app.route("/api/feedback", methods=["POST"])
def post_feedback():
    """Human-in-the-loop: mark an alert as resolved or mis-classified."""
    data = request.get_json()
    alert_id  = data.get("alert_id")
    resolved  = data.get("resolved", True)

    if not alert_id:
        return jsonify({"error": "alert_id required"}), 400

    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE apt_alerts SET resolved = %s WHERE alert_id = %s",
                    (resolved, alert_id),
                )
    finally:
        conn.close()
    return jsonify({"status": "ok", "alert_id": alert_id, "resolved": resolved})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
