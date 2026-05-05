# 🛡️ Titanium APT Shield: Quickstart Guide

This guide allows any team member to deploy the "Titanium-Hardened" PostgreSQL security sentinel from scratch.

## 🚀 One-Touch Deployment

If you have Docker installed, you can launch the entire system in seconds:

```bash
# 1. Build and Start (Sentinel, Monitor, and Dashboard)
sudo docker compose down -v
sudo docker compose up --build -d

# 2. Activate the Sentinel (Bootstrap Schema)
docker exec -it postgre-db-1 psql -U postgres -d university -f /data/schema.sql

# 3. Load Sample Data (Forensic Seeding)
docker exec -it postgre-db-1 psql -U postgres -d university -f /data/university_sample.sql
```

---

## 📊 Viewing the Security Pipeline

### 🌐 Method A: The Threat Dashboard (Recommended)
Open your browser to: **[http://localhost:5000](http://localhost:5000)**

*   **Real-Time Alerts**: See live threats detected by the AI.
*   **Session Forensic**: Watch as queries are automatically grouped into user behaviors.
*   **User Baselines**: Compare current activity against historical norms.

### 🐚 Method B: Direct Terminal Inspection
If you want to see the "Titanium" tables directly, run these commands:

```bash
# View Raw Forensic Logs (Every query captured)
docker exec -it postgre-db-1 psql -U postgres -d university -c "SELECT * FROM apt_events LIMIT 10;"

# View Grouped Sessions (The Monitor Daemon's Work)
docker exec -it postgre-db-1 psql -U postgres -d university -c "SELECT * FROM apt_sessions;"

# View User Baselines (Anomaly Detection)
docker exec -it postgre-db-1 psql -U postgres -d university -c "SELECT * FROM apt_user_profile;"
```

---

## 🛠️ Architecture Overview
*   **Sentinel (`src/apt_guard.c`)**: High-performance C-extension running inside the database engine.
*   **Monitor (`monitor/monitor.py`)**: Asynchronous AI daemon that analyzes logs and calculates risk scores.
*   **Dashboard (`api/app.py`)**: Real-time visualization for security analysts.

**Your system is now ready for the review call!** 🛡️🚀👋
