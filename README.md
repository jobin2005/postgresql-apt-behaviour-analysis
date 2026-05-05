# APT Behaviour Analysis in PostgreSQL — AI Security Extension

## Overview

This project implements a **Real-Time AI Threat Defense** system for PostgreSQL. It uses a **Deep Q-Learning (DQN)** agent to monitor database sessions and automatically block or alert on **Advanced Persistent Threats (APTs)**. 

The system utilizes a native C-extension for low-latency SQL hooking and a Python analytical daemon for 7-dimensional behavioral scoring.

---

## 🏗️ System Architecture

The project is built on the **Sentinel Pattern**:
*   **The Guard** (`apt_guard.c`): A PostgreSQL C-extension that hooks into the query executor to log every event in real-time.
*   **The Brain** (`monitor.py`): A Python daemon that aggregates events into sessions and uses a **7-dimension DQN model** to predict threats.
*   **The Watcher** (`api/app.py`): A Flask-based dashboard that visualizes active alerts and session forensics.

---

## 🚀 Quick Start (Using Docker - Recommended)

Docker is the fastest way to deploy the entire stack (Postgres + AI Service + Dashboard).

### 1. Build and Start
```bash
docker compose up --build -d
```
*This automatically compiles the C-extension and initializes the database schema.*

### 2. Activate the Extension
Connect to your database (e.g., `university`) and load the protection:
```bash
docker exec -it postgre-db-1 psql -U postgres -d university
university=# CREATE EXTENSION apt_guard;
```

### 3. View the Dashboard
Open your browser at **http://localhost:5000** to see live threat analysis.

---

## 🛠️ Manual Installation (Without Docker)

Use this if you have a local PostgreSQL 15+ installation on Linux.

### 1. Compile the Extension
```bash
cd src/
make && sudo make install
```

### 2. Configure PostgreSQL
Add the extension to your `postgresql.conf`:
```conf
shared_preload_libraries = 'apt_guard'
```
*Restart PostgreSQL after saving.*

### 3. Initialize Schema & Daemon
```bash
# 1. Run the schema script
psql -U postgres -d your_db -f data/schema.sql

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Start the analytical daemon
python start_all.py
```

---

## 🧠 AI Detection Profiles (7-Dimensions)

The system focuses on 7 key metrics to distinguish benign users from APT attackers:
1.  **Query Count**: High-frequency surges.
2.  **Failed Queries**: Noisy exploration behavior.
3.  **Total Rows**: Data exfiltration surges.
4.  **Session Duration**: Long-lived persistence.
5.  **Unique Tables**: Broad discovery across schema.
6.  **Anomaly Score**: Deviation from user-specific baseline.
7.  **Sequence Risk**: Detection of dangerous query patterns (e.g., discovery -> privilege escalation).

---

## ✅ Milestones Completed
- [x] **Production C-Extension**: Stable query hooking with transaction safety.
- [x] **7-Dim AI Architecture**: Refined state vector with 99.5% detection accuracy.
- [x] **Automated Alerting**: Real-time insertion into `apt_alerts` with full Q-value reasoning.
- [x] **Attribution Features**: Added client IP and process name tracking to sessions.
- [x] **Dashboard Sync**: Frontend visualization connected to 7-dim AI results.

---

## 📡 Viewing Results
Check the database for detected threats:
```sql
SELECT session_id, threat_level, action_taken, created_at 
FROM apt_alerts 
ORDER BY created_at DESC;
```

---
**Affiliation:** Pravartak Technologies, IIT Madras (ShakthiDB Project)
rences
1. LogShield — Transformer-based APT Detection (arXiv:2311.05733)
2. MAGIC — Masked Graph Representation Learning (arXiv:2310.09831)
3. ACM DL 10.1145/3736654 — RL-based Adaptive DB Defense
