# APT Behaviour Analysis in PostgreSQL — AI Security Extension

This repository contains the source code for **APT Guard**, a high-performance PostgreSQL security extension coupled with a Resident Deep Q-Learning (DQN) agent designed to detect and mitigate Advanced Persistent Threats (APTs) in real-time.

---

## Setup & Deployment Guide

Follow these steps to get the system running from scratch.

### 1. Clone the Repository
```bash
git clone https://github.com/jobin2005/postgresql-apt-behaviour-analysis.git
cd postgresql-apt-behaviour-analysis
```

### 2. Choose Your Deployment Method

### Option A: Docker (Fastest & Recommended)
Everything is pre-configured in containers, but you can customize credentials in the `.env` file.
1.  **Prep Environment**:
    ```bash
    cp .env.example .env
    ```
2.  **Start the containers**:
    ```bash
    docker compose up --build -d
    ```
3.  **Verify components**:
    - Database is at `localhost:5433`
    - AI Service is running in the background.
    - Dashboard is at `http://localhost:5000`

#### Option B: Native Linux Installation
Use this if you want to run directly on your host.
1.  **Build the Extension**:
    ```bash
    cd src/
    make && sudo make install
    ```
2.  **Prep Environment**:
    ```bash
    cp .env.example .env
    # Edit .env with your local Postgres settings
    ```
3.  **Enable the Extension**: Add `apt_guard` to `shared_preload_libraries` in your `postgresql.conf` and restart Postgres.
3.  **Start Backend**:
    ```bash
    pip install -r requirements.txt
    python start_all.py
    ```

---

### 3. Activating the Protection (`apt_guard`)
Once the database is running, you must load the extension into the specific database you want to protect (e.g., `university`).

```bash
# Enter the psql terminal
docker exec -it postgre-db-1 psql -U postgres -d university

# Run this once inside psql:
university=# CREATE EXTENSION IF NOT EXISTS apt_guard;
```

---

---

## 🔍 Detailed Verification Lab (A to Z)

To verify the system end-to-end, follow this data tracing lab:

### 1. Generate Malicious Activity
Use the built-in attack scripts to simulate noisy threats:
```bash
# Inside Docker (Recommended)
docker exec -it postgre-ml_service-1 python checkpoints/ultra_attack.py

# Native
# Ensure you have psycopg2 installed: pip install psycopg2-binary
python checkpoints/ultra_attack.py
```

### 2. Trace the Data Flow (SQL Queries)

| Pipeline Step | Table to Check | SQL Query | Purpose |
| :--- | :--- | :--- | :--- |
| **1. Raw Hooking** | `apt_events` | `SELECT * FROM apt_events ORDER BY event_time DESC LIMIT 10;` | Confirm C-extension is capturing SQL. |
| **2. Sessionizing** | `apt_sessions` | `SELECT session_id, query_count, failed_query_count, anomaly_score FROM apt_sessions;` | See how events are bundled by `session_builder.py`. |
| **3. Profiling** | `apt_user_profile` | `SELECT * FROM apt_user_profile;` | Check how `userprofile_builder.py` learns baselines. |
| **4. Sequences** | `apt_sequence_patterns` | `SELECT * FROM apt_sequence_patterns;` | View risky sequences found by `sequence_builder.py`. |
| **5. AI Alerts** | `apt_alerts` | `SELECT * FROM apt_alerts ORDER BY created_at DESC;` | View the final AI critical threat alerts. |

---

## 🛠️ Internal Components

*   **`monitor/monitor.py`**: The multi-processor orchestrator.
*   **`agent/inference.py`**: The 7-dimensional DQN "Brain" (Inference pipeline).
*   **`api/app.py`**: The Flask Dashboard backend.

---

## 🧠 AI Detection Profiles (7-Dimensions)

The system focuses on 7 key session metrics to distinguish benign users from APT attackers:
1.  **Query Count**: High-frequency surges.
2.  **Failed Queries**: Noisy exploration (SQL errors).
3.  **Total Rows**: Potential data exfiltration volumes.
4.  **Session Duration**: Detection of long-lived persistence.
5.  **Unique Tables**: Broad discovery across schema.
6.  **Anomaly Score**: Deviation from known user baselines.
7.  **Sequence Risk**: Patterns like `Discovery -> Privilege Escalation`.

---

## ✅ Milestones
- [x] **Native C-Logging**: Implemented low-latency executor hooks in `apt_guard.c`.
- [x] **AI Model**: Freshly trained 7-dimension DQN with **99.5% accuracy**.
- [x] **Real-Time Alerting**: Immediate population of `apt_alerts` table upon threat detection.
- [x] **Interactive Dashboard**: Flask-based visualization for forensic analysis.

---
**Team:** Adithyan M C, Asiya Salam, Jobin A J, Sreedeep Rajeevan.
**Affiliation:** Pravartak Technologies, IIT Madras (ShakthiDB Project)
