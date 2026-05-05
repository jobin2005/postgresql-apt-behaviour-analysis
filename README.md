# APT Behaviour Analysis in PostgreSQL — AI Security Extension

This repository contains the source code for **APT Guard**, a high-performance PostgreSQL security extension coupled with a Resident Deep Q-Learning (DQN) agent designed to detect and mitigate Advanced Persistent Threats (APTs) in real-time.

---

## 🚀 A-Z Setup & Deployment Guide

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

## 🔍 Detailed Verification Lab (Tracing the Data)

To see how the data flows through the entire pipeline, followed these steps after setting up:

### 1. Generate Activity
You can use the built-in simulator to generate mix of benign and APT activity:
```bash
# Inside Docker
docker exec -it postgre-ml_service-1 python simulate_apt.py --sessions 10

# Native
python simulate_apt.py --sessions 10
```

### 2. Trace the Data Flow (SQL Queries)

| Pipeline Step | Table to Check | SQL Query | Purpose |
| :--- | :--- | :--- | :--- |
| **Raw Capture** | `apt_events` | `SELECT * FROM apt_events ORDER BY event_time DESC LIMIT 10;` | Verification that the C-extension is hooking queries. |
| **Session Building** | `apt_sessions` | `SELECT session_id, query_count, failed_query_count, anomaly_score FROM apt_sessions;` | View how `session_builder.py` aggregates events. |
| **Learning Baselines** | `apt_user_profile` | `SELECT * FROM apt_user_profile;` | Check how `userprofile_builder.py` calculates "Normal" behavior. |
| **Pattern Detection** | `apt_sequence_patterns` | `SELECT * FROM apt_sequence_patterns ORDER BY risk_score DESC;` | View detected risky query sequences in `sequence_builder.py`. |
| **Final Decision** | `apt_alerts` | `SELECT a.*, s.user_id FROM apt_alerts a JOIN apt_sessions s ON a.session_id = s.session_id;` | See the final AI decision and defensive action. |

---

## 🛠️ Key Python Components

*   **`monitor/monitor.py`**: The main orchestrator that runs all the builders below in a loop.
*   **`monitor/session_builder.py`**: Bundles raw SQL events into Logical Sessions.
*   **`monitor/userprofile_builder.py`**: Calculates the Mean/Std values for "Normal" user behavior.
*   **`monitor/sequence_builder.py`**: Identifies repeating patterns of SQL queries to find "Attack Chain" signatures.
*   **`agent/inference.py`**: The AI "Brain" that scores sessions and inserts alerts.

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
