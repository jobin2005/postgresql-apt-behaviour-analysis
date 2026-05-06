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

1.  **Prep Environment**:
    ```bash
    cp .env.example .env
    ```
2.  **Start the containers**:
    ```bash
    docker compose up --build -d
    ```
3.  **Verify containers are running**:
    ```bash
    docker ps
    ```
    You should see two containers:
    - `postgresql-apt-behaviour-analysis-db-1` — PostgreSQL 15 with `apt_guard` extension
    - `postgresql-apt-behaviour-analysis-ml_service-1` — Python ML service + Dashboard

    **Endpoints:**
    - Database: `localhost:5433`
    - Dashboard: `http://localhost:5000`

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
4.  **Start Backend**:
    ```bash
    pip install -r requirements.txt
    python start_all.py
    ```

---

### 3. Activating the Protection (`apt_guard`)

> **Note:** The Docker init script (`schema.sql`) pre-creates some tables. You must drop them first before the extension can take ownership.

```bash
# Enter the psql terminal
docker exec -it postgresql-apt-behaviour-analysis-db-1 psql -U postgres -d postgres
```

Run these commands inside psql:
```sql
-- Drop pre-created tables so the extension can own them
DROP TABLE IF EXISTS apt_alerts, apt_sessions, apt_user_profile, apt_sequence_patterns, apt_events CASCADE;

-- Load the extension (this creates all tables automatically)
CREATE EXTENSION apt_guard;

-- Verify it loaded
\dx

-- Exit psql
\q
```

---

### 4. Train the AI Model

The system needs a trained DQN model before it can detect threats. Run these commands in order:

```bash
# Step 1: Generate synthetic training data (5000 sessions)
docker exec -it postgresql-apt-behaviour-analysis-ml_service-1 python data/generate_training_data.py --sessions 5000

# Step 2: Train the DQN agent (2000 episodes)
docker exec -it postgresql-apt-behaviour-analysis-ml_service-1 python agent/train.py --episodes 2000
```

Once training completes, the Monitor Daemon will **automatically start** inside the container (it polls for the checkpoint file).

---

### 5. Simulate Attacks & Verify

```bash
# Run the APT simulation script
docker exec -it postgresql-apt-behaviour-analysis-ml_service-1 python simulate_apt.py
```

Then verify the detection pipeline by checking the database:
```bash
docker exec -it postgresql-apt-behaviour-analysis-db-1 psql -U postgres -d postgres
```

### Data Flow Verification (SQL Queries)

| Pipeline Step | Table | SQL Query | Purpose |
| :--- | :--- | :--- | :--- |
| **1. Raw Hooking** | `apt_events` | `SELECT * FROM apt_events ORDER BY event_time DESC LIMIT 10;` | Confirm C-extension is capturing SQL |
| **2. Sessionizing** | `apt_sessions` | `SELECT session_id, query_count, failed_query_count, anomaly_score FROM apt_sessions;` | See how events are bundled by `session_builder.py` |
| **3. Profiling** | `apt_user_profile` | `SELECT * FROM apt_user_profile;` | Check how `userprofile_builder.py` learns baselines |
| **4. Sequences** | `apt_sequence_patterns` | `SELECT * FROM apt_sequence_patterns;` | View risky sequences found by `sequence_builder.py` |
| **5. AI Alerts** | `apt_alerts` | `SELECT * FROM apt_alerts ORDER BY created_at DESC;` | View the final AI threat detection alerts |

---

## 🛠️ Internal Components

*   **`src/apt_guard.c`**: The C-extension that hooks into PostgreSQL's executor to capture all SQL activity.
*   **`monitor/monitor.py`**: The multi-processor orchestrator that builds sessions, profiles, and triggers inference.
*   **`agent/inference.py`**: The 7-dimensional DQN "Brain" (inference pipeline).
*   **`agent/train.py`**: Offline DQN training with Double DQN and experience replay.
*   **`api/app.py`**: The Flask Dashboard backend.
*   **`start_all.py`**: Entry point that starts the Dashboard and Monitor (with graceful checkpoint detection).

---

## AI Detection Profiles (7-Dimensions)

The system focuses on 7 key session metrics to distinguish benign users from APT attackers:
1.  **Query Count**: High-frequency surges.
2.  **Failed Queries**: Noisy exploration (SQL errors).
3.  **Total Rows**: Potential data exfiltration volumes.
4.  **Session Duration**: Detection of long-lived persistence.
5.  **Unique Tables**: Broad discovery across schema.
6.  **Anomaly Score**: Deviation from known user baselines.
7.  **Sequence Risk**: Patterns like `Discovery -> Privilege Escalation`.

---

## Milestones
- [x] **Native C-Logging**: Implemented low-latency executor hooks in `apt_guard.c`.
- [x] **AI Model**: Freshly trained 7-dimension DQN with **99.5% accuracy**.
- [x] **Real-Time Alerting**: Immediate population of `apt_alerts` table upon threat detection.
- [x] **Interactive Dashboard**: Flask-based visualization for forensic analysis.
- [x] **Containerized Deployment**: Full Docker Compose workflow with graceful startup.

---
**Team:** Adithyan M C, Asiya Salam, Jobin A J, Sreedeep Rajeevan.
**Affiliation:** Pravartak Technologies, IIT Madras (ShakthiDB Project)
