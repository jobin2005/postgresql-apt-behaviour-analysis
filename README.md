# APT Behaviour Analysis in PostgreSQL — AI Security Extension

This repository contains the source code for **APT Guard**, a high-performance PostgreSQL security extension coupled with a Resident Deep Q-Learning (DQN) agent designed to detect and mitigate Advanced Persistent Threats (APTs) in real-time.

---

##Extension Setup & Deployment Guide

Follow these steps to get the system running from scratch.

### 1. Clone the Repository
```bash
git clone https://github.com/jobin2005/postgresql-apt-behaviour-analysis.git
cd postgresql-apt-behaviour-analysis
```

### 2. Choose Your Deployment Method

#### Option A: Docker (Fastest & Recommended)
Everything is pre-configured in containers.
1.  **Start the containers**:
    ```bash
    docker compose up --build -d
    ```
2.  **Verify components**:
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
2.  **Enable the Extension**: Add `apt_guard` to `shared_preload_libraries` in your `postgresql.conf` and restart Postgres.
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

### 4. Verification Walkthrough (Sample Data)

To verify that everything is working, you can simulate a few queries and check the logs.

#### Step A: Insert Sample Benign Activity
Run a few normal queries to see them being logged:
```sql
university=# CREATE TABLE IF NOT EXISTS sample_data (id INT, val TEXT);
university=# INSERT INTO sample_data VALUES (1, 'A'), (2, 'B');
university=# SELECT * FROM sample_data;
```

#### Step B: Check Raw Event Logs
Verify that the C-extension is capturing your queries:
```sql
university=# SELECT query_text, event_time FROM apt_events ORDER BY event_time DESC LIMIT 5;
```

#### Step C: Check AI Alerts
If you run an aggressive script (like a massive data dump or a series of failures), the AI will generate an alert:
```sql
university=# SELECT * FROM apt_alerts;
```

---

## 🏗️ Technical Architecture: 7-Dimension AI

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
