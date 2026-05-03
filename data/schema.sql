
-- ===============================
-- APT EVENTS TABLE (RAW INPUT)
-- ===============================
CREATE TABLE IF NOT EXISTS apt_events (
    event_id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,

    session_hint TEXT,  -- optional (can help grouping if available)

    query_type TEXT,
    query_text TEXT,

    table_names TEXT[],  -- multiple tables per query

    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    duration_ms FLOAT,
    rows_accessed INT,

    success_flag BOOLEAN,
    error_code TEXT,

    ip_address TEXT
);


-- ===============================
-- APT SESSIONS TABLE (CORE LOGIC)
-- ===============================
CREATE TABLE IF NOT EXISTS apt_sessions (
    session_id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,

    start_time TIMESTAMP,
    end_time TIMESTAMP,

    query_count INT DEFAULT 0,
    failed_query_count INT DEFAULT 0,

    total_rows_accessed INT DEFAULT 0,
    unique_tables INT DEFAULT 0,

    privilege_escalation_flag BOOLEAN DEFAULT FALSE,

    anomaly_score FLOAT DEFAULT 0,

    session_duration FLOAT DEFAULT 0  -- seconds
);


-- ===============================
-- USER PROFILE TABLE (BASELINE)
-- ===============================
CREATE TABLE IF NOT EXISTS apt_user_profile (
    user_id TEXT PRIMARY KEY,

    avg_queries_per_session FLOAT DEFAULT 0,
    avg_rows_accessed FLOAT DEFAULT 0,
    avg_session_duration FLOAT DEFAULT 0,

    normal_tables_accessed INT DEFAULT 0
);


-- ===============================
-- SEQUENCE PATTERNS TABLE (OPTIONAL ADVANCED)
-- ===============================
CREATE TABLE IF NOT EXISTS apt_sequence_patterns (
    pattern_id SERIAL PRIMARY KEY,

    sequence TEXT UNIQUE,   -- ✅ add UNIQUE here directly

    frequency INT DEFAULT 0,

    risk_score FLOAT DEFAULT 0
);


-- ===============================
-- ALERTS TABLE (OUTPUT)
-- ===============================
CREATE TABLE IF NOT EXISTS apt_alerts (
    alert_id SERIAL PRIMARY KEY,

    session_id INT REFERENCES apt_sessions(session_id),

    threat_level TEXT,
    action_taken TEXT,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- For fast event lookup by user
CREATE INDEX IF NOT EXISTS idx_events_user 
ON apt_events(user_id);

-- For time-based queries (VERY IMPORTANT)
CREATE INDEX IF NOT EXISTS idx_events_time 
ON apt_events(event_time);

-- For session lookup
CREATE INDEX IF NOT EXISTS idx_sessions_user 
ON apt_sessions(user_id);

-- Alerts lookup
CREATE INDEX IF NOT EXISTS idx_alerts_session 
ON apt_alerts(session_id);

CREATE INDEX IF NOT EXISTS idx_alerts_time 
ON apt_alerts(created_at);


