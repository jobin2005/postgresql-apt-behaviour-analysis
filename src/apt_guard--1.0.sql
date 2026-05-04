-- APT Guard Extension Schema v1.0

-- Table to store active and historical database sessions
CREATE TABLE IF NOT EXISTS apt_sessions (
    session_id SERIAL PRIMARY KEY,
    user_name TEXT,
    client_addr TEXT,
    start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP WITH TIME ZONE,
    process_id INT,
    process_name TEXT,
    threat_level INT DEFAULT 0
);

-- Table to store high-level security alerts
CREATE TABLE IF NOT EXISTS apt_alerts (
    alert_id SERIAL PRIMARY KEY,
    session_id INT REFERENCES apt_sessions(session_id),
    alert_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    threat_score DOUBLE PRECISION,
    action_taken TEXT,
    q_values TEXT,
    is_resolved BOOLEAN DEFAULT FALSE
);

-- Table to store granular SQL event logs for sequence analysis
CREATE TABLE IF NOT EXISTS apt_events (
    event_id SERIAL PRIMARY KEY,
    session_id INT, -- Not forced FK to allow flexible log insertion
    event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    command_type TEXT,
    object_schema TEXT,
    object_name TEXT,
    rows_affected BIGINT,
    query_hash TEXT,
    duration_ms DOUBLE PRECISION
);
