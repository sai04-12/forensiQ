-- ForensiQ Digital Forensic Toolkit
-- 002_artifact_tables.sql: Migration for Forensic Artifacts, Carving, Timeline & IOC Matches

CREATE TABLE IF NOT EXISTS file_artifacts (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sha256_hash VARCHAR(64) NOT NULL,
    is_carved BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_status VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_artifacts (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    visit_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    visit_count INT NOT NULL DEFAULT 1,
    browser VARCHAR(50) NOT NULL,
    category VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS system_artifacts (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    artifact_type VARCHAR(50) NOT NULL,
    source TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'Info'
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    category VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    source_artifact TEXT NOT NULL,
    icon VARCHAR(50) NOT NULL DEFAULT 'event'
);

CREATE TABLE IF NOT EXISTS threat_watchlists (
    id UUID PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    threat_name VARCHAR(255) NOT NULL,
    added_by VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS ioc_matches (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL,
    indicator_value TEXT NOT NULL,
    matched_source TEXT NOT NULL,
    threat_severity VARCHAR(20) NOT NULL,
    confidence_percentage INT NOT NULL DEFAULT 100,
    description TEXT NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS memory_processes (
    pid INT NOT NULL,
    ppid INT NOT NULL,
    process_name VARCHAR(255) NOT NULL,
    path TEXT NOT NULL,
    mem_usage_mb DOUBLE PRECISION NOT NULL,
    has_dll_injection BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL,
    PRIMARY KEY (pid, process_name)
);

CREATE TABLE IF NOT EXISTS network_sessions (
    session_id VARCHAR(100) PRIMARY KEY,
    protocol VARCHAR(20) NOT NULL,
    src_ip VARCHAR(50) NOT NULL,
    src_port INT NOT NULL,
    dst_ip VARCHAR(50) NOT NULL,
    dst_port INT NOT NULL,
    packet_count INT NOT NULL,
    total_bytes BIGINT NOT NULL,
    is_suspicious BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_case_id ON file_artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_browser_artifacts_case_id ON browser_artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_system_artifacts_case_id ON system_artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_events_case_id ON timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_ioc_matches_case_id ON ioc_matches(case_id);
