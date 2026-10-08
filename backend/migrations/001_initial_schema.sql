-- ForensiQ Digital Forensic Toolkit
-- 001_initial_schema.sql: PostgreSQL Migration for Core Persistence

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    role VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY,
    case_number VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    investigator_id UUID,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence_items (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    source_path TEXT,
    stored_path TEXT,
    file_size BIGINT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    sha1_hash VARCHAR(40),
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    write_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id UUID REFERENCES evidence_items(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action VARCHAR(100) NOT NULL,
    custodian VARCHAR(255) NOT NULL,
    sha256_at_action VARCHAR(64),
    integrity_status VARCHAR(50) NOT NULL,
    notes TEXT
);

-- Database Indexes for Forensic Search Performance
CREATE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_cases_investigator_id ON cases(investigator_id);
CREATE INDEX IF NOT EXISTS idx_evidence_items_case_id ON evidence_items(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_items_sha256 ON evidence_items(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_chain_of_custody_case_id ON chain_of_custody(case_id);
CREATE INDEX IF NOT EXISTS idx_chain_of_custody_evidence_id ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_chain_of_custody_timestamp ON chain_of_custody(timestamp);
