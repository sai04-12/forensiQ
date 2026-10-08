-- ForensiQ Digital Forensic Toolkit
-- 004_artifact_extraction.sql: Add evidence provenance columns and indexes to artifact tables

ALTER TABLE browser_artifacts ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence_items(id) ON DELETE CASCADE;
ALTER TABLE browser_artifacts ADD COLUMN IF NOT EXISTS extracted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE system_artifacts ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence_items(id) ON DELETE CASCADE;
ALTER TABLE system_artifacts ADD COLUMN IF NOT EXISTS extracted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_browser_artifacts_evidence_id ON browser_artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_system_artifacts_evidence_id ON system_artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_browser_artifacts_browser ON browser_artifacts(browser);
