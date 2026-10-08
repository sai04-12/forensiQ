-- ForensiQ Digital Forensic Toolkit
-- 005_file_carving.sql: Add carving provenance, offsets, validation status and sha1 hashes to file_artifacts

ALTER TABLE file_artifacts ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence_items(id) ON DELETE CASCADE;
ALTER TABLE file_artifacts ADD COLUMN IF NOT EXISTS mime_type VARCHAR(100) DEFAULT 'application/octet-stream';
ALTER TABLE file_artifacts ADD COLUMN IF NOT EXISTS offset_bytes BIGINT DEFAULT 0;
ALTER TABLE file_artifacts ADD COLUMN IF NOT EXISTS sha1_hash VARCHAR(40) DEFAULT '';
ALTER TABLE file_artifacts ADD COLUMN IF NOT EXISTS source_evidence_hash VARCHAR(64) DEFAULT '';
ALTER TABLE file_artifacts ADD COLUMN IF NOT EXISTS validation_status VARCHAR(50) DEFAULT 'VALID';

CREATE INDEX IF NOT EXISTS idx_file_artifacts_evidence_id ON file_artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_file_artifacts_sha256 ON file_artifacts(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_file_artifacts_file_type ON file_artifacts(file_type);
