-- ForensiQ Digital Forensic Toolkit
-- 003_authentication.sql: User Authentication Indexes & Foreign Keys

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
