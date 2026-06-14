-- DEPRECATED: superseded by Alembic revision 0001 (2026-06-13).
-- Retained for rollback only during the Alembic verification window. DO NOT EDIT.
-- New schema changes go through Alembic: api/alembic/versions/.
-- migration_002_auth.sql
-- Adds submitted_by column to analyses and creates audit_log table.
-- Idempotent — safe to re-run.

-- Track which user submitted each sample
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS submitted_by VARCHAR(255) DEFAULT NULL;

-- Audit log for write operations
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log (user_id);
