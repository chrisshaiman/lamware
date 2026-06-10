-- migration_003_investigation.sql
-- Adds investigation agent tables for conversational deep-dive sessions.
-- Idempotent — safe to re-run.

CREATE TABLE IF NOT EXISTS investigation_sessions (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    user_sub        TEXT NOT NULL,
    model           TEXT NOT NULL DEFAULT 'claude-sonnet-4-6',
    status          TEXT NOT NULL DEFAULT 'active',
    total_input_tokens  INTEGER NOT NULL DEFAULT 0,
    total_output_tokens INTEGER NOT NULL DEFAULT 0,
    total_cost_usd  NUMERIC(10,4) NOT NULL DEFAULT 0,
    max_turns       INTEGER NOT NULL DEFAULT 50,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_sessions_analysis ON investigation_sessions(analysis_id);
CREATE INDEX IF NOT EXISTS idx_inv_sessions_user ON investigation_sessions(user_sub);

CREATE TABLE IF NOT EXISTS investigation_messages (
    id              BIGSERIAL PRIMARY KEY,
    session_id      BIGINT NOT NULL REFERENCES investigation_sessions(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,
    content         TEXT NOT NULL,
    tool_name       TEXT,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_messages_session ON investigation_messages(session_id);

CREATE TABLE IF NOT EXISTS investigation_pins (
    id              BIGSERIAL PRIMARY KEY,
    session_id      BIGINT NOT NULL REFERENCES investigation_sessions(id) ON DELETE CASCADE,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    pin_type        TEXT NOT NULL,
    value           TEXT NOT NULL,
    ioc_type        TEXT,
    context         TEXT NOT NULL DEFAULT '',
    promoted        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_pins_session ON investigation_pins(session_id);
CREATE INDEX IF NOT EXISTS idx_inv_pins_analysis ON investigation_pins(analysis_id);
