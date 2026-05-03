-- Migration 001: IOC-technique mappings + pipeline status tracking
-- Safe to run on existing databases (IF NOT EXISTS throughout).

-- IOC ↔ Technique mapping
CREATE TABLE IF NOT EXISTS ioc_technique_mappings (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ioc_id          BIGINT NOT NULL REFERENCES ioc_values(id) ON DELETE CASCADE,
    technique_id    BIGINT NOT NULL REFERENCES technique_values(id) ON DELETE CASCADE,
    evidence        TEXT,
    method          VARCHAR(20) NOT NULL DEFAULT 'programmatic',
    confidence      VARCHAR(20) DEFAULT 'high',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(analysis_id, ioc_id, technique_id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_tech_map_analysis ON ioc_technique_mappings(analysis_id);
CREATE INDEX IF NOT EXISTS idx_ioc_tech_map_ioc ON ioc_technique_mappings(ioc_id);
CREATE INDEX IF NOT EXISTS idx_ioc_tech_map_technique ON ioc_technique_mappings(technique_id);
CREATE INDEX IF NOT EXISTS idx_ioc_tech_map_method ON ioc_technique_mappings(method);

-- Pipeline stage events
CREATE TABLE IF NOT EXISTS pipeline_stage_events (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    stage           VARCHAR(50) NOT NULL,
    status          VARCHAR(20) NOT NULL,
    detail          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pipeline_events_analysis ON pipeline_stage_events(analysis_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_events_stage ON pipeline_stage_events(stage);
CREATE INDEX IF NOT EXISTS idx_pipeline_events_created ON pipeline_stage_events(created_at);

-- Add status columns to analyses table
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS pipeline_status VARCHAR(20) DEFAULT 'completed';
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS current_stage VARCHAR(50);
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS stage_timings JSONB DEFAULT '{}';
