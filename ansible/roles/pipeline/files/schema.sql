-- =============================================================================
-- Malware Analysis Pipeline — PostgreSQL Schema
--
-- Stores structured analysis results from the five-stage pipeline:
-- Triage → Cape → Volatility → Ghidra → AI Reverse Engineering
--
-- Design principles:
--   - IOCs, techniques, and capabilities are normalized (many-to-many)
--     so relationships across samples can be queried efficiently
--   - IOC types use STIX 2.1 Observable vocabulary for interoperability
--   - Tags follow MISP taxonomy pattern for flexible classification
--   - JSONB report_json column preserves the full pipeline output as an
--     escape hatch for data not yet modeled in structured tables
--   - All timestamps are UTC with timezone
--
-- Author: Christopher Shaiman
-- License: Apache 2.0
-- =============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- trigram index for fuzzy text search

-- =============================================================================
-- Core tables
-- =============================================================================

-- Samples — one row per unique binary (by SHA256)
CREATE TABLE samples (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sha256          VARCHAR(64) NOT NULL UNIQUE,
    sha1            VARCHAR(40),
    md5             VARCHAR(32),
    ssdeep          VARCHAR(200),
    filename        VARCHAR(500),
    file_type       VARCHAR(300),
    file_mime       VARCHAR(100),
    file_size       BIGINT,
    entropy         REAL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    times_analyzed  INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_samples_sha256 ON samples(sha256);
CREATE INDEX idx_samples_first_seen ON samples(first_seen);
CREATE INDEX idx_samples_filename ON samples USING gin(filename gin_trgm_ops);


-- Analyses — one row per pipeline run (a sample can be analyzed multiple times)
CREATE TABLE analyses (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sample_id               UUID NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    task_id                 VARCHAR(100) NOT NULL,
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,

    -- Overall results
    severity                VARCHAR(20),  -- critical, high, medium, low
    malscore                REAL,
    malware_family_guess    VARCHAR(200),

    -- Stage completion flags
    triage_completed        BOOLEAN DEFAULT FALSE,
    cape_completed          BOOLEAN DEFAULT FALSE,
    cape_task_id            INTEGER,
    volatility_completed    BOOLEAN DEFAULT FALSE,
    volatility_triggered    BOOLEAN DEFAULT FALSE,
    ghidra_completed        BOOLEAN DEFAULT FALSE,
    ghidra_triggered        BOOLEAN DEFAULT FALSE,
    interpret_completed     BOOLEAN DEFAULT FALSE,
    summary_completed       BOOLEAN DEFAULT FALSE,
    pdf_generated           BOOLEAN DEFAULT FALSE,

    -- AI RE metadata
    interpret_model         VARCHAR(100),
    interpret_tool_calls    INTEGER DEFAULT 0,
    interpret_duration_secs REAL,
    interpret_escalated     BOOLEAN DEFAULT FALSE,
    possible_prompt_influence BOOLEAN DEFAULT FALSE,

    -- LLM narrative and working notes (searchable text)
    narrative               TEXT,
    working_notes           TEXT,
    executive_summary       TEXT,

    -- Full pipeline report JSON — escape hatch for unmodeled data
    report_json             JSONB,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_analyses_sample_id ON analyses(sample_id);
CREATE INDEX idx_analyses_task_id ON analyses(task_id);
CREATE INDEX idx_analyses_started_at ON analyses(started_at);
CREATE INDEX idx_analyses_severity ON analyses(severity);
CREATE INDEX idx_analyses_family ON analyses(malware_family_guess);
CREATE INDEX idx_analyses_family_trgm ON analyses USING gin(malware_family_guess gin_trgm_ops);
CREATE INDEX idx_analyses_narrative_trgm ON analyses USING gin(narrative gin_trgm_ops);
CREATE INDEX idx_analyses_report_json ON analyses USING gin(report_json);


-- =============================================================================
-- IOCs — normalized, many-to-many with analyses
-- =============================================================================

-- IOC values — each unique indicator exists once
-- type uses STIX 2.1 Observable vocabulary:
--   ipv4-addr, ipv6-addr, domain-name, url, email-addr,
--   file:hashes.SHA-256, file:hashes.MD5, file:name,
--   windows-registry-key, mutex, user-agent, network-traffic,
--   yara-rule (custom extension)
CREATE TABLE ioc_values (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type            VARCHAR(50) NOT NULL,
    value           TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    times_seen      INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(type, value)
);

CREATE INDEX idx_ioc_values_type ON ioc_values(type);
CREATE INDEX idx_ioc_values_value ON ioc_values USING gin(value gin_trgm_ops);
CREATE INDEX idx_ioc_values_type_value ON ioc_values(type, value);
CREATE INDEX idx_ioc_values_times_seen ON ioc_values(times_seen DESC);
CREATE INDEX idx_ioc_values_first_seen ON ioc_values(first_seen);


-- Analysis ↔ IOC join table
CREATE TABLE analysis_iocs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id     UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ioc_id          UUID NOT NULL REFERENCES ioc_values(id) ON DELETE CASCADE,
    source_stage    VARCHAR(50) NOT NULL,  -- Triage, Cape, Volatility, Ghidra, AI Reverse Engineering, Summary
    confidence      VARCHAR(20) DEFAULT 'high',  -- high, medium, low
    context         TEXT,  -- optional context (e.g., "found in DNS query", "YARA rule match")

    UNIQUE(analysis_id, ioc_id, source_stage)
);

CREATE INDEX idx_analysis_iocs_analysis ON analysis_iocs(analysis_id);
CREATE INDEX idx_analysis_iocs_ioc ON analysis_iocs(ioc_id);
CREATE INDEX idx_analysis_iocs_stage ON analysis_iocs(source_stage);


-- =============================================================================
-- MITRE ATT&CK techniques — normalized with tactic context
-- =============================================================================

-- Technique definitions — each technique exists once
CREATE TABLE technique_values (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    technique_id    VARCHAR(20) NOT NULL UNIQUE,  -- T1055.003
    technique_name  VARCHAR(300),                  -- Process Injection: Thread Execution Hijacking
    tactic          VARCHAR(100),                  -- defense-evasion, privilege-escalation
    -- A technique can map to multiple tactics; store the primary one here,
    -- additional mappings can go in technique_tactics if needed later
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    times_seen      INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_technique_values_tid ON technique_values(technique_id);
CREATE INDEX idx_technique_values_tactic ON technique_values(tactic);


-- Analysis ↔ Technique join table
CREATE TABLE analysis_techniques (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id     UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    technique_id    UUID NOT NULL REFERENCES technique_values(id) ON DELETE CASCADE,
    source_stage    VARCHAR(50) NOT NULL,  -- Cape, AI Reverse Engineering, Summary
    source_detail   VARCHAR(200),          -- e.g., Cape signature name that triggered it

    UNIQUE(analysis_id, technique_id, source_stage)
);

CREATE INDEX idx_analysis_techniques_analysis ON analysis_techniques(analysis_id);
CREATE INDEX idx_analysis_techniques_technique ON analysis_techniques(technique_id);


-- =============================================================================
-- Capabilities — normalized behavioral descriptions
-- =============================================================================

-- Capability values — each unique capability exists once
CREATE TABLE capability_values (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    description     TEXT NOT NULL UNIQUE,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    times_seen      INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_capability_values_desc ON capability_values USING gin(description gin_trgm_ops);


-- Analysis ↔ Capability join table
CREATE TABLE analysis_capabilities (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id     UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    capability_id   UUID NOT NULL REFERENCES capability_values(id) ON DELETE CASCADE,
    source_stage    VARCHAR(50) NOT NULL,

    UNIQUE(analysis_id, capability_id)
);

CREATE INDEX idx_analysis_capabilities_analysis ON analysis_capabilities(analysis_id);
CREATE INDEX idx_analysis_capabilities_capability ON analysis_capabilities(capability_id);


-- =============================================================================
-- Behavioral signatures (from Cape)
-- =============================================================================

CREATE TABLE signatures (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    analysis_id     UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    name            VARCHAR(200) NOT NULL,
    severity        INTEGER DEFAULT 0,  -- 0-3 (Cape's scale)
    description     TEXT,
    source_stage    VARCHAR(50) NOT NULL DEFAULT 'Cape',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signatures_analysis ON signatures(analysis_id);
CREATE INDEX idx_signatures_name ON signatures(name);
CREATE INDEX idx_signatures_severity ON signatures(severity DESC);


-- =============================================================================
-- Tags — MISP-style flexible taxonomy
-- =============================================================================

CREATE TABLE tags (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(200) NOT NULL UNIQUE,  -- e.g., "tlp:white", "malware:emotet", "campaign:2026-q1"
    taxonomy        VARCHAR(100),                   -- e.g., "tlp", "malware", "campaign", "confidence"
    color           VARCHAR(7) DEFAULT '#607d8b',   -- hex color for UI
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tags_name ON tags(name);
CREATE INDEX idx_tags_taxonomy ON tags(taxonomy);


-- Analysis ↔ Tags
CREATE TABLE analysis_tags (
    analysis_id     UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    tag_id          UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY(analysis_id, tag_id)
);

CREATE INDEX idx_analysis_tags_tag ON analysis_tags(tag_id);


-- IOC ↔ Tags (e.g., tag an IP as "tlp:red" or "sinkholed")
CREATE TABLE ioc_tags (
    ioc_id          UUID NOT NULL REFERENCES ioc_values(id) ON DELETE CASCADE,
    tag_id          UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY(ioc_id, tag_id)
);

CREATE INDEX idx_ioc_tags_tag ON ioc_tags(tag_id);


-- Sample ↔ Tags (e.g., tag a sample as "priority:high")
CREATE TABLE sample_tags (
    sample_id       UUID NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    tag_id          UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY(sample_id, tag_id)
);

CREATE INDEX idx_sample_tags_tag ON sample_tags(tag_id);


-- =============================================================================
-- Useful views
-- =============================================================================

-- IOCs that appear across multiple samples (correlation)
CREATE VIEW correlated_iocs AS
SELECT
    iv.id,
    iv.type,
    iv.value,
    iv.times_seen,
    iv.first_seen,
    iv.last_seen,
    COUNT(DISTINCT a.sample_id) AS distinct_samples,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE a.malware_family_guess IS NOT NULL) AS families
FROM ioc_values iv
JOIN analysis_iocs ai ON ai.ioc_id = iv.id
JOIN analyses a ON a.id = ai.analysis_id
GROUP BY iv.id, iv.type, iv.value, iv.times_seen, iv.first_seen, iv.last_seen
HAVING COUNT(DISTINCT a.sample_id) > 1
ORDER BY distinct_samples DESC;


-- Technique frequency across all analyses
CREATE VIEW technique_frequency AS
SELECT
    tv.technique_id,
    tv.technique_name,
    tv.tactic,
    tv.times_seen,
    COUNT(DISTINCT a.sample_id) AS distinct_samples,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE a.malware_family_guess IS NOT NULL) AS families
FROM technique_values tv
JOIN analysis_techniques at2 ON at2.technique_id = tv.id
JOIN analyses a ON a.id = at2.analysis_id
GROUP BY tv.id, tv.technique_id, tv.technique_name, tv.tactic, tv.times_seen
ORDER BY distinct_samples DESC;


-- Recent analyses summary
CREATE VIEW recent_analyses AS
SELECT
    a.id AS analysis_id,
    a.task_id,
    s.sha256,
    s.filename,
    s.file_type,
    a.malware_family_guess,
    a.severity,
    a.malscore,
    a.started_at,
    a.completed_at,
    a.interpret_tool_calls,
    a.possible_prompt_influence,
    (SELECT COUNT(*) FROM analysis_iocs ai WHERE ai.analysis_id = a.id) AS ioc_count,
    (SELECT COUNT(*) FROM analysis_techniques at2 WHERE at2.analysis_id = a.id) AS technique_count,
    (SELECT COUNT(*) FROM signatures sg WHERE sg.analysis_id = a.id) AS signature_count
FROM analyses a
JOIN samples s ON s.id = a.sample_id
ORDER BY a.started_at DESC;


-- =============================================================================
-- Example queries (for reference, not executed)
-- =============================================================================

-- Find all samples that share a specific C2 domain:
--   SELECT DISTINCT s.sha256, s.filename, a.malware_family_guess
--   FROM ioc_values iv
--   JOIN analysis_iocs ai ON ai.ioc_id = iv.id
--   JOIN analyses a ON a.id = ai.analysis_id
--   JOIN samples s ON s.id = a.sample_id
--   WHERE iv.type = 'domain-name' AND iv.value = 'evil.example.com';

-- Show evolution: new capabilities for a malware family:
--   SELECT cv.description, cv.first_seen, COUNT(*) as occurrences
--   FROM capability_values cv
--   JOIN analysis_capabilities ac ON ac.capability_id = cv.id
--   JOIN analyses a ON a.id = ac.analysis_id
--   WHERE a.malware_family_guess ILIKE '%emotet%'
--   AND cv.first_seen > NOW() - INTERVAL '30 days'
--   GROUP BY cv.id
--   ORDER BY cv.first_seen DESC;

-- IOC overlap between two samples:
--   SELECT iv.type, iv.value
--   FROM analysis_iocs ai1
--   JOIN analysis_iocs ai2 ON ai1.ioc_id = ai2.ioc_id
--   JOIN analyses a1 ON a1.id = ai1.analysis_id
--   JOIN analyses a2 ON a2.id = ai2.analysis_id
--   JOIN ioc_values iv ON iv.id = ai1.ioc_id
--   WHERE a1.sample_id = '<sample_uuid_1>'
--   AND a2.sample_id = '<sample_uuid_2>'
--   AND a1.sample_id != a2.sample_id;

-- Novel techniques not seen before last week:
--   SELECT tv.technique_id, tv.technique_name, tv.first_seen
--   FROM technique_values tv
--   WHERE tv.first_seen > NOW() - INTERVAL '7 days'
--   ORDER BY tv.first_seen DESC;
