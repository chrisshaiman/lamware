-- =============================================================================
-- Malware Analysis Pipeline — PostgreSQL Schema (v2)
--
-- Stores structured analysis results from the pipeline:
-- Triage → Cape → Volatility → Ghidra → AI Reverse Engineering
--
-- Design principles:
--   - BIGSERIAL PKs for index locality and performance
--   - IOCs, techniques normalized (many-to-many) for cross-sample queries
--   - IOC types use STIX 2.1 Observable vocabulary for export compatibility
--   - Tags follow MISP taxonomy pattern for flexible classification
--   - Capabilities stored per-analysis (not deduplicated — LLM output varies)
--   - MITRE techniques support multiple tactics via VARCHAR[]
--   - Sample relationships track dropped/injected file lineage
--   - Network events stored structurally (not flattened to IOC strings)
--   - JSONB report_json preserves full pipeline output as escape hatch
--   - Counters (times_seen) computed from joins, not stored (no race conditions)
--
-- Self-critique applied:
--   - v1 used UUIDs (bad index locality), switched to BIGSERIAL
--   - v1 had times_seen counters (race condition), removed
--   - v1 deduplicated capabilities (fragile with LLM text), now per-analysis
--   - v1 had single tactic column (many techniques span multiple), now VARCHAR[]
--   - v1 lacked dropped file relationships and structured network events
--
-- Author: Christopher Shaiman
-- License: Apache 2.0
-- =============================================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- trigram index for fuzzy text search

-- =============================================================================
-- Core tables
-- =============================================================================

-- Samples — one row per unique binary (by SHA256)
CREATE TABLE samples (
    id              BIGSERIAL PRIMARY KEY,
    sha256          VARCHAR(64) NOT NULL UNIQUE,
    sha1            VARCHAR(40),
    md5             VARCHAR(32),
    ssdeep          VARCHAR(200),
    filename        VARCHAR(500),
    file_type       TEXT,
    file_mime       VARCHAR(100),
    file_size       BIGINT,
    entropy         REAL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_samples_sha256 ON samples(sha256);
CREATE INDEX idx_samples_first_seen ON samples(first_seen);
CREATE INDEX idx_samples_filename ON samples USING gin(filename gin_trgm_ops);


-- Sample relationships — dropped/injected file lineage
-- "sample A dropped sample B during Cape analysis"
-- "sample C was extracted from memory region of sample A by Volatility"
CREATE TABLE sample_relationships (
    id              BIGSERIAL PRIMARY KEY,
    parent_id       BIGINT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    child_id        BIGINT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    relationship    VARCHAR(50) NOT NULL,  -- dropped-by, injected-by, extracted-from, unpacked-from
    context         TEXT,                  -- e.g., "Cape task 15, dropped to C:\Users\...\payload.exe"
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(parent_id, child_id, relationship)
);

CREATE INDEX idx_sample_rel_parent ON sample_relationships(parent_id);
CREATE INDEX idx_sample_rel_child ON sample_relationships(child_id);
CREATE INDEX idx_sample_rel_type ON sample_relationships(relationship);


-- Analyses — one row per pipeline run
CREATE TABLE analyses (
    id                      BIGSERIAL PRIMARY KEY,
    sample_id               BIGINT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
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

    -- Cost tracking
    llm_cost_usd            NUMERIC(8,4),
    plain_english_summary   TEXT,

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
--   yara-rule (custom extension for YARA signature names)
CREATE TABLE ioc_values (
    id              BIGSERIAL PRIMARY KEY,
    type            VARCHAR(50) NOT NULL,
    value           TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(type, value)
);

CREATE INDEX idx_ioc_values_type ON ioc_values(type);
CREATE INDEX idx_ioc_values_value ON ioc_values USING gin(value gin_trgm_ops);
CREATE INDEX idx_ioc_values_type_value ON ioc_values(type, value);
CREATE INDEX idx_ioc_values_first_seen ON ioc_values(first_seen);


-- Analysis ↔ IOC join table
CREATE TABLE analysis_iocs (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ioc_id          BIGINT NOT NULL REFERENCES ioc_values(id) ON DELETE CASCADE,
    source_stage    VARCHAR(50) NOT NULL,  -- Triage, Cape, Volatility, Ghidra, AI Reverse Engineering, Summary
    confidence      VARCHAR(20) DEFAULT 'high',  -- high, medium, low
    context         TEXT,  -- e.g., "DNS query during detonation", "YARA rule match"

    UNIQUE(analysis_id, ioc_id, source_stage)
);

CREATE INDEX idx_analysis_iocs_analysis ON analysis_iocs(analysis_id);
CREATE INDEX idx_analysis_iocs_ioc ON analysis_iocs(ioc_id);
CREATE INDEX idx_analysis_iocs_stage ON analysis_iocs(source_stage);


-- =============================================================================
-- MITRE ATT&CK techniques — normalized with multiple tactics
-- =============================================================================

-- Technique definitions — each technique exists once
CREATE TABLE technique_values (
    id              BIGSERIAL PRIMARY KEY,
    technique_id    VARCHAR(20) NOT NULL UNIQUE,  -- T1055.003
    technique_name  VARCHAR(300),                  -- Process Injection: Thread Execution Hijacking
    tactics         VARCHAR(100)[],                -- {defense-evasion,privilege-escalation}
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_technique_values_tid ON technique_values(technique_id);
CREATE INDEX idx_technique_values_tactics ON technique_values USING gin(tactics);


-- Analysis ↔ Technique join table
CREATE TABLE analysis_techniques (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    technique_id    BIGINT NOT NULL REFERENCES technique_values(id) ON DELETE CASCADE,
    source_stage    VARCHAR(50) NOT NULL,  -- Cape, AI Reverse Engineering, Summary
    source_detail   VARCHAR(200),          -- e.g., Cape signature name that triggered it

    UNIQUE(analysis_id, technique_id, source_stage)
);

CREATE INDEX idx_analysis_techniques_analysis ON analysis_techniques(analysis_id);
CREATE INDEX idx_analysis_techniques_technique ON analysis_techniques(technique_id);


-- =============================================================================
-- Capabilities — per-analysis (not deduplicated)
--
-- LLM output is non-deterministic: "Shellcode injection via CallWindowProcA"
-- and "shellcode injection using CallWindowProcA" are different strings.
-- Deduplicating on exact text match creates false distinctions; fuzzy matching
-- on insert is expensive and error-prone. Store per-analysis and aggregate
-- at query time.
-- =============================================================================

CREATE TABLE capabilities (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    description     TEXT NOT NULL,
    source_stage    VARCHAR(50) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_capabilities_analysis ON capabilities(analysis_id);
CREATE INDEX idx_capabilities_desc ON capabilities USING gin(description gin_trgm_ops);


-- =============================================================================
-- Behavioral signatures (from Cape)
-- =============================================================================

CREATE TABLE signatures (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
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
-- Network events — structured Cape network data
--
-- Stored structurally instead of flattened into ioc_values strings.
-- Enables queries like "which samples contacted port 443 on this IP"
-- or "show me all HTTP POST requests across analyses."
-- =============================================================================

CREATE TABLE network_events (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    event_type      VARCHAR(20) NOT NULL,  -- dns, http, tcp, udp, smtp
    -- DNS fields
    dns_query       VARCHAR(500),
    dns_type        VARCHAR(10),           -- A, AAAA, MX, TXT, etc.
    dns_answers     JSONB,                 -- array of answer records
    -- HTTP fields
    http_method     VARCHAR(10),
    http_url        TEXT,
    http_host       VARCHAR(500),
    http_status     INTEGER,
    http_user_agent TEXT,
    -- TCP/UDP fields
    src_ip          VARCHAR(45),           -- supports IPv6
    src_port        INTEGER,
    dst_ip          VARCHAR(45),
    dst_port        INTEGER,
    -- Common
    timestamp       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_network_events_analysis ON network_events(analysis_id);
CREATE INDEX idx_network_events_type ON network_events(event_type);
CREATE INDEX idx_network_events_dst_ip ON network_events(dst_ip);
CREATE INDEX idx_network_events_dst_port ON network_events(dst_port);
CREATE INDEX idx_network_events_dns_query ON network_events USING gin(dns_query gin_trgm_ops);
CREATE INDEX idx_network_events_http_host ON network_events(http_host);
CREATE INDEX idx_network_events_http_url ON network_events USING gin(http_url gin_trgm_ops);


-- =============================================================================
-- Tags — MISP-style flexible taxonomy
-- =============================================================================

CREATE TABLE tags (
    id              BIGSERIAL PRIMARY KEY,
    name            VARCHAR(200) NOT NULL UNIQUE,  -- e.g., "tlp:white", "malware:emotet"
    taxonomy        VARCHAR(100),                   -- e.g., "tlp", "malware", "campaign"
    color           VARCHAR(7) DEFAULT '#607d8b',   -- hex color for UI
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tags_name ON tags(name);
CREATE INDEX idx_tags_taxonomy ON tags(taxonomy);


-- Analysis ↔ Tags
CREATE TABLE analysis_tags (
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    tag_id          BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY(analysis_id, tag_id)
);

CREATE INDEX idx_analysis_tags_tag ON analysis_tags(tag_id);


-- IOC ↔ Tags (e.g., tag an IP as "tlp:red" or "sinkholed")
CREATE TABLE ioc_tags (
    ioc_id          BIGINT NOT NULL REFERENCES ioc_values(id) ON DELETE CASCADE,
    tag_id          BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY(ioc_id, tag_id)
);

CREATE INDEX idx_ioc_tags_tag ON ioc_tags(tag_id);


-- Sample ↔ Tags
CREATE TABLE sample_tags (
    sample_id       BIGINT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
    tag_id          BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY(sample_id, tag_id)
);

CREATE INDEX idx_sample_tags_tag ON sample_tags(tag_id);


-- =============================================================================
-- IOC ↔ Technique mapping — links IOCs to the MITRE techniques they evidence
--
-- Per-analysis: the same IOC may evidence different techniques in different
-- samples (e.g., a mutex used as execution guard in one sample, singleton
-- check in another).
--
-- method distinguishes programmatic (deterministic rules) from LLM-generated
-- mappings. Programmatic mappings get confidence='high' by default; LLM
-- mappings get confidence='medium'. This distinction is surfaced in the
-- dashboard with different badge styles so analysts know what's AI-generated.
-- =============================================================================

CREATE TABLE ioc_technique_mappings (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ioc_id          BIGINT NOT NULL REFERENCES ioc_values(id) ON DELETE CASCADE,
    technique_id    BIGINT NOT NULL REFERENCES technique_values(id) ON DELETE CASCADE,
    evidence        TEXT,                  -- "C2 domain for beacon callback"
    method          VARCHAR(20) NOT NULL DEFAULT 'programmatic',  -- programmatic, llm
    confidence      VARCHAR(20) DEFAULT 'high',  -- high, medium, low
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(analysis_id, ioc_id, technique_id)
);

CREATE INDEX idx_ioc_tech_map_analysis ON ioc_technique_mappings(analysis_id);
CREATE INDEX idx_ioc_tech_map_ioc ON ioc_technique_mappings(ioc_id);
CREATE INDEX idx_ioc_tech_map_technique ON ioc_technique_mappings(technique_id);
CREATE INDEX idx_ioc_tech_map_method ON ioc_technique_mappings(method);


-- =============================================================================
-- Pipeline stage events — real-time status tracking for running analyses
--
-- Append-only event log: each stage start/complete is a single INSERT.
-- The most recent 'started' event without a 'completed' is the current stage.
-- Designed for fast writes (single INSERT, no contention) so the pipeline
-- is not slowed down by status tracking.
--
-- The analyses table also gets denormalized pipeline_status/current_stage
-- columns for fast dashboard queries without scanning the event log.
-- =============================================================================

CREATE TABLE pipeline_stage_events (
    id              BIGSERIAL PRIMARY KEY,
    analysis_id     BIGINT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    stage           VARCHAR(50) NOT NULL,
    status          VARCHAR(20) NOT NULL,  -- started, completed, failed, skipped
    detail          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_pipeline_events_analysis ON pipeline_stage_events(analysis_id);
CREATE INDEX idx_pipeline_events_stage ON pipeline_stage_events(stage);
CREATE INDEX idx_pipeline_events_created ON pipeline_stage_events(created_at);


-- =============================================================================
-- Views — prebuilt queries for common analytical tasks
-- =============================================================================

-- IOCs shared across multiple samples (the correlation engine)
CREATE VIEW correlated_iocs AS
SELECT
    iv.id AS ioc_id,
    iv.type,
    iv.value,
    iv.first_seen,
    iv.last_seen,
    COUNT(DISTINCT a.sample_id) AS distinct_samples,
    COUNT(DISTINCT a.id) AS distinct_analyses,
    array_agg(DISTINCT a.malware_family_guess)
        FILTER (WHERE a.malware_family_guess IS NOT NULL) AS families
FROM ioc_values iv
JOIN analysis_iocs ai ON ai.ioc_id = iv.id
JOIN analyses a ON a.id = ai.analysis_id
GROUP BY iv.id, iv.type, iv.value, iv.first_seen, iv.last_seen
HAVING COUNT(DISTINCT a.sample_id) > 1
ORDER BY distinct_samples DESC;


-- Technique frequency with tactic breakdown
CREATE VIEW technique_frequency AS
SELECT
    tv.technique_id,
    tv.technique_name,
    tv.tactics,
    COUNT(DISTINCT a.sample_id) AS distinct_samples,
    COUNT(DISTINCT a.id) AS distinct_analyses,
    array_agg(DISTINCT at2.source_stage) AS seen_in_stages,
    array_agg(DISTINCT a.malware_family_guess)
        FILTER (WHERE a.malware_family_guess IS NOT NULL) AS families
FROM technique_values tv
JOIN analysis_techniques at2 ON at2.technique_id = tv.id
JOIN analyses a ON a.id = at2.analysis_id
GROUP BY tv.id, tv.technique_id, tv.technique_name, tv.tactics
ORDER BY distinct_samples DESC;


-- Recent analyses summary (dashboard landing page)
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
    (SELECT COUNT(*) FROM signatures sg WHERE sg.analysis_id = a.id) AS signature_count,
    (SELECT COUNT(*) FROM network_events ne WHERE ne.analysis_id = a.id) AS network_event_count
FROM analyses a
JOIN samples s ON s.id = a.sample_id
ORDER BY a.started_at DESC;


-- Sample lineage tree (dropped/injected relationships)
CREATE VIEW sample_lineage AS
SELECT
    p.sha256 AS parent_sha256,
    p.filename AS parent_filename,
    c.sha256 AS child_sha256,
    c.filename AS child_filename,
    sr.relationship,
    sr.context,
    sr.discovered_at
FROM sample_relationships sr
JOIN samples p ON p.id = sr.parent_id
JOIN samples c ON c.id = sr.child_id
ORDER BY sr.discovered_at DESC;


-- Infrastructure overlap — IPs/domains seen across multiple families
CREATE VIEW infrastructure_overlap AS
SELECT
    iv.value AS indicator,
    iv.type,
    iv.first_seen,
    iv.last_seen,
    COUNT(DISTINCT a.malware_family_guess) AS family_count,
    array_agg(DISTINCT a.malware_family_guess)
        FILTER (WHERE a.malware_family_guess IS NOT NULL) AS families,
    COUNT(DISTINCT a.sample_id) AS sample_count
FROM ioc_values iv
JOIN analysis_iocs ai ON ai.ioc_id = iv.id
JOIN analyses a ON a.id = ai.analysis_id
WHERE iv.type IN ('ipv4-addr', 'ipv6-addr', 'domain-name', 'url')
GROUP BY iv.id, iv.value, iv.type, iv.first_seen, iv.last_seen
HAVING COUNT(DISTINCT a.malware_family_guess) > 1
ORDER BY family_count DESC, sample_count DESC;


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

-- Show new capabilities for a malware family in the last 30 days:
--   SELECT c.description, c.source_stage, a.task_id, a.started_at
--   FROM capabilities c
--   JOIN analyses a ON a.id = c.analysis_id
--   WHERE a.malware_family_guess ILIKE '%emotet%'
--   AND c.created_at > NOW() - INTERVAL '30 days'
--   ORDER BY c.created_at DESC;

-- IOC overlap between two samples:
--   SELECT iv.type, iv.value
--   FROM analysis_iocs ai1
--   JOIN analysis_iocs ai2 ON ai1.ioc_id = ai2.ioc_id
--   JOIN analyses a1 ON a1.id = ai1.analysis_id
--   JOIN analyses a2 ON a2.id = ai2.analysis_id
--   JOIN ioc_values iv ON iv.id = ai1.ioc_id
--   WHERE a1.sample_id = 1 AND a2.sample_id = 2
--   AND a1.sample_id != a2.sample_id;

-- Novel techniques not seen before last week:
--   SELECT tv.technique_id, tv.technique_name, tv.tactics, tv.first_seen
--   FROM technique_values tv
--   WHERE tv.first_seen > NOW() - INTERVAL '7 days'
--   ORDER BY tv.first_seen DESC;

-- Which samples contacted a specific port:
--   SELECT DISTINCT s.sha256, s.filename, a.malware_family_guess, ne.dst_ip
--   FROM network_events ne
--   JOIN analyses a ON a.id = ne.analysis_id
--   JOIN samples s ON s.id = a.sample_id
--   WHERE ne.dst_port = 4444 AND ne.event_type = 'tcp';

-- DGA detection — domains queried that resolved to nothing:
--   SELECT ne.dns_query, COUNT(DISTINCT a.sample_id) AS sample_count
--   FROM network_events ne
--   JOIN analyses a ON a.id = ne.analysis_id
--   WHERE ne.event_type = 'dns'
--   AND (ne.dns_answers IS NULL OR ne.dns_answers = '[]'::jsonb)
--   GROUP BY ne.dns_query
--   ORDER BY sample_count DESC;

-- Full dropped file chain for a sample:
--   WITH RECURSIVE chain AS (
--     SELECT parent_id, child_id, relationship, 1 AS depth
--     FROM sample_relationships WHERE parent_id = 1
--     UNION ALL
--     SELECT sr.parent_id, sr.child_id, sr.relationship, c.depth + 1
--     FROM sample_relationships sr
--     JOIN chain c ON c.child_id = sr.parent_id
--     WHERE c.depth < 5
--   )
--   SELECT p.sha256, c2.sha256, chain.relationship, chain.depth
--   FROM chain
--   JOIN samples p ON p.id = chain.parent_id
--   JOIN samples c2 ON c2.id = chain.child_id;
