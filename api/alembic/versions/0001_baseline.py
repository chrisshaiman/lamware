# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""baseline: snapshot of the malware_analysis schema as of adoption

Captured from production with:
    pg_dump --schema-only --no-owner --no-privileges malware_analysis

Raw SQL is intentional for the baseline ONLY -- it is a one-time snapshot of an
existing database. Future migrations use op.* calls. The DDL is embedded as a
module constant so the revision is self-contained.

The psql client meta-commands that pg_dump 16 wraps the output in (the
restrict/unrestrict pair) were removed, because op.execute() runs through
psycopg2, which does not understand backslash meta-commands. Everything else is
the verbatim pg_dump --schema-only output.

Revision ID: 0001
Revises:
Create Date: 2026-06-13
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

BASELINE_SQL = r"""
--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14 (Ubuntu 16.14-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.14 (Ubuntu 16.14-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
-- NOTE: pg_dump's `SELECT pg_catalog.set_config('search_path', '', false);` was
-- removed here. It blanks the connection search_path for the rest of the session,
-- which breaks Alembic's unqualified `INSERT INTO alembic_version` bookkeeping when
-- this runs via op.execute(). Every object below is already public-qualified, so
-- dropping it is safe.
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: analyses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analyses (
    id bigint NOT NULL,
    sample_id bigint NOT NULL,
    task_id character varying(100) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    severity character varying(20),
    malscore real,
    malware_family_guess character varying(200),
    triage_completed boolean DEFAULT false,
    cape_completed boolean DEFAULT false,
    cape_task_id integer,
    volatility_completed boolean DEFAULT false,
    volatility_triggered boolean DEFAULT false,
    ghidra_completed boolean DEFAULT false,
    ghidra_triggered boolean DEFAULT false,
    interpret_completed boolean DEFAULT false,
    summary_completed boolean DEFAULT false,
    pdf_generated boolean DEFAULT false,
    interpret_model character varying(100),
    interpret_tool_calls integer DEFAULT 0,
    interpret_duration_secs real,
    interpret_escalated boolean DEFAULT false,
    possible_prompt_influence boolean DEFAULT false,
    narrative text,
    working_notes text,
    executive_summary text,
    report_json jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    pipeline_status character varying(20) DEFAULT 'completed'::character varying,
    current_stage character varying(50),
    stage_timings jsonb DEFAULT '{}'::jsonb,
    llm_cost_usd numeric(8,4),
    plain_english_summary text,
    submitted_by character varying(255) DEFAULT NULL::character varying
);


--
-- Name: analyses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analyses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analyses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analyses_id_seq OWNED BY public.analyses.id;


--
-- Name: analysis_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_iocs (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    ioc_id bigint NOT NULL,
    source_stage character varying(50) NOT NULL,
    confidence character varying(20) DEFAULT 'high'::character varying,
    context text
);


--
-- Name: analysis_iocs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analysis_iocs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analysis_iocs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analysis_iocs_id_seq OWNED BY public.analysis_iocs.id;


--
-- Name: analysis_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_tags (
    analysis_id bigint NOT NULL,
    tag_id bigint NOT NULL
);


--
-- Name: analysis_techniques; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.analysis_techniques (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    technique_id bigint NOT NULL,
    source_stage character varying(50) NOT NULL,
    source_detail character varying(200)
);


--
-- Name: analysis_techniques_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.analysis_techniques_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: analysis_techniques_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.analysis_techniques_id_seq OWNED BY public.analysis_techniques.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id integer NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    user_id character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    action character varying(50) NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id character varying(255),
    details jsonb
);


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: capabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.capabilities (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    description text NOT NULL,
    source_stage character varying(50) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: capabilities_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.capabilities_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: capabilities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.capabilities_id_seq OWNED BY public.capabilities.id;


--
-- Name: ioc_values; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_values (
    id bigint NOT NULL,
    type character varying(50) NOT NULL,
    value text NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: correlated_iocs; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.correlated_iocs AS
 SELECT iv.id AS ioc_id,
    iv.type,
    iv.value,
    iv.first_seen,
    iv.last_seen,
    count(DISTINCT a.sample_id) AS distinct_samples,
    count(DISTINCT a.id) AS distinct_analyses,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE (a.malware_family_guess IS NOT NULL)) AS families
   FROM ((public.ioc_values iv
     JOIN public.analysis_iocs ai ON ((ai.ioc_id = iv.id)))
     JOIN public.analyses a ON ((a.id = ai.analysis_id)))
  GROUP BY iv.id, iv.type, iv.value, iv.first_seen, iv.last_seen
 HAVING (count(DISTINCT a.sample_id) > 1)
  ORDER BY (count(DISTINCT a.sample_id)) DESC;


--
-- Name: infrastructure_overlap; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.infrastructure_overlap AS
 SELECT iv.value AS indicator,
    iv.type,
    iv.first_seen,
    iv.last_seen,
    count(DISTINCT a.malware_family_guess) AS family_count,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE (a.malware_family_guess IS NOT NULL)) AS families,
    count(DISTINCT a.sample_id) AS sample_count
   FROM ((public.ioc_values iv
     JOIN public.analysis_iocs ai ON ((ai.ioc_id = iv.id)))
     JOIN public.analyses a ON ((a.id = ai.analysis_id)))
  WHERE ((iv.type)::text = ANY ((ARRAY['ipv4-addr'::character varying, 'ipv6-addr'::character varying, 'domain-name'::character varying, 'url'::character varying])::text[]))
  GROUP BY iv.id, iv.value, iv.type, iv.first_seen, iv.last_seen
 HAVING (count(DISTINCT a.malware_family_guess) > 1)
  ORDER BY (count(DISTINCT a.malware_family_guess)) DESC, (count(DISTINCT a.sample_id)) DESC;


--
-- Name: investigation_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_messages (
    id bigint NOT NULL,
    session_id bigint NOT NULL,
    role text NOT NULL,
    content text NOT NULL,
    tool_name text,
    input_tokens integer,
    output_tokens integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: investigation_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.investigation_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: investigation_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.investigation_messages_id_seq OWNED BY public.investigation_messages.id;


--
-- Name: investigation_pins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_pins (
    id bigint NOT NULL,
    session_id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    pin_type text NOT NULL,
    value text NOT NULL,
    ioc_type text,
    context text DEFAULT ''::text NOT NULL,
    promoted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: investigation_pins_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.investigation_pins_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: investigation_pins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.investigation_pins_id_seq OWNED BY public.investigation_pins.id;


--
-- Name: investigation_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_sessions (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    user_sub text NOT NULL,
    model text DEFAULT 'claude-sonnet-4-6'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    total_input_tokens integer DEFAULT 0 NOT NULL,
    total_output_tokens integer DEFAULT 0 NOT NULL,
    total_cost_usd numeric(10,4) DEFAULT 0 NOT NULL,
    max_turns integer DEFAULT 50 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: investigation_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.investigation_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: investigation_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.investigation_sessions_id_seq OWNED BY public.investigation_sessions.id;


--
-- Name: ioc_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_tags (
    ioc_id bigint NOT NULL,
    tag_id bigint NOT NULL
);


--
-- Name: ioc_technique_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_technique_mappings (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    ioc_id bigint NOT NULL,
    technique_id bigint NOT NULL,
    evidence text,
    method character varying(20) DEFAULT 'programmatic'::character varying NOT NULL,
    confidence character varying(20) DEFAULT 'high'::character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: ioc_technique_mappings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_technique_mappings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_technique_mappings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_technique_mappings_id_seq OWNED BY public.ioc_technique_mappings.id;


--
-- Name: ioc_values_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_values_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_values_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_values_id_seq OWNED BY public.ioc_values.id;


--
-- Name: network_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_events (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    event_type character varying(20) NOT NULL,
    dns_query character varying(500),
    dns_type character varying(10),
    dns_answers jsonb,
    http_method character varying(10),
    http_url text,
    http_host character varying(500),
    http_status integer,
    http_user_agent text,
    src_ip character varying(45),
    src_port integer,
    dst_ip character varying(45),
    dst_port integer,
    "timestamp" timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: network_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.network_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: network_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.network_events_id_seq OWNED BY public.network_events.id;


--
-- Name: pipeline_stage_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pipeline_stage_events (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    stage character varying(50) NOT NULL,
    status character varying(20) NOT NULL,
    detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pipeline_stage_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.pipeline_stage_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pipeline_stage_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.pipeline_stage_events_id_seq OWNED BY public.pipeline_stage_events.id;


--
-- Name: samples; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.samples (
    id bigint NOT NULL,
    sha256 character varying(64) NOT NULL,
    sha1 character varying(40),
    md5 character varying(32),
    ssdeep character varying(200),
    filename character varying(500),
    file_type text,
    file_mime character varying(100),
    file_size bigint,
    entropy real,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: signatures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signatures (
    id bigint NOT NULL,
    analysis_id bigint NOT NULL,
    name character varying(200) NOT NULL,
    severity integer DEFAULT 0,
    description text,
    source_stage character varying(50) DEFAULT 'Cape'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: recent_analyses; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.recent_analyses AS
 SELECT a.id AS analysis_id,
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
    ( SELECT count(*) AS count
           FROM public.analysis_iocs ai
          WHERE (ai.analysis_id = a.id)) AS ioc_count,
    ( SELECT count(*) AS count
           FROM public.analysis_techniques at2
          WHERE (at2.analysis_id = a.id)) AS technique_count,
    ( SELECT count(*) AS count
           FROM public.signatures sg
          WHERE (sg.analysis_id = a.id)) AS signature_count,
    ( SELECT count(*) AS count
           FROM public.network_events ne
          WHERE (ne.analysis_id = a.id)) AS network_event_count
   FROM (public.analyses a
     JOIN public.samples s ON ((s.id = a.sample_id)))
  ORDER BY a.started_at DESC;


--
-- Name: sample_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sample_relationships (
    id bigint NOT NULL,
    parent_id bigint NOT NULL,
    child_id bigint NOT NULL,
    relationship character varying(50) NOT NULL,
    context text,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: sample_lineage; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.sample_lineage AS
 SELECT p.sha256 AS parent_sha256,
    p.filename AS parent_filename,
    c.sha256 AS child_sha256,
    c.filename AS child_filename,
    sr.relationship,
    sr.context,
    sr.discovered_at
   FROM ((public.sample_relationships sr
     JOIN public.samples p ON ((p.id = sr.parent_id)))
     JOIN public.samples c ON ((c.id = sr.child_id)))
  ORDER BY sr.discovered_at DESC;


--
-- Name: sample_relationships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sample_relationships_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sample_relationships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sample_relationships_id_seq OWNED BY public.sample_relationships.id;


--
-- Name: sample_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sample_tags (
    sample_id bigint NOT NULL,
    tag_id bigint NOT NULL
);


--
-- Name: samples_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.samples_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: samples_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.samples_id_seq OWNED BY public.samples.id;


--
-- Name: signatures_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.signatures_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: signatures_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.signatures_id_seq OWNED BY public.signatures.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id bigint NOT NULL,
    name character varying(200) NOT NULL,
    taxonomy character varying(100),
    color character varying(7) DEFAULT '#607d8b'::character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tags_id_seq OWNED BY public.tags.id;


--
-- Name: technique_values; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.technique_values (
    id bigint NOT NULL,
    technique_id character varying(20) NOT NULL,
    technique_name character varying(300),
    tactics character varying(100)[],
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: technique_frequency; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.technique_frequency AS
 SELECT tv.technique_id,
    tv.technique_name,
    tv.tactics,
    count(DISTINCT a.sample_id) AS distinct_samples,
    count(DISTINCT a.id) AS distinct_analyses,
    array_agg(DISTINCT at2.source_stage) AS seen_in_stages,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE (a.malware_family_guess IS NOT NULL)) AS families
   FROM ((public.technique_values tv
     JOIN public.analysis_techniques at2 ON ((at2.technique_id = tv.id)))
     JOIN public.analyses a ON ((a.id = at2.analysis_id)))
  GROUP BY tv.id, tv.technique_id, tv.technique_name, tv.tactics
  ORDER BY (count(DISTINCT a.sample_id)) DESC;


--
-- Name: technique_values_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.technique_values_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: technique_values_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.technique_values_id_seq OWNED BY public.technique_values.id;


--
-- Name: analyses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyses ALTER COLUMN id SET DEFAULT nextval('public.analyses_id_seq'::regclass);


--
-- Name: analysis_iocs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_iocs ALTER COLUMN id SET DEFAULT nextval('public.analysis_iocs_id_seq'::regclass);


--
-- Name: analysis_techniques id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_techniques ALTER COLUMN id SET DEFAULT nextval('public.analysis_techniques_id_seq'::regclass);


--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Name: capabilities id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities ALTER COLUMN id SET DEFAULT nextval('public.capabilities_id_seq'::regclass);


--
-- Name: investigation_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_messages ALTER COLUMN id SET DEFAULT nextval('public.investigation_messages_id_seq'::regclass);


--
-- Name: investigation_pins id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_pins ALTER COLUMN id SET DEFAULT nextval('public.investigation_pins_id_seq'::regclass);


--
-- Name: investigation_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_sessions ALTER COLUMN id SET DEFAULT nextval('public.investigation_sessions_id_seq'::regclass);


--
-- Name: ioc_technique_mappings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_technique_mappings ALTER COLUMN id SET DEFAULT nextval('public.ioc_technique_mappings_id_seq'::regclass);


--
-- Name: ioc_values id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_values ALTER COLUMN id SET DEFAULT nextval('public.ioc_values_id_seq'::regclass);


--
-- Name: network_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_events ALTER COLUMN id SET DEFAULT nextval('public.network_events_id_seq'::regclass);


--
-- Name: pipeline_stage_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pipeline_stage_events ALTER COLUMN id SET DEFAULT nextval('public.pipeline_stage_events_id_seq'::regclass);


--
-- Name: sample_relationships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_relationships ALTER COLUMN id SET DEFAULT nextval('public.sample_relationships_id_seq'::regclass);


--
-- Name: samples id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.samples ALTER COLUMN id SET DEFAULT nextval('public.samples_id_seq'::regclass);


--
-- Name: signatures id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures ALTER COLUMN id SET DEFAULT nextval('public.signatures_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags ALTER COLUMN id SET DEFAULT nextval('public.tags_id_seq'::regclass);


--
-- Name: technique_values id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_values ALTER COLUMN id SET DEFAULT nextval('public.technique_values_id_seq'::regclass);


--
-- Name: analyses analyses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyses
    ADD CONSTRAINT analyses_pkey PRIMARY KEY (id);


--
-- Name: analysis_iocs analysis_iocs_analysis_id_ioc_id_source_stage_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_iocs
    ADD CONSTRAINT analysis_iocs_analysis_id_ioc_id_source_stage_key UNIQUE (analysis_id, ioc_id, source_stage);


--
-- Name: analysis_iocs analysis_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_iocs
    ADD CONSTRAINT analysis_iocs_pkey PRIMARY KEY (id);


--
-- Name: analysis_tags analysis_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_tags
    ADD CONSTRAINT analysis_tags_pkey PRIMARY KEY (analysis_id, tag_id);


--
-- Name: analysis_techniques analysis_techniques_analysis_id_technique_id_source_stage_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_techniques
    ADD CONSTRAINT analysis_techniques_analysis_id_technique_id_source_stage_key UNIQUE (analysis_id, technique_id, source_stage);


--
-- Name: analysis_techniques analysis_techniques_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_techniques
    ADD CONSTRAINT analysis_techniques_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: capabilities capabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_pkey PRIMARY KEY (id);


--
-- Name: investigation_messages investigation_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_messages
    ADD CONSTRAINT investigation_messages_pkey PRIMARY KEY (id);


--
-- Name: investigation_pins investigation_pins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_pins
    ADD CONSTRAINT investigation_pins_pkey PRIMARY KEY (id);


--
-- Name: investigation_sessions investigation_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_sessions
    ADD CONSTRAINT investigation_sessions_pkey PRIMARY KEY (id);


--
-- Name: ioc_tags ioc_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_tags
    ADD CONSTRAINT ioc_tags_pkey PRIMARY KEY (ioc_id, tag_id);


--
-- Name: ioc_technique_mappings ioc_technique_mappings_analysis_id_ioc_id_technique_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_technique_mappings
    ADD CONSTRAINT ioc_technique_mappings_analysis_id_ioc_id_technique_id_key UNIQUE (analysis_id, ioc_id, technique_id);


--
-- Name: ioc_technique_mappings ioc_technique_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_technique_mappings
    ADD CONSTRAINT ioc_technique_mappings_pkey PRIMARY KEY (id);


--
-- Name: ioc_values ioc_values_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_values
    ADD CONSTRAINT ioc_values_pkey PRIMARY KEY (id);


--
-- Name: ioc_values ioc_values_type_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_values
    ADD CONSTRAINT ioc_values_type_value_key UNIQUE (type, value);


--
-- Name: network_events network_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_events
    ADD CONSTRAINT network_events_pkey PRIMARY KEY (id);


--
-- Name: pipeline_stage_events pipeline_stage_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pipeline_stage_events
    ADD CONSTRAINT pipeline_stage_events_pkey PRIMARY KEY (id);


--
-- Name: sample_relationships sample_relationships_parent_id_child_id_relationship_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_relationships
    ADD CONSTRAINT sample_relationships_parent_id_child_id_relationship_key UNIQUE (parent_id, child_id, relationship);


--
-- Name: sample_relationships sample_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_relationships
    ADD CONSTRAINT sample_relationships_pkey PRIMARY KEY (id);


--
-- Name: sample_tags sample_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_tags
    ADD CONSTRAINT sample_tags_pkey PRIMARY KEY (sample_id, tag_id);


--
-- Name: samples samples_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.samples
    ADD CONSTRAINT samples_pkey PRIMARY KEY (id);


--
-- Name: samples samples_sha256_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.samples
    ADD CONSTRAINT samples_sha256_key UNIQUE (sha256);


--
-- Name: signatures signatures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures
    ADD CONSTRAINT signatures_pkey PRIMARY KEY (id);


--
-- Name: tags tags_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_name_key UNIQUE (name);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: technique_values technique_values_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_values
    ADD CONSTRAINT technique_values_pkey PRIMARY KEY (id);


--
-- Name: technique_values technique_values_technique_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.technique_values
    ADD CONSTRAINT technique_values_technique_id_key UNIQUE (technique_id);


--
-- Name: idx_analyses_family; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_family ON public.analyses USING btree (malware_family_guess);


--
-- Name: idx_analyses_family_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_family_trgm ON public.analyses USING gin (malware_family_guess public.gin_trgm_ops);


--
-- Name: idx_analyses_narrative_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_narrative_trgm ON public.analyses USING gin (narrative public.gin_trgm_ops);


--
-- Name: idx_analyses_report_json; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_report_json ON public.analyses USING gin (report_json);


--
-- Name: idx_analyses_sample_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_sample_id ON public.analyses USING btree (sample_id);


--
-- Name: idx_analyses_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_severity ON public.analyses USING btree (severity);


--
-- Name: idx_analyses_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_started_at ON public.analyses USING btree (started_at);


--
-- Name: idx_analyses_task_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analyses_task_id ON public.analyses USING btree (task_id);


--
-- Name: idx_analysis_iocs_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analysis_iocs_analysis ON public.analysis_iocs USING btree (analysis_id);


--
-- Name: idx_analysis_iocs_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analysis_iocs_ioc ON public.analysis_iocs USING btree (ioc_id);


--
-- Name: idx_analysis_iocs_stage; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analysis_iocs_stage ON public.analysis_iocs USING btree (source_stage);


--
-- Name: idx_analysis_tags_tag; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analysis_tags_tag ON public.analysis_tags USING btree (tag_id);


--
-- Name: idx_analysis_techniques_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analysis_techniques_analysis ON public.analysis_techniques USING btree (analysis_id);


--
-- Name: idx_analysis_techniques_technique; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analysis_techniques_technique ON public.analysis_techniques USING btree (technique_id);


--
-- Name: idx_audit_log_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_timestamp ON public.audit_log USING btree ("timestamp");


--
-- Name: idx_audit_log_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_user_id ON public.audit_log USING btree (user_id);


--
-- Name: idx_capabilities_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_capabilities_analysis ON public.capabilities USING btree (analysis_id);


--
-- Name: idx_capabilities_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_capabilities_desc ON public.capabilities USING gin (description public.gin_trgm_ops);


--
-- Name: idx_inv_messages_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_messages_session ON public.investigation_messages USING btree (session_id);


--
-- Name: idx_inv_pins_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_pins_analysis ON public.investigation_pins USING btree (analysis_id);


--
-- Name: idx_inv_pins_session; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_pins_session ON public.investigation_pins USING btree (session_id);


--
-- Name: idx_inv_sessions_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_sessions_analysis ON public.investigation_sessions USING btree (analysis_id);


--
-- Name: idx_inv_sessions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_sessions_user ON public.investigation_sessions USING btree (user_sub);


--
-- Name: idx_ioc_tags_tag; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tags_tag ON public.ioc_tags USING btree (tag_id);


--
-- Name: idx_ioc_tech_map_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tech_map_analysis ON public.ioc_technique_mappings USING btree (analysis_id);


--
-- Name: idx_ioc_tech_map_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tech_map_ioc ON public.ioc_technique_mappings USING btree (ioc_id);


--
-- Name: idx_ioc_tech_map_method; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tech_map_method ON public.ioc_technique_mappings USING btree (method);


--
-- Name: idx_ioc_tech_map_technique; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_tech_map_technique ON public.ioc_technique_mappings USING btree (technique_id);


--
-- Name: idx_ioc_values_first_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_values_first_seen ON public.ioc_values USING btree (first_seen);


--
-- Name: idx_ioc_values_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_values_type ON public.ioc_values USING btree (type);


--
-- Name: idx_ioc_values_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_values_type_value ON public.ioc_values USING btree (type, value);


--
-- Name: idx_ioc_values_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_values_value ON public.ioc_values USING gin (value public.gin_trgm_ops);


--
-- Name: idx_network_events_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_analysis ON public.network_events USING btree (analysis_id);


--
-- Name: idx_network_events_dns_query; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_dns_query ON public.network_events USING gin (dns_query public.gin_trgm_ops);


--
-- Name: idx_network_events_dst_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_dst_ip ON public.network_events USING btree (dst_ip);


--
-- Name: idx_network_events_dst_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_dst_port ON public.network_events USING btree (dst_port);


--
-- Name: idx_network_events_http_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_http_host ON public.network_events USING btree (http_host);


--
-- Name: idx_network_events_http_url; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_http_url ON public.network_events USING gin (http_url public.gin_trgm_ops);


--
-- Name: idx_network_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_network_events_type ON public.network_events USING btree (event_type);


--
-- Name: idx_pipeline_events_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pipeline_events_analysis ON public.pipeline_stage_events USING btree (analysis_id);


--
-- Name: idx_pipeline_events_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pipeline_events_created ON public.pipeline_stage_events USING btree (created_at);


--
-- Name: idx_pipeline_events_stage; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pipeline_events_stage ON public.pipeline_stage_events USING btree (stage);


--
-- Name: idx_sample_rel_child; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sample_rel_child ON public.sample_relationships USING btree (child_id);


--
-- Name: idx_sample_rel_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sample_rel_parent ON public.sample_relationships USING btree (parent_id);


--
-- Name: idx_sample_rel_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sample_rel_type ON public.sample_relationships USING btree (relationship);


--
-- Name: idx_sample_tags_tag; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sample_tags_tag ON public.sample_tags USING btree (tag_id);


--
-- Name: idx_samples_filename; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_samples_filename ON public.samples USING gin (filename public.gin_trgm_ops);


--
-- Name: idx_samples_first_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_samples_first_seen ON public.samples USING btree (first_seen);


--
-- Name: idx_samples_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_samples_sha256 ON public.samples USING btree (sha256);


--
-- Name: idx_signatures_analysis; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_signatures_analysis ON public.signatures USING btree (analysis_id);


--
-- Name: idx_signatures_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_signatures_name ON public.signatures USING btree (name);


--
-- Name: idx_signatures_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_signatures_severity ON public.signatures USING btree (severity DESC);


--
-- Name: idx_tags_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tags_name ON public.tags USING btree (name);


--
-- Name: idx_tags_taxonomy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tags_taxonomy ON public.tags USING btree (taxonomy);


--
-- Name: idx_technique_values_tactics; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_technique_values_tactics ON public.technique_values USING gin (tactics);


--
-- Name: idx_technique_values_tid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_technique_values_tid ON public.technique_values USING btree (technique_id);


--
-- Name: analyses analyses_sample_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analyses
    ADD CONSTRAINT analyses_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES public.samples(id) ON DELETE CASCADE;


--
-- Name: analysis_iocs analysis_iocs_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_iocs
    ADD CONSTRAINT analysis_iocs_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: analysis_iocs analysis_iocs_ioc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_iocs
    ADD CONSTRAINT analysis_iocs_ioc_id_fkey FOREIGN KEY (ioc_id) REFERENCES public.ioc_values(id) ON DELETE CASCADE;


--
-- Name: analysis_tags analysis_tags_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_tags
    ADD CONSTRAINT analysis_tags_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: analysis_tags analysis_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_tags
    ADD CONSTRAINT analysis_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: analysis_techniques analysis_techniques_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_techniques
    ADD CONSTRAINT analysis_techniques_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: analysis_techniques analysis_techniques_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.analysis_techniques
    ADD CONSTRAINT analysis_techniques_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.technique_values(id) ON DELETE CASCADE;


--
-- Name: capabilities capabilities_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.capabilities
    ADD CONSTRAINT capabilities_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: investigation_messages investigation_messages_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_messages
    ADD CONSTRAINT investigation_messages_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.investigation_sessions(id) ON DELETE CASCADE;


--
-- Name: investigation_pins investigation_pins_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_pins
    ADD CONSTRAINT investigation_pins_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: investigation_pins investigation_pins_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_pins
    ADD CONSTRAINT investigation_pins_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.investigation_sessions(id) ON DELETE CASCADE;


--
-- Name: investigation_sessions investigation_sessions_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_sessions
    ADD CONSTRAINT investigation_sessions_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: ioc_tags ioc_tags_ioc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_tags
    ADD CONSTRAINT ioc_tags_ioc_id_fkey FOREIGN KEY (ioc_id) REFERENCES public.ioc_values(id) ON DELETE CASCADE;


--
-- Name: ioc_tags ioc_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_tags
    ADD CONSTRAINT ioc_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: ioc_technique_mappings ioc_technique_mappings_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_technique_mappings
    ADD CONSTRAINT ioc_technique_mappings_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: ioc_technique_mappings ioc_technique_mappings_ioc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_technique_mappings
    ADD CONSTRAINT ioc_technique_mappings_ioc_id_fkey FOREIGN KEY (ioc_id) REFERENCES public.ioc_values(id) ON DELETE CASCADE;


--
-- Name: ioc_technique_mappings ioc_technique_mappings_technique_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_technique_mappings
    ADD CONSTRAINT ioc_technique_mappings_technique_id_fkey FOREIGN KEY (technique_id) REFERENCES public.technique_values(id) ON DELETE CASCADE;


--
-- Name: network_events network_events_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_events
    ADD CONSTRAINT network_events_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: pipeline_stage_events pipeline_stage_events_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pipeline_stage_events
    ADD CONSTRAINT pipeline_stage_events_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- Name: sample_relationships sample_relationships_child_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_relationships
    ADD CONSTRAINT sample_relationships_child_id_fkey FOREIGN KEY (child_id) REFERENCES public.samples(id) ON DELETE CASCADE;


--
-- Name: sample_relationships sample_relationships_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_relationships
    ADD CONSTRAINT sample_relationships_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.samples(id) ON DELETE CASCADE;


--
-- Name: sample_tags sample_tags_sample_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_tags
    ADD CONSTRAINT sample_tags_sample_id_fkey FOREIGN KEY (sample_id) REFERENCES public.samples(id) ON DELETE CASCADE;


--
-- Name: sample_tags sample_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sample_tags
    ADD CONSTRAINT sample_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: signatures signatures_analysis_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures
    ADD CONSTRAINT signatures_analysis_id_fkey FOREIGN KEY (analysis_id) REFERENCES public.analyses(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--
"""


def upgrade() -> None:
    op.execute(BASELINE_SQL)


def downgrade() -> None:
    # The genesis revision is not reversible -- there is no prior schema state.
    raise NotImplementedError("Cannot downgrade past the baseline revision.")
