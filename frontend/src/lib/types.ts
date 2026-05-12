// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// TypeScript interfaces mirroring FastAPI response shapes.
// Derived from api/app/models/ and api/app/routers/.

// ---------------------------------------------------------------------------
// Sample
// ---------------------------------------------------------------------------

export interface Sample {
  id: number;
  sha256: string;
  sha1: string | null;
  md5: string | null;
  ssdeep: string | null;
  filename: string | null;
  file_type: string | null;
  file_mime: string | null;
  file_size: number | null;
  entropy: number | null;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string | null;
}

/** Subset of Sample returned in the analyses list view. */
export interface SampleSummary {
  id: number;
  sha256: string;
  filename: string | null;
  file_type: string | null;
  file_mime: string | null;
  file_size: number | null;
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/** Item in the paginated analyses list (/api/analyses). */
export interface AnalysisListItem {
  id: number;
  task_id: string;
  started_at: string;
  completed_at: string | null;
  severity: string | null;
  malscore: number | null;
  malware_family_guess: string | null;
  pipeline_status: string | null;
  current_stage: string | null;
  sample: SampleSummary;
  ioc_count: number;
  technique_count: number;
  signature_count: number;
}

/** Paginated response from /api/analyses. */
export interface AnalysisListResponse {
  total: number;
  offset: number;
  limit: number;
  analyses: AnalysisListItem[];
}

/** IOC nested in analysis detail. */
export interface AnalysisIoc {
  id: number;
  ioc_id: number;
  type: string;
  value: string;
  source_stage: string;
  confidence: string | null;
  context: string | null;
}

/** Technique nested in analysis detail. */
export interface AnalysisTechnique {
  id: number;
  technique_id: string;
  technique_name: string;
  tactics: string[];
  source_stage: string;
  source_detail: string | null;
}

/** Capability nested in analysis detail. */
export interface Capability {
  id: number;
  description: string;
  source_stage: string;
}

/** Signature nested in analysis detail. */
export interface Signature {
  id: number;
  name: string;
  severity: number | null;
  description: string | null;
  source_stage: string;
}

/** Network event nested in analysis detail. */
export interface NetworkEvent {
  id: number;
  event_type: string;
  dns_query: string | null;
  dns_type: string | null;
  dns_answers: unknown[] | null;
  http_method: string | null;
  http_url: string | null;
  http_host: string | null;
  http_status: number | null;
  http_user_agent: string | null;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  timestamp: string | null;
}

/** Full analysis detail from /api/analyses/{id}. */
export interface AnalysisDetail {
  id: number;
  task_id: string;
  started_at: string;
  completed_at: string | null;
  severity: string | null;
  malscore: number | null;
  malware_family_guess: string | null;
  pipeline_status: string | null;
  current_stage: string | null;

  // Stage completion flags
  triage_completed: boolean | null;
  cape_completed: boolean | null;
  cape_task_id: number | null;
  volatility_completed: boolean | null;
  volatility_triggered: boolean | null;
  ghidra_completed: boolean | null;
  ghidra_triggered: boolean | null;
  interpret_completed: boolean | null;
  summary_completed: boolean | null;
  pdf_generated: boolean | null;

  // AI RE metadata
  interpret_model: string | null;
  interpret_tool_calls: number | null;
  interpret_duration_secs: number | null;
  interpret_escalated: boolean | null;
  possible_prompt_influence: boolean | null;

  // Narratives
  narrative: string | null;
  working_notes: string | null;
  executive_summary: string | null;
  plain_english_summary: string | null;

  // Cost & timing
  llm_cost_usd: number | null;
  stage_timings: Record<string, number> | null;

  created_at: string;

  // Nested objects
  sample: Omit<Sample, "first_seen" | "last_seen" | "created_at"> | null;
  iocs: AnalysisIoc[];
  techniques: AnalysisTechnique[];
  capabilities: Capability[];
  signatures: Signature[];
  network_events: NetworkEvent[];
}

/** Response from DELETE /api/analyses/{id}. */
export interface DeleteAnalysisResponse {
  deleted: boolean;
  analysis_id: number;
  task_id: string;
  files_removed: string[];
}

// ---------------------------------------------------------------------------
// IOC browser
// ---------------------------------------------------------------------------

/** Item from /api/iocs. */
export interface IocBrowseItem {
  id: number;
  type: string;
  value: string;
  first_seen: string | null;
  last_seen: string | null;
  analysis_count: number;
}

// ---------------------------------------------------------------------------
// Technique browser
// ---------------------------------------------------------------------------

/** Item from /api/techniques. */
export interface TechniqueBrowseItem {
  id: number;
  technique_id: string;
  technique_name: string;
  tactics: string[];
  first_seen: string | null;
  analysis_count: number;
}

// ---------------------------------------------------------------------------
// Families
// ---------------------------------------------------------------------------

/** Item from /api/families. */
export interface FamilyItem {
  family: string;
  count: number;
  last_seen: string | null;
}

// ---------------------------------------------------------------------------
// Pipeline status
// ---------------------------------------------------------------------------

/** Pipeline item (running or recently completed). */
export interface PipelineItem {
  id: number;
  task_id: string;
  pipeline_status: string;
  current_stage: string;
  stage_timings: Record<string, number>;
  started_at: string | null;
  completed_at: string | null;
  severity: string | null;
  malscore: number | null;
  malware_family_guess: string | null;
  sample: {
    sha256: string;
    filename: string | null;
    file_type: string | null;
  };
}

/** Response from /api/pipeline/status. */
export interface PipelineStatusResponse {
  running: PipelineItem[];
  recent_completed: PipelineItem[];
  as_of: string;
}

// ---------------------------------------------------------------------------
// Alerts / operational health
// ---------------------------------------------------------------------------

export interface DiskInfo {
  total_gb: number;
  used_gb: number;
  free_gb: number;
  used_pct: number;
}

export interface AlertsResponse {
  network_monitor: Record<string, unknown> | null;
  auto_feeder: Record<string, unknown> | null;
  paused: boolean;
  disk: DiskInfo | null;
  latest_digest: Record<string, unknown> | null;
  cost_today_usd: number | null;
  as_of: string;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export interface StatsResponse {
  total_analyses: number;
  total_samples: number;
  total_iocs: number;
  total_techniques: number;
  families_detected: number;
  cost_today: number;
  cost_week: number;
  cost_total: number;
  analyses_today: number;
  analyses_week: number;
}

// ---------------------------------------------------------------------------
// Feeder
// ---------------------------------------------------------------------------

export interface FeederStatusResponse {
  status: string;
  paused: boolean;
  state: Record<string, unknown> | null;
  as_of: string;
}

export interface FeederActionResponse {
  status: string;
  pause_file?: string;
  consecutive_failures?: number;
}

// ---------------------------------------------------------------------------
// Sample submission
// ---------------------------------------------------------------------------

export interface SubmitResponse {
  status: string;
  submission_id: string;
  filename: string;
  size_bytes: number;
  pipeline_pid: number;
  message: string;
}
