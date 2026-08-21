# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Runtime pipeline configuration, read from a Jinja-rendered config.json.

Phase 1 covers the malfind block (the config round-trip POC). Phase 2b-1 landed
the scalar tuning knobs + analysis-tool CMD paths (malfind from Phase 1). Phase
2b-2 landed the collection values: the interpret submodel plus the volatility
triggers and extra-plugins maps. Phase 3b landed the non-secret DB connection
fields (db_host/db_port/db_name/db_user) so db_ingest/pipeline_status can stop
carrying their own Jinja for them. Secrets (cape_api_key, db_password) are
intentionally NOT here — they stay in the no_log env path.
"""
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class InterpretConfig(BaseModel):
    """LLM-interpretation stage knobs. model_dump() reproduces the dict the
    orchestrator body passes as interpret_config= and indexes by key name."""
    model_config = ConfigDict(extra="forbid")
    model: str
    escalation_threshold: int
    escalation_model: str
    max_output_tokens: int
    max_tool_calls: int
    max_imports: int
    max_strings: int
    max_string_length: int
    summary_model: str          # model for the executive/kill-chain summary
    plain_english_model: str    # model for the plain-English summary
    # Wall-clock budget for the whole summarize container run. Defaulted rather than
    # required so a config.json written before this key still loads — the eval harness
    # passes whole config dicts through and an older one would fail validation, which
    # `extra="forbid"` makes a hard error rather than a warning.
    summary_timeout: int = 900


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    malfind_enabled: bool
    malfind_max_candidates: int
    malfind_min_size: int
    malfind_max_size: int
    malfind_min_score: int
    malfind_benign_processes: list[str]

    # Phase 2b-1 — analysis-tool command paths
    cape_api_url: str
    triage_cmd: str
    volatility_cmd: str
    ghidra_cmd: str
    dotnet_cmd: str
    go_cmd: str
    pyinstaller_cmd: str
    java_cmd: str
    office_cmd: str
    powershell_cmd: str
    screenshot_cmd: str
    pdf_cmd: str
    interpret_cmd: str
    pcap_cmd: str

    # Phase 2b-1 — scalar tuning knobs
    interpret_enabled: bool
    interpret_timeout: int
    reports_dir: str
    cape_poll_interval: int
    cape_timeout: int
    pcap_enabled: bool
    pcap_timeout: int
    evasion_hunter_enabled: bool
    evasion_max_signatures: int
    evasion_min_binary_size: int
    volatility_ramdisk: str
    volatility_parallel_workers: int

    # Phase 2b-2 — collections
    interpret: InterpretConfig
    volatility_triggers: list[str]
    volatility_extra_plugins: dict[str, dict[str, list[str]]]

    # Phase 3b — DB connection (non-secret; PIPELINE_DB_PASSWORD comes from the env)
    db_host: str
    db_port: int
    db_name: str
    db_user: str

    # Campaign-graph relationship thresholds (2026-06-26)
    relationship_max_ioc_frequency: int
    relationship_ssdeep_threshold: int

    @classmethod
    def load(cls, path: str) -> "PipelineConfig":
        return cls.model_validate_json(Path(path).read_text())
