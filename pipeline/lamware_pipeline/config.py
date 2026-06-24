# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Runtime pipeline configuration, read from a Jinja-rendered config.json.

Phase 1 covers the malfind block (the config round-trip POC). Phase 2b-1 landed
the scalar tuning knobs + analysis-tool CMD paths (malfind from Phase 1);
collections and secrets are still pending. Secrets (cape_api_key, db_password)
are intentionally NOT here — they stay in the no_log env path.
"""
from pathlib import Path

from pydantic import BaseModel


class PipelineConfig(BaseModel):
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

    @classmethod
    def load(cls, path: str) -> "PipelineConfig":
        return cls.model_validate_json(Path(path).read_text())
