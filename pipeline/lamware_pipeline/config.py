# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Runtime pipeline configuration, read from a Jinja-rendered config.json.

Phase 1 covers the malfind block (the config round-trip POC). Phase 2 expands
this model to the full ~45 deploy-time values and migrates the rest of the
run-pipeline.py.j2:99-154 constant block. Secrets (cape_api_key, db_password)
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

    @classmethod
    def load(cls, path: str) -> "PipelineConfig":
        return cls.model_validate_json(Path(path).read_text())
