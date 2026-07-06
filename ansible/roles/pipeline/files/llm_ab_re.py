# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A/B the agentic Ghidra RE stage across models (local Qwen vs cloud Claude).

Replays a saved Ghidra project through the interpret container's agentic loop
once per model and writes the analyses + reliability metrics side-by-side.
Increment-2 measurement tooling — see
docs/superpowers/specs/2026-07-06-local-re-ab-design.md. Sibling of llm_ab_summary.py.
"""
import argparse  # noqa: F401
import json  # noqa: F401
import time  # noqa: F401
from pathlib import Path  # noqa: F401

from stages.interpret import run_interpret  # noqa: F401


def build_re_configs(base_config: dict, models: list[str]) -> list[dict]:
    """One interpret_config per arm. A model whose name starts with 'local'
    routes through the LiteLLM router (re_backend=local) with escalation pinned
    to itself (pure-local, no Claude fallback). Cloud models keep base config."""
    configs: list[dict] = []
    for m in models:
        cfg = {**base_config, "model": m}
        if m.startswith("local"):
            cfg["re_backend"] = "local"
            cfg["escalation_model"] = m
        configs.append(cfg)
    return configs
