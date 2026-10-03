# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""`dotnet_mode` reaches the pipeline from the role variable, and only valid values do (#646).

CLAUDE.md §1: a switch must be carried by every config path — the interpret
role's defaults (what ships), config.json.j2 (what renders), PipelineConfig
(what the pipeline accepts, extra="forbid"), and run-pipeline's use of it.
#590 was a flag set in one of these and not another. This renders the actual
template with the actual role defaults, as test_config_template_renders does,
and validates the result.
"""
import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from lamware_pipeline.config import PipelineConfig

ROOT = Path(__file__).resolve().parents[2]
INTERPRET_DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text(encoding="utf-8"))

_spec = importlib.util.spec_from_file_location(
    "_cfg_render", Path(__file__).parent / "test_config_template_renders.py")
_cfg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_cfg)


def _render_with(**role_vars) -> PipelineConfig:
    """The template rendered with the pipeline role's defaults plus `role_vars`
    (in a play, the interpret role's defaults are in scope too)."""
    return PipelineConfig.model_validate(json.loads(_cfg._render(**role_vars)))


def test_the_shipped_default_is_agentic():
    assert INTERPRET_DEFAULTS["interpret_dotnet_mode"] == "agentic"
    cfg = _render_with(interpret_dotnet_mode=INTERPRET_DEFAULTS["interpret_dotnet_mode"])
    assert cfg.interpret.dotnet_mode == "agentic"
    assert cfg.interpret.model_dump()["dotnet_mode"] == "agentic", (
        "run-pipeline reads INTERPRET_CONFIG, which is model_dump()")


def test_the_role_variable_drives_the_rendered_value():
    """Not hardcoded in the template: setting the variable changes the config."""
    assert _render_with(interpret_dotnet_mode="single_shot").interpret.dotnet_mode == "single_shot"


def test_without_the_variable_the_template_falls_back_to_agentic():
    assert _render_with().interpret.dotnet_mode == "agentic"


def test_a_typo_fails_at_startup_instead_of_choosing_a_path():
    with pytest.raises(Exception):
        _render_with(interpret_dotnet_mode="agentc")
