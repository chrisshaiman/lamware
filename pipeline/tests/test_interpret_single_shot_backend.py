# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every interpret path must reach the same backend the pipeline is pointed at (#590).

interpret-ghidra.py has TWO transport flags, not one:

    re_backend           the agentic Ghidra path
    single_shot_backend  .NET, Java, Office macro, PowerShell

#584 set re_backend and stopped there. The single-shot paths kept the
/anthropic passthrough, which serves cloud models only, so every one of them
returned

    NotFoundError: 404 - not_found_error: model: local-qwen-llamacpp-re

Six of ten samples in the 2026-09-09 corpus run produced no analysis for that
reason, and the 404 sat one level down in llm_interpretation.analysis.error
where the outer error check — and my run driver — never looked. All ten were
reported OK.

Two of the four paths did not even consult the flag: Java and Office called
client.messages.create directly. Routing them was not enough either — on
/v1/messages qwen3.6 spends the whole budget reasoning and returns 0 chars, so
they had to move to single_shot_completion, which uses the OpenAI leg with
enable_thinking:false.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
INTERPRET_SRC = (ROOT / "ansible" / "roles" / "interpret" / "files"
                 / "interpret-ghidra.py").read_text(encoding="utf-8")
DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text(encoding="utf-8"))
CONFIG_TEMPLATE = (ROOT / "ansible" / "roles" / "pipeline" / "templates"
                   / "config.json.j2").read_text(encoding="utf-8")

SINGLE_SHOT_PATHS = ("dotnet", "java_cfr", "office_macro", "powershell")


def _path_block(analysis_type: str) -> str:
    """The body of one single-shot branch, from its guard to its sys.exit(0)."""
    start = INTERPRET_SRC.index(f'if ghidra_data.get("analysis_type") == "{analysis_type}":')
    end = INTERPRET_SRC.index("sys.exit(0)", start)
    return INTERPRET_SRC[start:end]


def test_no_single_shot_path_hardcodes_the_cloud_client():
    """Java and Office called client.messages.create directly, so the flag could
    not have helped them however it was set."""
    for t in SINGLE_SHOT_PATHS:
        block = _path_block(t)
        assert "client.messages.create(" not in block, (
            f"the {t} path calls the anthropic client directly; it will 404 on a "
            f"local model name no matter what single_shot_backend says")


def test_every_single_shot_path_honours_the_backend_flag():
    for t in SINGLE_SHOT_PATHS:
        block = _path_block(t)
        assert "single_shot_completion(" in block, f"{t} does not use single_shot_completion"
        assert "ss_local" in block, f"{t} ignores the single_shot_backend flag"


def test_the_local_leg_transport_errors_are_caught():
    """"the local leg raises transport errors, and without this they escape the
    handler and kill the container mid-stage" — the .NET path already said so;
    the converted paths need it too."""
    for t in SINGLE_SHOT_PATHS:
        block = _path_block(t)
        assert "httpx.HTTPError" in block, (
            f"the {t} path catches only anthropic errors, so a local transport "
            f"failure kills the container instead of being reported")


def test_the_flag_ships_as_local_alongside_re_backend():
    """Setting one and not the other IS the bug. Automated runs are local, so
    both must be."""
    assert DEFAULTS["interpret_single_shot_backend"] == "local"
    assert DEFAULTS["interpret_re_backend"] == "local"


def test_both_transports_agree_with_the_model():
    """A local model on a cloud transport can only 404 — on either path."""
    model_is_local = DEFAULTS["interpret_model"].startswith("local-")
    for var in ("interpret_re_backend", "interpret_single_shot_backend"):
        assert (DEFAULTS[var] == "local") == model_is_local, (
            f"{var}={DEFAULTS[var]} disagrees with "
            f"interpret_model={DEFAULTS['interpret_model']}")


def test_the_rendered_config_carries_the_flag():
    """Absent, it defaults to cloud inside the container and the paths 404
    silently."""
    assert '"single_shot_backend"' in CONFIG_TEMPLATE
    assert "interpret_single_shot_backend" in CONFIG_TEMPLATE, \
        "the flag is hardcoded rather than driven by the role variable"


def test_the_pydantic_model_accepts_it():
    """PipelineConfig is extra='forbid': shipping a key it does not model kills
    the pipeline at startup, before triage."""
    src = (ROOT / "pipeline" / "lamware_pipeline" / "config.py").read_text(encoding="utf-8")
    assert re.search(r"^\s*single_shot_backend:\s*str", src, re.M), \
        "PipelineConfig has no single_shot_backend field"
