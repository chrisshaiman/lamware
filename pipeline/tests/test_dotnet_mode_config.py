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


# --- the size bounds (review of #673: CPU-shaped numbers must be config) ---------

def test_the_shipped_limits_reach_the_pipeline_unchanged():
    """Role defaults -> rendered config -> InterpretConfig -> the toolbox's own
    dataclass: the same numbers at every step, so the deployed bounds are the
    ones the code was tested with."""
    from dataclasses import asdict

    from stages.dotnet_tools import DotnetToolLimits
    shipped = INTERPRET_DEFAULTS["interpret_dotnet_tool_limits"]
    cfg = _render_with(interpret_dotnet_tool_limits=shipped)
    dumped = cfg.interpret.model_dump()["dotnet_tool_limits"]
    assert dumped == shipped
    assert dumped == asdict(DotnetToolLimits()), (
        "the pydantic defaults and the toolbox defaults have drifted")
    assert asdict(DotnetToolLimits.from_config(dumped)) == shipped


def test_a_raised_limit_reaches_the_tools():
    """A faster host sets one number in the role; a tool result grows with it."""
    from stages.dotnet_tools import DotnetToolbox
    cfg = _render_with(interpret_dotnet_tool_limits={"page_chars": 20_000})
    limits = cfg.interpret.model_dump()["dotnet_tool_limits"]
    assert limits["page_chars"] == 20_000 and limits["lines_max"] == 150
    src = "class A {\n void M() {\n" + "  int x = 1;\n" * 3000 + " }\n}\n"
    small = DotnetToolbox(src).call("get_method_source", {"class_name": "A", "method_name": "M"})
    big = DotnetToolbox(src, limits=limits).call(
        "get_method_source", {"class_name": "A", "method_name": "M"})
    assert len(small["source"]) <= 6_000 < len(big["source"]) <= 20_000
    assert big["pages"] < small["pages"]


def test_the_limits_shape_the_first_message():
    from stages.dotnet_tools import build_dotnet_interpret_init
    src = "class A {\n" + "".join(f" void M{i}() {{ }}\n" for i in range(50)) + "}\n"
    init = build_dotnet_interpret_init({"decompilation": {"source": src}}, {}, [], "agentic",
                                       {"toc_max_methods": 3})
    assert init["table_of_contents"]["methods_listed"] == 3


def test_run_interpret_hands_the_configured_limits_to_the_tools(tmp_path):
    import sys
    import textwrap

    from stages.dotnet_tools import build_dotnet_interpret_init
    from stages.interpret import run_interpret
    src = "class A {\n void M() {\n" + "  int x = 1;\n" * 3000 + " }\n}\n"
    init = build_dotnet_interpret_init({"decompilation": {"source": src}}, {}, [], "agentic")
    fake = tmp_path / "fake"
    fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''
        import json, sys
        json.loads(sys.stdin.readline())
        print(json.dumps({"type": "tool_call", "id": "1", "tool": "get_method_source",
                          "args": {"class_name": "A", "method_name": "M"}}), flush=True)
        reply = json.loads(sys.stdin.readline())
        print(json.dumps({"type": "final", "analysis": {"n": len(reply["result"]["source"])},
                          "model_used": "m", "tool_calls_used": 1}), flush=True)
    '''))
    fake.chmod(0o755)
    out = tmp_path / "out"
    out.mkdir()
    res = run_interpret(init, out, str(fake), True, 30,
                        {"model": "m", "dotnet_tool_limits": {"page_chars": 500}},
                        "/nonexistent/run-ghidra")
    assert 0 < res["analysis"]["n"] <= 500


@pytest.mark.parametrize("bad", [{"page_chars": 0}, {"page_chars": -5}, {"pages": 3}])
def test_a_bad_limit_fails_at_startup(bad):
    with pytest.raises(Exception):
        _render_with(interpret_dotnet_tool_limits=bad)
