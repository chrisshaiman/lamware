# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pin has to survive the whole chain: defaults -> template -> config -> call.

A knob that exists in the dataclass but is never rendered into config.json, or
rendered but never passed to submit_to_cape, is a knob wired to nothing -- and
it would read as "configurable" in review while the production path stayed
exactly as broken as before.
"""
import ast
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"
sys.path.insert(0, str(FILES))

from lamware_pipeline.config import PipelineConfig  # noqa: E402

DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "pipeline" / "defaults" / "main.yml").read_text())
TEMPLATE = (ROOT / "ansible" / "roles" / "pipeline"
            / "templates" / "config.json.j2").read_text()
RUN_PIPELINE = ast.parse((FILES / "run-pipeline.py").read_text())

NEW_KEYS = ("cape_machine", "cape_office_machine", "cape_memory_dump")


def test_the_dataclass_accepts_the_new_keys():
    for k in NEW_KEYS:
        assert k in PipelineConfig.model_fields, f"{k} missing from PipelineConfig"


def test_an_older_config_json_still_loads():
    """These are defaulted on purpose: a host whose config.json predates them
    must keep working rather than crash every stage at import."""
    for k in NEW_KEYS:
        assert PipelineConfig.model_fields[k].default is not None, (
            f"{k} has no default, so an existing config.json would fail to load")


def test_the_defaults_are_the_safe_ones():
    assert DEFAULTS["pipeline_cape_machine"] == "clean"
    assert DEFAULTS["pipeline_cape_office_machine"] == "office"
    assert DEFAULTS["pipeline_cape_memory_dump"] is False, (
        "memory dumps default ON would reintroduce 8.6 GB a run with "
        "delete_memdump=no, which filled the disk and stalled CAPE")


def test_every_key_is_rendered_into_config_json():
    for k in NEW_KEYS:
        assert f'"{k}"' in TEMPLATE, f"{k} is never written to config.json"
        assert f"pipeline_{k}" in TEMPLATE, f"{k} is not fed from the role default"


def _call_keywords(tree, func_name):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == func_name):
            return {kw.arg for kw in node.keywords}
    return None


def test_run_pipeline_passes_the_pin_to_the_api():
    kws = _call_keywords(RUN_PIPELINE, "submit_to_cape")
    assert kws is not None, "run-pipeline no longer calls submit_to_cape"
    assert "machine" in kws, "the submission is unpinned again"
    assert "memory_dump" in kws, "memory dumping is not driven by config"


def test_run_pipeline_derives_the_machine_rather_than_hardcoding_one():
    """Hardcoding `clean` at the call site would send Office documents to a guest
    with no Office installed."""
    assert _call_keywords(RUN_PIPELINE, "derive_machine") is not None or any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "derive_machine" for n in ast.walk(RUN_PIPELINE)), (
        "run-pipeline does not derive the guest from the routing tags")


def test_volatility_is_told_whether_a_dump_was_requested():
    kws = _call_keywords(RUN_PIPELINE, "run_volatility")
    assert kws is not None and "memory_dump_requested" in kws, (
        "the Volatility stage cannot tell 'disabled' from 'CAPE failed'")
