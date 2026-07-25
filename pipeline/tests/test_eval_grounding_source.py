# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Grounding must score against everything the model saw, including tool output.

Pass 1 (2026-07-25) scored IOCs only against the initial Ghidra dump, so values
the model legitimately read out of decompiled code counted as fabrications: the
cloud arm showed 40/47 (85%) "fabricated", including `-id=` and `~%u.tmp` which a
separate baseline run independently confirmed were real.
"""
import json
from pathlib import Path

from grounding_check import grounding_scorecard
from lamware_eval.runner import tool_output_text


def _audit(tmp_path: Path, records) -> Path:
    d = tmp_path / "llm_audit"
    d.mkdir(parents=True, exist_ok=True)
    (d / "tool_calls.json").write_text(json.dumps(records))
    return tmp_path


def test_collects_values_returned_by_tools(tmp_path):
    out = _audit(tmp_path, [
        {"tool": "decompile_function", "args": {"name": "entry"},
         "result": {"code": "sprintf(buf, \"~%u.tmp\", id);"}},
        {"tool": "get_strings_at", "args": {}, "result": ["-id=", "MilcoSoft_#Rip_X"]},
    ])
    text = tool_output_text(out)
    assert "~%u.tmp" in text and "-id=" in text and "MilcoSoft_#Rip_X" in text


def test_missing_or_malformed_audit_is_not_fatal(tmp_path):
    assert tool_output_text(tmp_path) == ""          # no audit dir at all
    bad = tmp_path / "llm_audit"
    bad.mkdir()
    (bad / "tool_calls.json").write_text("{not json")
    assert tool_output_text(tmp_path) == ""          # malformed must not sink the cell


def test_tool_derived_ioc_is_grounded_not_fabricated(tmp_path):
    """The exact pass-1 failure: an IOC found via a tool call, absent from the
    initial dump, must score as grounded once tool output is included."""
    ghidra_dump = json.dumps({"analyzed_files": [{"functions_count": 75}]})
    out = _audit(tmp_path, [
        {"tool": "decompile_function", "result": {"code": "fopen(\"~%u.tmp\")"}},
    ])
    analysis = {"code_level_iocs": [{"value": "~%u.tmp"}]}

    before = grounding_scorecard(analysis, ghidra_dump)
    assert before["fabricated"] == ["~%u.tmp"]  # the bug we shipped in pass 1

    after = grounding_scorecard(analysis, ghidra_dump + " " + tool_output_text(out))
    assert after["fabricated"] == [] and after["grounded"] == 1
