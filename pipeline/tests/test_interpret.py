# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the interpret stage's Ghidra tool brokering guards and audit log.

Regression guards for two bugs found on live analyses:

1. Non-native analysis paths (script/office/etc.) have no Ghidra project, but
   the interpret container still let the LLM call Ghidra tools. The broker
   shelled out `run-ghidra --tool "" ""` and every call failed with
   "realpath: '': No such file or directory", polluting the narrative.

2. run_interpret is invoked up to three times per pipeline run (main
   interpretation, evasion_analysis, visual_analysis) with the same
   output_dir, and each invocation overwrote llm_audit/tool_calls.json —
   the last (usually tool-less) call clobbered the real log to [].
"""

from stages.interpret import audit_filename, ghidra_unavailable_error, run_ghidra_tool

# ---------------------------------------------------------------------------
# Guard: brokering a Ghidra tool call without a project must not shell out
# ---------------------------------------------------------------------------


def test_run_ghidra_tool_rejects_empty_project_dir():
    result = run_ghidra_tool("", "prog", "list_functions", {}, "/bin/false")
    assert "error" in result
    assert "no ghidra project" in result["error"].lower()


def test_run_ghidra_tool_rejects_empty_program_name():
    result = run_ghidra_tool("/some/project", "", "list_functions", {}, "/bin/false")
    assert "error" in result
    assert "no ghidra project" in result["error"].lower()


def test_run_ghidra_tool_rejects_none_args():
    result = run_ghidra_tool(None, None, "decompile_function", {"name": "main"}, "/bin/false")
    assert "error" in result


def test_unavailable_error_names_analysis_type_and_says_stop():
    msg = ghidra_unavailable_error("script_analysis")
    assert "script_analysis" in msg
    # The message must tell the LLM not to keep retrying tools.
    assert "do not retry" in msg.lower()


def test_unavailable_error_handles_missing_type():
    msg = ghidra_unavailable_error(None)
    assert "unknown" in msg
    assert "do not retry" in msg.lower()


# ---------------------------------------------------------------------------
# Audit log: each run_interpret invocation writes its own file
# ---------------------------------------------------------------------------


def test_audit_filename_default_is_backward_compatible():
    # The main native-PE interpretation passes a per-file Ghidra result with
    # no analysis_type — it must keep the historical tool_calls.json name.
    assert audit_filename(None) == "tool_calls.json"
    assert audit_filename("") == "tool_calls.json"


def test_audit_filename_is_distinct_per_analysis_type():
    assert audit_filename("evasion_hunter") == "tool_calls_evasion_hunter.json"
    assert audit_filename("visual_analysis") == "tool_calls_visual_analysis.json"
    assert audit_filename("script_analysis") == "tool_calls_script_analysis.json"
    # Distinct types never collide with each other or the default.
    names = {audit_filename(t) for t in (None, "evasion_hunter", "visual_analysis")}
    assert len(names) == 3


def test_audit_filename_sanitizes_unexpected_characters():
    # analysis_type is internal, but a path separator must never reach a filename.
    assert "/" not in audit_filename("weird/../type")
    assert "\\" not in audit_filename("weird\\type")
