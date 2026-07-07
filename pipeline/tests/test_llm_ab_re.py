# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the local-vs-cloud agentic-RE A/B harness (pure functions)."""
import json

from llm_ab_re import build_re_configs, extract_metrics


def test_cloud_arm_leaves_backend_unset():
    cfgs = build_re_configs({"model": "x", "escalation_model": "claude-opus-4-6"},
                            ["claude-sonnet-4-6"])
    assert len(cfgs) == 1
    assert cfgs[0]["model"] == "claude-sonnet-4-6"
    assert "re_backend" not in cfgs[0]
    assert cfgs[0]["escalation_model"] == "claude-opus-4-6"  # production escalation kept


def test_local_arm_routes_local_and_disables_escalation():
    cfgs = build_re_configs({"model": "x", "escalation_model": "claude-opus-4-6"},
                            ["local-qwen-re"])
    assert cfgs[0]["model"] == "local-qwen-re"
    assert cfgs[0]["re_backend"] == "local"
    assert cfgs[0]["escalation_model"] == "local-qwen-re"  # no fallback to Claude


def test_one_config_per_model_preserving_order():
    cfgs = build_re_configs({"model": "x"}, ["claude-sonnet-4-6", "local-qwen-re"])
    assert [c["model"] for c in cfgs] == ["claude-sonnet-4-6", "local-qwen-re"]


def test_metrics_completed_run_with_tool_errors(tmp_path):
    audit = tmp_path / "tc.json"
    audit.write_text(json.dumps([
        {"tool": "list_functions", "result": {"ok": 1}},
        {"tool": "decompile_function", "error": "bad tool_use translation"},
    ]))
    res = {"enabled": True, "tool_calls_used": 2, "model_final": "local-qwen-re",
           "duration_seconds": 812.0, "analysis": {"family": "wannacry"},
           "audit": {"tool_call_log": str(audit)}}
    m = extract_metrics(res)
    assert m["completed"] is True
    assert m["tool_calls_logged"] == 2
    assert m["tool_call_errors"] == 1
    assert m["tool_call_error_rate"] == 0.5
    assert m["family"] == "wannacry"


def test_metrics_errored_run_not_completed():
    res = {"enabled": True, "error": "Interpret loop error: boom"}
    m = extract_metrics(res)
    assert m["completed"] is False
    assert m["error"] == "Interpret loop error: boom"
    assert m["tool_call_error_rate"] == 0.0


def test_local_arm_gets_bigger_token_budget():
    cfgs = build_re_configs({"model": "x", "max_output_tokens": 4096}, ["claude-sonnet-4-6", "local-qwen-re"])
    cloud, local = cfgs
    assert cloud["max_output_tokens"] == 4096          # cloud unchanged
    assert local["max_output_tokens"] == 8192          # local bumped for thinking headroom
