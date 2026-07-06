# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the local-vs-cloud agentic-RE A/B harness (pure functions)."""
from llm_ab_re import build_re_configs


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
