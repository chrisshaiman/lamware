# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the local-vs-cloud summary A/B harness (pure payload builder)."""
from llm_ab_summary import build_ab_payloads


def test_build_ab_payloads_one_per_model():
    report = {"sample_name": "x"}
    payloads = build_ab_payloads(report, ["local-qwen", "claude-haiku-4-5"])
    assert len(payloads) == 2
    assert payloads[0]["config"]["summary_model"] == "local-qwen"
    assert payloads[1]["config"]["summary_model"] == "claude-haiku-4-5"
    assert all(p["type"] == "summarize" and p["report"] is report for p in payloads)


def test_build_ab_payloads_empty_models():
    assert build_ab_payloads({"sample_name": "x"}, []) == []
