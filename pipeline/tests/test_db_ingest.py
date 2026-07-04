# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for db_ingest helpers — importable via the conftest harness."""
import db_ingest


def test_calculate_llm_cost_fallback_without_usage():
    # No usage data anywhere in the report -> documented $0.50 fallback estimate.
    assert db_ingest._calculate_llm_cost({}) == 0.50


def test_calculate_llm_cost_computes_from_usage():
    # llm_interpretation with claude-sonnet-4-6 pricing: input $3.00, output $15.00
    # per million tokens. cost = in*price_in/1e6 + out*price_out/1e6.
    #   1_000_000 * 3.00 / 1e6  = 3.00
    #     500_000 * 15.00 / 1e6 = 7.50
    #   total                   = 10.50
    report = {
        "llm_interpretation": {
            "model_used": "claude-sonnet-4-6",
            "usage": {"input_tokens": 1_000_000, "output_tokens": 500_000},
        }
    }
    cost = db_ingest._calculate_llm_cost(report)
    assert cost > 0
    assert cost == 10.50


def test_local_qwen_summary_priced_at_zero():
    # A summary produced by the local model must cost $0 (local inference has no
    # per-token API cost), not the $0.50 unknown-model fallback. has_usage is True
    # (real tokens), so the return is the computed 0.0, not the fallback.
    report = {
        "executive_summary": {
            "model": "local-qwen",
            "usage": {"input_tokens": 5_000, "output_tokens": 2_000},
        }
    }
    assert db_ingest._calculate_llm_cost(report) == 0.0
