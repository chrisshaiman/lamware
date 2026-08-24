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


def test_plain_english_priced_by_its_model():
    # Plain-English cost uses the recorded model, not a hardcoded Haiku rate — so a
    # local plain-English summary is $0, while an older report (no model) falls back
    # to Haiku pricing.
    local = {"plain_english_usage": {"input_tokens": 1_000, "output_tokens": 1_000},
             "plain_english_model": "local-qwen"}
    assert db_ingest._calculate_llm_cost(local) == 0.0
    # Haiku fallback for a report missing plain_english_model, at Haiku 4.5's real
    # rate ($1.00 / $5.00 per Mtok): 1000*1.00/1e6 + 1000*5.00/1e6.
    legacy = {"plain_english_usage": {"input_tokens": 1_000, "output_tokens": 1_000}}
    assert round(db_ingest._calculate_llm_cost(legacy), 6) == round(0.001 + 0.005, 6)


def test_pricing_table_matches_published_rates():
    """Guard against per-Mtok rate drift in _LLM_PRICING.

    These rates are what Anthropic actually bills and what LiteLLM's own cost map
    uses. A drifted entry here silently mis-states every analysis's llm_cost_usd:
    the opus-4-6 row was $15/$75 (3x the real rate) and inflated 30-day reported
    spend to ~2.2x what LiteLLM recorded for the same traffic.
    """
    expected = {
        "claude-opus-4-6": {"input": 5.00, "output": 25.00},
        "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
        "claude-haiku-4-5": {"input": 1.00, "output": 5.00},
    }
    for model, rates in expected.items():
        assert db_ingest._LLM_PRICING[model] == rates, f"{model} pricing drifted"


def test_opus_priced_at_real_rate():
    # Behavioral check on the drifted row: 1M in + 500K out on opus-4-6 is
    # 1e6*5/1e6 + 5e5*25/1e6 = 5.00 + 12.50 = 17.50 (was 52.50 at the wrong rate).
    report = {
        "llm_interpretation": {
            "model_used": "claude-opus-4-6",
            "usage": {"input_tokens": 1_000_000, "output_tokens": 500_000},
        }
    }
    assert db_ingest._calculate_llm_cost(report) == 17.50


# ---------------------------------------------------------------------------
# Local-model pricing must not silently fall through to the default row.
#
# The deployed summary and plain-english model is `local-qwen-llamacpp` (the
# Ollama->llama.cpp switch), and the eval arms use `local-qwen-llamacpp-re` /
# `local-qwen-re`. None were in _LLM_PRICING, so free local inference was billed
# at the "default" Sonnet rate ($3/$15 per Mtok) on every run, surfaced in
# llm_cost_usd and the spend dashboard. The old test only covered "local-qwen",
# a name production no longer emits — the exact drift these guard against.
# ---------------------------------------------------------------------------

# The names the deployed config actually emits into a report's model fields, read
# from Ansible defaults so a rename there fails HERE rather than at the invoice.
def _deployed_local_pipeline_models():
    import re
    from pathlib import Path

    defaults = (Path(__file__).resolve().parents[2]
                / "ansible" / "roles" / "pipeline" / "defaults" / "main.yml")
    text = defaults.read_text(encoding="utf-8")
    names = set()
    for key in ("pipeline_summary_model", "pipeline_plain_english_model"):
        m = re.search(rf'^{key}:\s*"([^"]+)"', text, re.MULTILINE)
        assert m, f"{key} not found in {defaults} — did the var get renamed?"
        names.add(m.group(1))
    return names


def test_deployed_local_models_are_priced_at_zero():
    # Every model the deployed pipeline config names for the summary/plain-english
    # stages must resolve to $0, not the default Sonnet fallback.
    for model in _deployed_local_pipeline_models():
        assert model.startswith("local-"), (
            f"{model!r} is configured as a pipeline model but is not a local- name; "
            "if it is a cloud model it needs an explicit _LLM_PRICING entry")
        assert db_ingest._price_for_model(model) == {"input": 0.0, "output": 0.0}, (
            f"{model!r} is not priced at zero — free local inference would be billed "
            "at the default cloud rate")


def test_llamacpp_summary_priced_at_zero_end_to_end():
    # The whole-report path, with the model name production actually uses.
    report = {
        "executive_summary": {
            "model": "local-qwen-llamacpp",
            "usage": {"input_tokens": 2_800, "output_tokens": 3_000},
        },
        "plain_english_usage": {"input_tokens": 2_800, "output_tokens": 3_000},
        "plain_english_model": "local-qwen-llamacpp",
    }
    # has_usage is True (real tokens), so a nonzero result would be the mispricing.
    assert db_ingest._calculate_llm_cost(report) == 0.0


def test_local_re_and_seeded_variants_priced_at_zero():
    for model in ("local-qwen-llamacpp-re", "local-qwen-re",
                  "local-qwen-llamacpp-re-s1337"):
        assert db_ingest._price_for_model(model) == {"input": 0.0, "output": 0.0}


def test_unknown_model_still_falls_back_to_default():
    # A genuinely unrecognised (non-local) model keeps the default estimate — the
    # prefix rule must not swallow cloud models into $0.
    assert db_ingest._price_for_model("some-new-cloud-model") == \
        db_ingest._LLM_PRICING["default"]
