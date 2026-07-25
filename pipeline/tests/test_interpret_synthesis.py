# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guards: the two-phase RE synthesis (forced submit_analysis + think:false)."""
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parents[2]
            / "ansible" / "roles" / "interpret" / "templates" / "interpret-ghidra.py.j2")


def _t() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_phase2b_serializes_only_the_conclusion_not_the_transcript():
    """A forced tool_choice is silently ignored at RE-scale context.

    Measured 2026-07-25 on the live llama.cpp/LiteLLM path: a forced
    submit_analysis returned finish_reason=tool_calls with valid JSON at short
    context, but finish_reason=stop with prose and NO tool call at ~25k chars.
    Passing the full investigation transcript (concl_msgs) put every real run in
    the failing regime, so local RE always emitted family=unknown with no
    capabilities and no IOCs.
    """
    block = _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]
    assert "serialize_msgs = [{" in block, (
        "phase 2b must build a fresh, minimal message list from the conclusion"
    )
    after = block.split("serialize_msgs", 1)[1][:400]
    assert "concl_msgs" not in after, (
        "phase 2b must NOT reuse concl_msgs - that sends the whole transcript"
    )


def test_synthesis_failure_is_logged_not_silent():
    """Returning None with no output cost a full benchmark pass to diagnose."""
    block = _t().split("def synthesize_analysis", 1)[1].split("def parse_final_response", 1)[0]
    assert "[synth]" in block, "synthesis fallbacks must log why"
    assert "finish_reason" in block, (
        "log finish_reason - it is what identifies the ignored-forced-tool case"
    )


def test_submit_analysis_schema_defined():
    t = _t()
    assert "SUBMIT_ANALYSIS_SCHEMA = {" in t
    block = t.split("SUBMIT_ANALYSIS_SCHEMA = {", 1)[1][:1500]
    for field in ("malware_family_guess", "capabilities", "attack_techniques",
                  "code_level_iocs", "narrative"):
        assert field in block, field


def test_synth_openai_base_read_from_env():
    t = _t()
    assert 'os.environ.get("LITELLM_OPENAI_BASE_URL"' in t


def test_synthesize_analysis_defined_forced_tool_thinkfalse():
    t = _t()
    assert "def synthesize_analysis(" in t
    body = t.split("def synthesize_analysis(", 1)[1][:2000]
    assert '"submit_analysis"' in body
    assert '"tool_choice"' in body and '"function"' in body
    assert '"enable_thinking": False' in body
    assert "/chat/completions" in body


def test_synthesize_returns_none_on_no_toolcall():
    # The helper must return None on failure so callers fall back to parse_final_response.
    body = _t().split("def synthesize_analysis(", 1)[1][:2000]
    assert "return None" in body


def test_all_three_synthesis_sites_use_local_synthesizer():
    t = _t()
    # DRY: one closure (local_synthesize) wraps the two-phase synthesis; it must be
    # defined once and invoked at all three local-backend synthesis sites (def + 3 calls).
    assert "def local_synthesize(" in t
    assert t.count("local_synthesize(") >= 4
    assert "synthesize_analysis(" in t  # the closure calls the helper


def test_local_synthesis_falls_back_to_parse_final():
    t = _t()
    assert "parse_final_response(" in t  # safety net preserved


def test_reasoning_preservation_guard_turn_present():
    t = _t()
    assert "summarize your findings" in t.lower()
