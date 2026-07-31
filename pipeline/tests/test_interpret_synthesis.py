# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guards: the two-phase RE synthesis (forced submit_analysis + think:false)."""
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[2]
          / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py")


def _t() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _func(name: str) -> str:
    """Source of one top-level function, from its `def` to the next one.

    Several of these guards used a fixed character window instead. That silently
    truncates the moment anyone adds a comment above the code being asserted on --
    which is exactly how adding the #246 comment broke two passing tests without
    changing a line of their subject.
    """
    body = _t().split(f"def {name}(", 1)[1]
    return body.split("\ndef ", 1)[0]


def test_phase2b_serializes_only_the_conclusion_not_the_transcript():
    """Phase 2b must build a fresh, minimal message list.

    Measured 2026-07-25 on the live llama.cpp/LiteLLM path: submit_analysis came
    back as a valid tool call at short context but as prose with NO tool call at
    ~25k chars, so passing the full transcript (concl_msgs) made local RE emit
    family=unknown with no capabilities and no IOCs.

    The symptom was real; the MECHANISM originally recorded here was not. It was
    never "a forced tool_choice ignored at scale" -- tool_choice was never applied
    at any context, because it was sent in an object form llama.cpp rejects (see
    test_tool_choice_is_a_string_not_an_object). The model was choosing freely and
    simply preferred prose on a long prompt. Keeping 2b's prompt small remains
    correct either way, which is what this guards.
    """
    block = _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]
    assert "serialize_msgs = [{" in block, (
        "phase 2b must build a fresh, minimal message list from the conclusion"
    )
    after = block.split("serialize_msgs", 1)[1][:400]
    assert "concl_msgs" not in after, (
        "phase 2b must NOT reuse concl_msgs - that sends the whole transcript"
    )


def test_phase2a_failure_is_logged_not_silent():
    """Phase 2a swallowed anthropic.APIError with a bare `pass`.

    An empty concl_text silently SKIPS phase 2b and drops the run to the legacy
    free-text path, which is the shape that made a plumbing failure read as
    "the model won't commit to a family" across two benchmark passes.
    """
    block = _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]
    assert "except anthropic.APIError:\n            pass" not in block, (
        "phase 2a must not swallow APIError silently"
    )
    assert "phase 2a failed" in block, "log the phase 2a exception"
    assert "no visible text" in block, "log the empty-but-successful case too"


def test_phase2a_disables_thinking_via_no_think():
    """The router path cannot forward chat_template_kwargs, so /no_think is the
    only lever. Measured 2026-07-25 it cut the call 154s -> 115s.

    Whether the switch still does anything is OPEN (#260): a 2026-07-30 probe on
    this transport had the /no_think arm return an empty response where the same
    request without it produced correct prose. Unchanged pending a
    production-scale A/B, so this guard stays -- but it asserts what the code
    currently DOES, not that the behaviour is settled.
    """
    block = _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]
    assert "/no_think" in block, "phase 2a prompt must carry the /no_think switch"
    assert "#260" in block, "the open question about /no_think must stay visible in the code"


def test_phase2a_carries_the_loop_tools_block_for_prefix_reuse():
    """#246: phase 2a must send the SAME tools block the loop sends.

    Tool definitions render near the front of the chat template, so omitting them
    changes the prompt at its start and llama.cpp can reuse nothing after that
    point. Measured on the 2026-07-29 run: the last loop turn reused every one of
    the 6,176 tokens available to it; phase 2a, with a 31,023-token prompt, reused
    THREE -- 1,280s of prompt evaluation, 72% of the run's wall-clock. Passing the
    same block took reuse from 0% to 99.4% both directly against llama.cpp and
    through the LiteLLM router.

    It must be TOOLS itself: a subset or a rebuilt block diverges just as badly.
    """
    block = _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]
    concl = block.split("concl = create_message(", 1)
    assert len(concl) == 2, "phase 2a must still issue its create_message call"
    # Up to the next statement, not to the first ")" -- the argument list contains
    # max(max_output_tokens, 8192), whose paren would truncate the slice early.
    call = concl[1].split("concl_text =", 1)[0]
    assert "tools=TOOLS" in call, (
        "phase 2a must pass tools=TOOLS or it re-evaluates the whole transcript (#246)"
    )


def test_phase2a_logs_a_tool_call_reply():
    """Offering tools makes a tool_use reply possible where it was not before.

    It did not occur in any probe, but an unlogged tool_use would empty
    concl_text, skip phase 2b and silently drop the run to the legacy path -- the
    same silent shape #246's sibling bugs already cost two benchmark passes.
    """
    block = _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]
    assert "tool_use" in block, "phase 2a must detect a tool_use reply"
    assert "instead of prose" in block, "and say so in the log"


def test_tool_choice_is_a_string_not_an_object():
    """llama.cpp's server accepts only a STRING for tool_choice.

    The OpenAI object form is rejected outright --
        Wrong type supplied for parameter 'tool_choice'. Expected 'string'
    -- and silently falls back to "auto". Confirmed in the llama-cpp journal on
    6 of 6 synthesis runs 2026-07-27..07-29: the "forced" call was never once
    forced. Every success so far was the model complying voluntarily.
    """
    body = _func("synthesize_analysis")
    assert '"tool_choice": "required"' in body, (
        "tool_choice must be a string; the object form is silently discarded"
    )
    assert '"tool_choice": {' not in body, (
        "the object form of tool_choice is rejected by llama.cpp"
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
    assert "def synthesize_analysis(" in _t()
    body = _func("synthesize_analysis")
    assert '"submit_analysis"' in body
    assert '"tool_choice"' in body and '"function"' in body
    assert '"enable_thinking": False' in body
    assert "/chat/completions" in body


def test_synthesize_returns_none_on_no_toolcall():
    # The helper must return None on failure so callers fall back to parse_final_response.
    assert "return None" in _func("synthesize_analysis")


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
