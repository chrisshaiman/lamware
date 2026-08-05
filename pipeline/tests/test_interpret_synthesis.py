# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guards: single-call RE synthesis (forced submit_analysis, prefix intact).

Synthesis used to be two phases. 2a summarised the investigation in prose; 2b converted
that prose into the schema over a separate OpenAI request. 2b never saw the tool output,
so every IOC had to survive a round-trip through English before anything structured
looked at it — a bottleneck sitting directly upstream of `grounded_ratio`, the metric
the eval harness is built on (#298).

The split existed because a forced `submit_analysis` returned prose at ~25k context
while complying at 1.6k. That observation was real; the mechanism recorded for it was
not. `tool_choice` was never "ignored at scale" — it was never applied AT ALL, at any
context, because it was sent in the OpenAI object form llama.cpp rejects. The model was
choosing freely both times.

Synthesis is now ONE call: the transcript in context, `tool_choice` forcing
submit_analysis, verified with a control arm.

THE STANDING HAZARD IS #246. The chat template renders tool definitions near the FRONT
of the prompt, so any change to the tools block invalidates the whole KV prefix after
it. Phase 2a once had a 31,023-token prompt and reused THREE tokens — 1,280s of prompt
evaluation, 72% of the run's wall-clock. That is why submit_analysis is declared in the
LOOP's tools rather than added at synthesis time, and why several guards below exist
only to keep that block byte-identical.
"""
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


def _synth() -> str:
    return _t().split("def local_synthesize", 1)[1].split("# ---- Agentic loop", 1)[0]


def _code_only() -> str:
    """Source with comments and docstrings stripped.

    An absence guard that reads prose is worthless: this file's own explanation of WHY
    `/no_think` was removed contains the string `/no_think`, so a naive `not in source`
    fails on a correct file. The same bit the smoke-gate guard, which found its own
    documentation instead of the recipe it was checking for.

    Uses the tokenizer rather than a regex — `#` and quotes appear inside string
    literals all over this file, and a regex that mangles them would produce a
    different, quieter wrong answer.
    """
    import io
    import tokenize
    out = []
    src = _t()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.NL):
                continue
            if tok.type == tokenize.STRING and tok.line.strip().startswith(
                    ('"""', "'''", 'r"""')):
                continue  # docstring
            out.append(tok.string)
    except tokenize.TokenError:  # pragma: no cover - source must parse anyway
        return src
    return "\n".join(out)


# --- the #246 hazard: one tools block, unchanged everywhere ------------------


def test_submit_analysis_is_declared_in_the_loop_tools_block():
    """THE prefix guard.

    Adding submit_analysis only at synthesis time would change the tools block between
    the loop and synthesis, invalidating the entire KV prefix — #246, measured at 1,280s
    of prompt evaluation and 72% of a run's wall-clock. Declaring it from turn 1 keeps
    the block byte-identical across every request of the run.
    """
    tools_block = _t().split("TOOLS: list[dict[str, Any]] = [", 1)[1].split("\n]", 1)[0]
    assert '"name": "submit_analysis"' in tools_block, (
        "submit_analysis must be in the LOOP's tools block, not added at synthesis "
        "time — a tools block that changes mid-run re-evaluates the whole transcript "
        "(#246, #298)")


def test_the_schema_is_defined_before_the_tools_block_that_uses_it():
    t = _t()
    assert t.index("SUBMIT_ANALYSIS_SCHEMA = {") < t.index("TOOLS: list[dict[str, Any]] = ["), (
        "SUBMIT_ANALYSIS_SCHEMA must be defined above TOOLS or the module cannot import")


def test_synthesis_carries_the_loop_tools_block_for_prefix_reuse():
    """Measured 0% -> 99.4% reuse when this was added. It must pass TOOLS ITSELF, not a
    subset or a rebuilt list — byte-identical or the prefix breaks again."""
    call = _synth().split("create_message(", 1)[1][:400]
    assert "tools=TOOLS" in call, (
        "synthesis must pass tools=TOOLS or it re-evaluates the whole transcript (#246)")


# --- forcing the call --------------------------------------------------------


def test_synthesis_forces_submit_analysis_with_the_anthropic_object_form():
    """The Anthropic route takes an OBJECT; llama.cpp's OpenAI route took a STRING.

    Getting this wrong is silent: the old code sent the OpenAI object form to a server
    that wanted a string, which logged a type warning and fell back to "auto". Six of
    six synthesis runs were "forced" without ever being forced.

    Verified 2026-08-05 on /v1/messages with a discriminating probe — a question no
    tool should answer, so voluntary compliance could not be mistaken for forcing:
        no tool_choice   stop=end_turn  tools=[]
        {"type":"tool"}  stop=tool_use  tools=['submit_analysis']
    """
    call = _synth().split("create_message(", 1)[1][:500]
    assert '"type": "tool"' in call and '"name": "submit_analysis"' in call, (
        "synthesis must force submit_analysis using the Anthropic object form "
        "{'type':'tool','name':...}; the string form is an OpenAI-ism this route "
        "does not accept")


def test_the_forced_tool_call_is_read_as_the_analysis():
    """The point of #298: the schema is filled with the transcript in context, so IOCs
    come from the tool output rather than from prose about the tool output."""
    block = _synth()
    assert 'b.name == "submit_analysis"' in block, (
        "synthesis must read the forced tool call's input as the analysis")
    assert "return args" in block


def test_a_useless_forced_call_still_falls_back():
    """A forced call can still return junk. The prose parse stays as a net."""
    block = _synth()
    assert "falling back" in block
    assert "parse_final_response(" in _t()


# --- the loop must not dispatch a tool Ghidra cannot run ---------------------


def test_the_loop_intercepts_submit_analysis():
    """It is declared for prefix reasons, but Ghidra has no handler for it.

    Forwarding it to the orchestrator would surface as an unknown-tool error.
    """
    t = _t()
    assert 'if block.name == "submit_analysis":' in t, (
        "the loop must intercept submit_analysis rather than dispatching it")


def test_the_interception_does_not_consume_tool_budget():
    """Nothing was executed, so charging for it would silently shrink the run's real
    depth — the trap #234 documents for deferrals."""
    t = _t()
    intercept = t.split('if block.name == "submit_analysis":', 1)[1].split("continue", 1)[0]
    assert "tool_calls_used += 1" not in intercept, (
        "intercepting submit_analysis must not increment tool_calls_used")
    assert "calls_this_turn += 1" not in intercept


# --- #297: the switch that never worked --------------------------------------


def test_no_think_is_gone():
    """`/no_think` was inert. Measured 2026-08-05, identical prompt:
        plain                    thinking=3111  text=  0
        + /no_think              thinking=2948  text=266
        enable_thinking:false    thinking=   0  text=989

    3111 -> 2948 is noise. The working switch is chat_template_kwargs, which LiteLLM
    does not forward on the Anthropic route (re-measured post-#285). A prompt asking
    for something it does not get is worse than not asking (#297).
    """
    assert "/no_think" not in _code_only(), (
        "/no_think does not suppress reasoning and must not be re-added; use "
        "chat_template_kwargs if a route ever forwards it (#297)")


# --- phase 2b is gone --------------------------------------------------------


def test_phase2b_is_gone():
    code = _code_only()
    assert "def synthesize_analysis(" not in code, (
        "phase 2b filled the schema from PROSE and never saw the tool output (#298)")
    assert "/chat/completions" not in code, (
        "the separate OpenAI synthesis leg is removed with 2b")


# --- unchanged properties ----------------------------------------------------


def test_synthesis_failure_is_logged_not_silent():
    """Returning nothing with no output cost a full benchmark pass to diagnose."""
    block = _synth()
    assert "[synth]" in block, "synthesis fallbacks must log why"
    assert "stop_reason" in block, (
        "log stop_reason — it is what identifies a forced call that produced nothing")


def test_synthesis_records_its_cost():
    """Synthesis has no `turn` event, so without this its cost appears nowhere (#299)."""
    assert 'log_request_result("synth_2a"' in _t()


def test_submit_analysis_schema_defined():
    t = _t()
    assert "SUBMIT_ANALYSIS_SCHEMA = {" in t
    block = t.split("SUBMIT_ANALYSIS_SCHEMA = {", 1)[1][:1500]
    for field in ("malware_family_guess", "capabilities", "attack_techniques",
                  "code_level_iocs", "narrative"):
        assert field in block, field


def test_all_synthesis_sites_use_the_local_synthesizer():
    t = _t()
    assert "def local_synthesize(" in t
    assert t.count("local_synthesize(") >= 4


def test_reasoning_preservation_guard_turn_present():
    t = _t()
    assert "emit_turn(" in t
