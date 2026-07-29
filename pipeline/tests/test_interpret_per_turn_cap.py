# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tool calls must be bounded PER TURN, not just per run (#234).

`max_tool_calls` caps a run's total but never the size of a single batch, so the model
could emit several parallel `decompile_function` calls in one response. Measured on a
qwen@30 cell 2026-07-28: one turn added **14,848 tokens (~59,000 chars)** — about six
9KB decompiles at once — and took 55 minutes, because prompt-eval also degrades from
66 to 8.6 tok/s as context grows. That combination is what made deep local runs
quadratic.

The fix defers surplus calls instead of dropping them. Two properties matter and both
are asserted here:

  1. EVERY tool_use block still receives a tool_result. The Messages API rejects the
     next request otherwise, so a deferral that skipped the result would break the run
     outright rather than merely slow it.
  2. A deferred call does NOT count against tool_calls_used. Nothing executed, and
     charging for it would silently shrink the run's real depth — a 30-call run would
     quietly become a 12-call one.

interpret-ghidra.py.j2 is a Jinja template, so nothing can import or execute it (#205).
These are static assertions over its text plus a compile check of the rendered result.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TMPL_PATH = (ROOT / "ansible" / "roles" / "interpret" / "templates"
             / "interpret-ghidra.py.j2")
TMPL = TMPL_PATH.read_text()
DEFAULTS = (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text()


def _deferral_block() -> str:
    """The per-turn guard and its body."""
    start = TMPL.index("if calls_this_turn >= max_tool_calls_per_turn:")
    return TMPL[start:start + 1400]


def test_the_per_turn_counter_exists_and_gates_execution():
    assert "calls_this_turn = 0" in TMPL, "per-turn counter must reset each turn"
    assert "if calls_this_turn >= max_tool_calls_per_turn:" in TMPL
    assert "calls_this_turn += 1" in TMPL


def test_counter_resets_each_turn_not_once_per_run():
    """Initialised inside the loop body — a run-level counter would cap the whole run."""
    loop = TMPL.index("if response.stop_reason == \"tool_use\":")
    init = TMPL.index("calls_this_turn = 0")
    assert init > loop, (
        "calls_this_turn must be initialised inside the tool_use branch; hoisting it "
        "out would turn a per-turn cap into a second per-run cap.")


def test_every_deferred_block_still_gets_a_tool_result():
    """A tool_use with no matching tool_result makes the NEXT request malformed."""
    block = _deferral_block()
    assert '"type": "tool_result"' in block
    assert '"tool_use_id": block.id' in block


def test_deferral_does_not_consume_the_run_budget():
    """tool_calls_used must not be incremented before the deferral `continue`."""
    block = _deferral_block()
    upto_continue = block[:block.index("continue")]
    assert "tool_calls_used += 1" not in upto_continue, (
        "a deferred call executed nothing; counting it would silently shrink the run's "
        "real depth (a 30-call run quietly becoming ~12).")


def test_deferral_is_not_flagged_as_an_error():
    """is_error=True would read as a tool failure and may stop the model retrying."""
    block = _deferral_block()
    assert '"is_error": True' not in block, (
        "deferral is not a failure — marking it an error invites the model to give up "
        "on the call instead of re-requesting it.")


def test_the_deferral_message_tells_the_model_to_retry():
    """The whole design depends on the model asking again; say so explicitly."""
    block = _deferral_block()
    assert "request it again" in block.lower()
    assert "not executed" in block.lower()


def test_config_is_read_with_a_default_for_older_config_files():
    """The eval harness passes whole config dicts; a pre-#234 one would KeyError."""
    assert 'config.get("max_tool_calls_per_turn")' in TMPL, (
        "read it with .get() and a fallback — config['...'] breaks older config.json")


def test_ansible_default_is_present_and_small():
    match = re.search(r"^interpret_max_tool_calls_per_turn:\s*(\d+)", DEFAULTS, re.MULTILINE)
    assert match, "interpret_max_tool_calls_per_turn missing from the role defaults"
    value = int(match.group(1))
    assert 1 <= value <= 5, (
        f"per-turn cap is {value}; the point is to bound context growth. At the observed "
        f"9.4KB max decompile, 3 caps a turn at ~28KB — a large value re-creates #234.")


def test_template_variable_is_wired_into_default_config():
    assert '"max_tool_calls_per_turn": {{ interpret_max_tool_calls_per_turn }},' in TMPL


# NOTE: the "does the rendered template still compile" check lives in
# test_interpret_streaming.py::test_rendered_template_is_valid_python, whose _SUBS map
# gains the new variable. Deliberately NOT duplicated here — two render harnesses drift,
# and that test already fails loudly when a new Jinja scalar is added (it did for this
# change, which is how the omission was caught).
