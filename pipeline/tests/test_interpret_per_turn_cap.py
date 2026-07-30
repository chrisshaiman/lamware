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

These are static assertions over the script's text plus a compile check. They predate
#205, when the file was a Jinja template; it is now plain Python and importable, but
the deferral behaviour lives inside the agentic loop and is still cheapest to pin here.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TMPL_PATH = (ROOT / "ansible" / "roles" / "interpret" / "files"
             / "interpret-ghidra.py")
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


def test_the_per_turn_cap_reaches_the_container():
    """#205 moved the nine deploy-time scalars out of Jinja into a JSON config the role
    renders, so the old assertion (a `{{ }}` inside the script) no longer has anything to
    match. The PROPERTY it protected is unchanged and still worth pinning: the role's
    value has to travel to the container, and the script's fallback has to be sane if it
    does not.
    """
    config_tmpl = (ROOT / "ansible" / "roles" / "interpret" / "templates"
                   / "interpret-config.json.j2").read_text(encoding="utf-8")
    assert "interpret_max_tool_calls_per_turn" in config_tmpl, (
        "the cap is no longer shipped to the container; it would silently revert to the "
        "script's builtin fallback and the role default would stop meaning anything")
    assert '"max_tool_calls_per_turn": 3,' in TMPL, (
        "the builtin fallback must stay small — it is what applies if the config file is "
        "missing or unreadable. A large value there re-creates #234 silently.")


# NOTE: the "does it still compile" gate now lives in
# test_interpret_config_defaults.py::test_the_script_compiles_standalone. It used to
# require rendering the Jinja first; the file is plain Python since #205, so the compile
# check is direct and the render harness is gone.
