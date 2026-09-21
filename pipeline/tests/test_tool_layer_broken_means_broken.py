# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""`tool_layer_broken` must mean the instrument failed, not that the model missed.

`is_tool_error` counts any `result.error` as a failed call, and
`tool_layer_broken` was computed from that rate. Two unrelated things reach the
log in that shape:

    realpath: .../project: No such file or directory   the tool layer is DEAD
    Function not found: main                           it ran and answered "no"

Measured across every persisted cell on the sandbox (2026-09-20): 18 of the
first, 18 of the second (14 "Function not found", 4 "Memory read failed").

The consequence is not cosmetic. The #420 pilot ran against a REPAIRED corpus
with a working tool layer — `list_functions` and `get_strings_at` both
succeeded — and still scored `tool_layer_broken: True` at a 0.6 rate, because
the model asked for `entry`, `main`, `WinMain` and `_DllMainCRTStartup` on a
shellcode blob that has none of them. The cell was voided for the model's own
choices, which is the behaviour the eval exists to measure.

The threshold comment claimed "a genuinely dead tool layer was 5 of 5 (100%).
Nothing observed lands between." 0.6 from a working layer is the counterexample.

`tool_call_error_rate` still counts EVERY failed call — that is the router
translation-fidelity signal and it should not lose the semantic ones. Only the
gate moves.
"""
import pytest
from llm_ab_re import (
    TOOL_LAYER_BROKEN_THRESHOLD,
    is_semantic_tool_error,
    is_tool_error,
    is_transport_tool_error,
)


def _call(err):
    return {"tool": "decompile_function", "args": {}, "result": {"error": err}}


DEAD = "realpath: /opt/pipeline/reports/r5_x/shellcode_0_N/A/project: No such file or directory\n"
MISS = "Function not found: main"
UNREADABLE = "Memory read failed at 0x00400000: Unable to read bytes at ram:00400000"


def test_a_dead_tool_layer_is_a_transport_error():
    assert is_transport_tool_error(_call(DEAD))
    assert not is_semantic_tool_error(_call(DEAD))


@pytest.mark.parametrize("err", [MISS, UNREADABLE, "Function not found: WinMain"])
def test_a_negative_answer_is_not_a_transport_error(err):
    """The tool worked. The answer is 'no'. That is data."""
    assert is_semantic_tool_error(_call(err))
    assert not is_transport_tool_error(_call(err))


def test_both_still_count_as_tool_errors():
    """The translation-fidelity signal must not lose the semantic ones."""
    assert is_tool_error(_call(DEAD)) and is_tool_error(_call(MISS))


def test_a_successful_call_is_neither():
    ok = {"tool": "list_functions", "args": {}, "result": {"functions": []}}
    assert not is_tool_error(ok)
    assert not is_transport_tool_error(ok) and not is_semantic_tool_error(ok)


def test_an_unrecognised_failure_counts_as_transport():
    """Fail safe. Wrongly voiding a cell costs a re-run; wrongly trusting one
    corrupts a result, which is what #631 did for nine days."""
    assert is_transport_tool_error(_call("some new error nobody has seen"))


def test_the_pilot_shape_no_longer_voids_the_cell():
    """The exact 2026-09-20 log: 10 calls, 4 clean, 6 negative answers."""
    log = ([{"tool": "list_functions", "args": {}, "result": {"functions": []}}] * 4
           + [_call(MISS)] * 5 + [_call(UNREADABLE)])
    transport = sum(1 for e in log if is_transport_tool_error(e))
    errors = sum(1 for e in log if is_tool_error(e))
    assert errors == 6, "every failed call still counts for the fidelity signal"
    assert transport == 0
    assert (transport / len(log)) < TOOL_LAYER_BROKEN_THRESHOLD, "cell must be scoreable"


def test_a_genuinely_dead_layer_still_voids_the_cell():
    """The case the gate exists for — the first pilot, 8 of 8 dead."""
    log = [_call(DEAD)] * 8
    transport = sum(1 for e in log if is_transport_tool_error(e))
    assert (transport / len(log)) >= TOOL_LAYER_BROKEN_THRESHOLD


def _write_log(tmp_path, log):
    """A persisted cell directory the offline re-scorer can read."""
    import json
    audit = tmp_path / "llm_audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "tool_calls.json").write_text(json.dumps(log))
    return tmp_path


def test_the_offline_rescorer_agrees_with_the_live_path(tmp_path):
    """Asserted by RUNNING it, not by reading its source. A source check passes
    while the gate still uses the old rate — the vacuous-guard pattern this repo
    keeps finding, and it survived a mutation here before being rewritten.

    Two copies of this rule drifting is #380, in the figures that decide whether
    a cell counts at all."""
    from lamware_eval.rebuild import _tool_call_metrics

    ok = {"tool": "list_functions", "args": {}, "result": {"functions": []}}
    semantic = _write_log(tmp_path / "a", [ok] * 4 + [_call(MISS)] * 5 + [_call(UNREADABLE)])
    m = _tool_call_metrics(semantic)
    assert m["tool_call_errors"] == 6, "fidelity signal keeps every failed call"
    assert m["tool_transport_errors"] == 0
    assert m["tool_layer_broken"] is False, "a working layer must stay scoreable"

    dead = _write_log(tmp_path / "b", [_call(DEAD)] * 8)
    m = _tool_call_metrics(dead)
    assert m["tool_transport_errors"] == 8
    assert m["tool_layer_broken"] is True, "a dead layer must still void the cell"
