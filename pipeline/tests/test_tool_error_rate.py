# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""tool_call_error_rate must observe the failure it exists to catch (#316).

The reported case: `depth-10-vs-15-n7`, latrodectus, `qwen@10` —

    completed: True   tool_calls_used: 8   tool_call_error_rate: 0.0

with all 8 calls carrying `Requested project program file(s) not found`. The
models both diagnosed it in their working notes; the harness did not.

Cause: `sum(1 for e in log if "error" in e)` tests for an "error" KEY on the log
entry. Only the validation-refusal path writes that. A tool that RAN and failed
records `{"tool", "args", "result": {"error": …}}`, and `run_ghidra_tool`
returns exactly that shape for a non-zero exit, a timeout, or unparseable
output — so every real failure counted as a success.

The issue asks specifically for a test that fails against the broken state,
because "a guard for this that is never seen to fail is worth nothing — which
is precisely how this survived". `test_the_original_bug_is_detected` is that
test; it is written from the real log shape, not an invented one.
"""
import json
from pathlib import Path

import pytest
from lamware_eval.metrics import aggregate
from llm_ab_re import TOOL_LAYER_BROKEN_THRESHOLD, extract_metrics, is_tool_error

# --- the two shapes that actually reach the log ------------------------------

def refused(tool="decompile_function"):
    """Validation refused it — the only shape the old code counted."""
    return {"tool": tool, "args": {}, "error": "unknown tool"}


def ran_and_failed(msg="Requested project program file(s) not found: 9f3ed585"):
    """run_ghidra_tool returned {"error": …}. The shape that was missed."""
    return {"tool": "decompile_function", "args": {"name": "entry"},
            "result": {"error": msg}}


def succeeded(n=15):
    return {"tool": "list_functions", "args": {},
            "result": {"count": n, "functions": ["FUN_0040b477"]}}


# --- is_tool_error -----------------------------------------------------------

def test_a_tool_that_ran_and_failed_is_an_error():
    assert is_tool_error(ran_and_failed())


def test_a_refused_call_is_still_an_error():
    """The path that already worked must keep working."""
    assert is_tool_error(refused())


def test_a_successful_call_is_not_an_error():
    """Positive control: not everything counts as an error."""
    assert not is_tool_error(succeeded())


def test_a_result_without_an_error_key_is_not_an_error():
    assert not is_tool_error({"tool": "get_data_at", "args": {}, "result": {"bytes": "90"}})


def test_a_non_dict_result_is_not_an_error():
    """Older logs stringify the result; absence of a dict is not a failure."""
    assert not is_tool_error({"tool": "x", "args": {}, "result": "{'count': 15}"})


def test_an_empty_error_string_is_not_an_error():
    assert not is_tool_error({"tool": "x", "args": {}, "result": {"error": ""}})


# --- the metric ---------------------------------------------------------------

def _metrics(tmp_path, log):
    p = tmp_path / "tool_calls.json"
    p.write_text(json.dumps(log))
    return extract_metrics({
        "analysis": {"capabilities": ["x"]},
        "tool_calls_used": len(log),
        "audit": {"tool_call_log": str(p)},
    })


def test_the_original_bug_is_detected(tmp_path):
    """THE regression test the issue asks for: 8 of 8 failing must not read 0.0."""
    m = _metrics(tmp_path, [ran_and_failed() for _ in range(8)])

    assert m["tool_call_errors"] == 8, m
    assert m["tool_call_error_rate"] == 1.0, (
        f"8 of 8 tool calls failed and the rate is {m['tool_call_error_rate']} — "
        f"the metric cannot see the failure mode it exists to catch"
    )
    assert m["tool_layer_broken"] is True


def test_a_healthy_cell_reports_zero(tmp_path):
    """Positive control: the fix must not make every cell look broken."""
    m = _metrics(tmp_path, [succeeded() for _ in range(10)])

    assert m["tool_call_errors"] == 0
    assert m["tool_call_error_rate"] == 0.0
    assert m["tool_layer_broken"] is False


def test_the_observed_normal_error_band_is_not_flagged(tmp_path):
    """Real corpus rate is 5 errors in 444 calls; that is a working tool layer."""
    log = [succeeded() for _ in range(19)] + [ran_and_failed("Function not found: main")]
    m = _metrics(tmp_path, log)

    assert m["tool_call_error_rate"] == 0.05
    assert m["tool_layer_broken"] is False


def test_no_tool_calls_is_not_a_broken_tool_layer(tmp_path):
    """A cell that made no calls has an unknown tool layer, not a dead one."""
    m = _metrics(tmp_path, [])

    assert m["tool_call_error_rate"] == 0.0
    assert m["tool_layer_broken"] is False


@pytest.mark.parametrize("rate_num,expected", [(4, False), (5, True), (10, True)])
def test_threshold_boundary(tmp_path, rate_num, expected):
    log = ([ran_and_failed() for _ in range(rate_num)]
           + [succeeded() for _ in range(10 - rate_num)])
    m = _metrics(tmp_path, log)

    assert m["tool_layer_broken"] is expected, (
        f"{rate_num}/10 failed -> rate {m['tool_call_error_rate']}, "
        f"threshold {TOOL_LAYER_BROKEN_THRESHOLD}"
    )


# --- load-bearing: broken cells leave the aggregates -------------------------

def _cell(arm="qwen@10", total=0, grounded=0, broken=False, completed=True):
    return {"arm": arm, "total": total, "grounded": grounded,
            "grounded_ratio": (grounded / total) if total else 1.0,
            "fabricated": [], "completed": completed, "parse_failed": False,
            "tool_layer_broken": broken, "wall_seconds": 10.0, "cost_usd": 0.0}


def test_a_broken_cell_does_not_dilute_the_arm():
    """It contributed a 0/0 to both arms of an A/B as though depth were tested."""
    agg = aggregate([_cell(total=4, grounded=4), _cell(broken=True)])["qwen@10"]

    assert agg["n"] == 2, "the attempt still happened"
    assert agg["n_valid"] == 1
    assert agg["tool_layer_broken"] == 1
    assert agg["total_claims"] == 4
    assert agg["mean_grounded_ratio"] == 1.0


def test_completed_rate_is_over_measurable_cells():
    """A dead tool layer says nothing about whether the config completes."""
    agg = aggregate([_cell(total=1, grounded=1), _cell(broken=True, completed=True)])["qwen@10"]

    assert agg["completed_rate"] == 1.0
    assert agg["n_valid"] == 1


def test_cost_and_wall_still_count_broken_cells():
    """A cell that burned an hour failing still cost an hour."""
    agg = aggregate([_cell(total=1, grounded=1), _cell(broken=True)])["qwen@10"]

    assert agg["mean_wall_seconds"] == 10.0
    assert agg["n"] == 2


def test_an_all_broken_arm_reports_no_capability():
    """Not a 'perfect' arm — an unmeasured one."""
    agg = aggregate([_cell(broken=True), _cell(broken=True)])["qwen@10"]

    assert agg["n_valid"] == 0
    assert agg["mean_grounded_ratio"] is None
    assert agg["completed_rate"] is None
    assert agg["tool_layer_broken"] == 2


# --- it reaches the scorecard ------------------------------------------------

def _scorecard_src() -> str:
    return (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
            / "files" / "lamware_eval" / "scorecard.py").read_text(encoding="utf-8")


def _col_list(marker: str) -> set[str]:
    body = _scorecard_src().split(marker, 1)[1].split("]", 1)[0]
    return {c.strip().strip('"') for c in body.split(",") if c.strip()}


def _summary_cols() -> set[str]:
    return _col_list("cols = [")


def test_the_column_readers_work():
    """Guards the guards below — both parse a literal list out of source."""
    assert "n" in _summary_cols() and "total_cost_usd" in _summary_cols()
    assert "sample" in _col_list("cell_cols = [")


def test_the_summary_table_shows_the_exclusion():
    """A number nobody can see is not a fix.

    The first cut of #316 computed n_valid and tool_layer_broken, rendered them
    in the per-cell table, and left them out of the summary `cols` — so the
    summary reported rates over a denominator it never showed.
    """
    assert "n_valid" in _summary_cols(), "summary hides the denominator its rates use"
    assert "tool_layer_broken" in _summary_cols(), "summary hides why n_valid < n"
    assert "tool_layer_broken" in _col_list("cell_cols = ["), (
        "per-cell table omits tool_layer_broken")


def test_every_aggregate_key_is_rendered():
    """Drift guard: a new aggregate field must be shown, or this fails.

    Catches the general form of the bug above — computing a summary figure and
    never displaying it — for whatever gets added next.
    """
    produced = set(aggregate([_cell(total=1, grounded=1)])["qwen@10"])

    assert not (produced - _summary_cols()), (
        f"aggregate produces fields the scorecard never shows: "
        f"{sorted(produced - _summary_cols())}")
