# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Multi-seed consensus reconciliation.

The property that matters is that agreement is counted across RUNS and matched
across WORDINGS. Both are easy to get wrong in ways that silently inflate the
result: matching whole strings reports no agreement where there is total
agreement, and counting claim occurrences instead of runs lets a single run
manufacture its own consensus.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from lamware_eval.consensus import consensus, render_consensus  # noqa: E402


def _a(iocs, capabilities=None):
    return {"code_level_iocs": iocs, "capabilities": capabilities or []}


def test_claim_agreed_across_runs_is_reported_with_its_run_count():
    res = consensus([_a(["MilcoSoft.dll"]), _a(["MilcoSoft.dll"])], k=2)
    agreed = res["code_level_iocs"]["agreed"]
    assert [e["runs"] for e in agreed] == [2]
    assert res["code_level_iocs"]["n_runs"] == 2


def test_claim_in_one_run_is_a_singleton_not_agreement():
    res = consensus([_a(["MilcoSoft.dll"]), _a(["other.dll"])], k=2)
    field = res["code_level_iocs"]
    assert field["agreed"] == []
    assert {e["key"] for e in field["singleton"]} == {"milcosoft.dll", "other.dll"}


def test_differently_worded_claims_still_count_as_agreement():
    """The whole point: two runs describing one finding must not read as two findings."""
    res = consensus([
        _a(["`FUN_0040b477` contains the XOR loop"]),
        _a(["decryption routine at `FUN_0040b477`, do..while"]),
    ], k=2)
    keys = {e["key"] for e in res["code_level_iocs"]["agreed"]}
    assert "fun_0040b477" in keys


def test_a_single_run_cannot_manufacture_its_own_consensus():
    """Repeating a claim within one run is one run's opinion, not two runs agreeing."""
    res = consensus([_a(["evil.dll", "evil.dll", "evil.dll"]), _a(["good.dll"])], k=2)
    assert res["code_level_iocs"]["agreed"] == []
    assert [e["runs"] for e in res["code_level_iocs"]["singleton"]] == [1, 1]


def test_k_of_three_requires_more_than_a_bare_majority_when_asked():
    runs = [_a(["a.dll"]), _a(["a.dll"]), _a(["b.dll"])]
    assert [e["key"] for e in consensus(runs, k=2)["code_level_iocs"]["agreed"]] == ["a.dll"]
    assert consensus(runs, k=3)["code_level_iocs"]["agreed"] == []


def test_k_below_two_is_rejected():
    """k=1 keeps every claim and asserts nothing — it would look like a result."""
    with pytest.raises(ValueError):
        consensus([_a(["a.dll"])], k=1)


def test_dict_shaped_iocs_are_handled():
    """Models disagree on the IOC schema; a crash here already cost 5 cells once."""
    res = consensus([
        _a([{"type": "file", "value": "MilcoSoft.dll"}]),
        _a(["MilcoSoft.dll"]),
    ], k=2)
    assert [e["runs"] for e in res["code_level_iocs"]["agreed"]] == [2]


def test_both_ioc_schema_spellings_are_merged():
    res = consensus([
        {"code_level_ioc": ["MilcoSoft.dll"]},
        {"code_level_iocs": ["MilcoSoft.dll"]},
    ], k=2)
    assert [e["runs"] for e in res["code_level_iocs"]["agreed"]] == [2]


def test_capabilities_are_reconciled_separately_from_iocs():
    res = consensus([
        _a(["a.dll"], ["persists via `Run` key"]),
        _a(["a.dll"], ["persists via `Run` key"]),
    ], k=2)
    assert "capabilities" in res and "code_level_iocs" in res
    assert res["capabilities"]["agreed"], "capability agreement was dropped"


def test_render_reports_singletons_rather_than_hiding_them():
    """A claim only one run made is the most interesting row, not noise to filter."""
    md = render_consensus("t", {"abc — qwen@30": consensus(
        [_a(["shared.dll"]), _a(["shared.dll", "lonely.dll"])], k=2)}, k=2)
    assert "shared.dll" in md
    assert "lonely.dll" in md
    assert "unconfirmed" in md


def test_render_says_so_when_there_is_nothing_to_reconcile():
    md = render_consensus("t", {}, k=2)
    assert "nothing to reconcile" in md


# ---------------------------------------------------------------------------
# Vacuity: agreement between identical runs is not agreement (#292)
# ---------------------------------------------------------------------------

def test_identical_runs_are_counted_as_one_distinct_run():
    """n_runs cannot tell agreement from duplication; distinct_runs can.

    This is the #292 condition itself — three seeds, byte-identical transcripts —
    detected from the data rather than inferred from arm names, so it stays
    correct if independence is ever restored (#310).
    """
    res = consensus([_a(["a.dll"]), _a(["a.dll"]), _a(["a.dll"])], k=2)
    field = res["code_level_iocs"]
    assert field["n_runs"] == 3
    assert field["distinct_runs"] == 1


def test_genuinely_different_runs_are_counted_as_distinct():
    res = consensus([_a(["a.dll"]), _a(["a.dll", "b.dll"])], k=2)
    assert res["code_level_iocs"]["distinct_runs"] == 2


def test_distinct_runs_is_per_field_not_per_sample():
    """Runs can duplicate one field and diverge on another. Collapsing to a single
    per-sample verdict would either suppress a real result or bless a vacuous one."""
    res = consensus([
        _a(["a.dll"], ["persists via `Run` key"]),
        _a(["a.dll"], ["injects into `explorer.exe`"]),
    ], k=2)
    assert res["code_level_iocs"]["distinct_runs"] == 1
    assert res["capabilities"]["distinct_runs"] == 2


def test_render_refuses_to_tabulate_agreement_over_identical_runs():
    """THE regression guard.

    The old renderer printed `3/3` for every claim, which reads as strong
    confirmation and is an artifact of the runs being copies. The warning must
    REPLACE the table: a reader who sees 3/3 rows treats a caveat above them as a
    footnote, and the rows are what gets quoted.
    """
    md = render_consensus("t", {"abc — qwen@10": consensus(
        [_a(["a.dll"]), _a(["a.dll"])], k=2)}, k=2)
    assert "NOT A RESULT" in md
    assert "#292" in md
    assert "2/2" not in md, (
        "an agreement row over identical runs must not be rendered at all")


def test_render_still_tabulates_real_agreement():
    """The vacuity guard must not fire on genuine agreement, or it would suppress
    every real result #310 is meant to produce."""
    md = render_consensus("t", {"abc — cross-model": consensus(
        [_a(["a.dll"]), _a(["a.dll", "b.dll"])], k=2)}, k=2)
    assert "NOT A RESULT" not in md
    assert "2/2" in md
    assert "unconfirmed" in md
