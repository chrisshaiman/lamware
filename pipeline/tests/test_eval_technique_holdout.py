# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""MITRE IDs are held out, so a technique claim has to be earned (#491).

`attack_techniques` was scored by nothing at all — `grounding_scorecard` reads
`code_level_ioc` only — while the correlations shown to `+corr` carried the IDs
outright. On the #420 pilot:

    correlations shown to +corr: ['T1059 — Execution', 'T1055 — Process Injection']
    qwen@10       claimed 3: T1055.003, T1218.012, T1574.002
    qwen@10+corr  claimed 6: T1027, T1055, T1055.003, T1059.001, T1070, T1572

Two of `+corr`'s six were IDs it had been handed, and doubling the count cost it
nothing because nothing checked. Cape's `mitre_ttps` are now the answer key —
derived from behaviour Cape watched, independently of anything Ghidra saw, which
is what makes them usable as ground truth (#314) — and no arm is shown them.
"""
import json

import pytest
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import aggregate, compose_cell, technique_hits
from lamware_eval.runner import (
    correlated_evidence,
    held_out_techniques,
    strip_technique_ids,
)
from lamware_eval.scorecard import render_scorecard

SAMPLE = CorpusSample("42b9c406d556" + "0" * 52, "unclassified", "/tmp/x")

# The real correlations from unclassified_42b9c406, mitre field included.
REPORT = {
    "cross_correlations": [
        {"type": "dropped_file_loaded", "title": "Dropped file 'System.dll' was loaded",
         "detail": "Cape observed this", "mitre": "T1059 — Execution"},
        {"type": "injection_corroborated", "title": "Injection into PID 1536",
         "detail": "corroborated in memory", "mitre": "T1055 — Process Injection"},
    ],
    "cape": {
        "signatures": [{"name": "injection_write_process", "severity": 3,
                        "description": "Writes to another process"}],
        "mitre_ttps": [{"id": "T1055"}, {"id": "T1059"}, {"id": "T1027"},
                       {"id": "T1059.001"}],
    },
}


# --- the evidence must not carry the answer ---


def test_the_mitre_field_never_reaches_the_agent():
    """THE change. `+corr` was handed T1059 and T1055 and then claimed both."""
    ev = correlated_evidence(REPORT)
    assert "T1055" not in json.dumps(ev)
    assert "T1059" not in json.dumps(ev)


def test_the_finding_itself_survives_the_strip():
    """Only the ID goes. The title and detail are what the arm is supposed to
    reason from, and removing those would test nothing."""
    ev = correlated_evidence(REPORT)
    text = json.dumps(ev)
    assert "Dropped file 'System.dll' was loaded" in text
    assert "Injection into PID 1536" in text
    assert "injection_write_process" in text, "cape signatures carry no IDs and stay"


def test_an_id_hiding_in_prose_is_redacted_and_counted():
    """Dropping one field is not a guarantee. Anything that leaks the key by
    another route is redacted, and COUNTED — a non-zero count on a real sample
    means there is a second route to find, not a number to bury."""
    ev, removed = strip_technique_ids(
        {"cross_correlations": [{"detail": "looks like T1055.003 to me"}]})
    assert removed == 1
    assert "T1055" not in json.dumps(ev)
    assert "[held out]" in json.dumps(ev)


def test_stripping_reports_how_much_it_removed():
    _, removed = strip_technique_ids(REPORT["cross_correlations"])
    assert removed == 2


def test_a_sample_with_no_correlations_is_still_an_empty_evidence_set():
    """Byte-identical to the base arm on such samples is deliberate — they are
    the control. Stripping must not turn {} into something."""
    assert correlated_evidence({"cape": {}}) == {}


# --- the answer key ---


def test_the_answer_key_is_capes_own_observations():
    assert held_out_techniques(REPORT) == ["T1027", "T1055", "T1059", "T1059.001"]


def test_a_report_without_cape_techniques_yields_no_key():
    assert held_out_techniques({}) == []
    assert held_out_techniques({"cape": {"mitre_ttps": []}}) == []


# --- matching ---


def test_an_exact_match_hits():
    assert technique_hits(["T1055"], ["T1055", "T1027"]) == ["T1055"]


def test_a_sub_technique_hits_its_parent():
    """Claiming T1055.003 when Cape saw T1055 is a MORE specific version of the
    same finding. Penalising that is not the point."""
    assert technique_hits(["T1055.003"], ["T1055"]) == ["T1055.003"]


def test_a_parent_does_not_hit_a_sub_technique():
    """The reverse is a LESS specific claim. Crediting both directions would
    make the metric generous both ways, which is another way of saying
    unfalsifiable."""
    assert technique_hits(["T1055"], ["T1055.003"]) == []


def test_a_technique_cape_never_saw_does_not_hit():
    assert technique_hits(["T1218.012"], ["T1055", "T1059"]) == []


# --- scoring ---


def _cell(ids, arm="qwen@10", key=None):
    analysis = {"attack_techniques": [{"id": i, "name": i} for i in ids]}
    return compose_cell(arm, SAMPLE, analysis, "{}", None, 1.0, 0.0,
                        {"completed": True}, None,
                        cape_techniques=key if key is not None
                        else held_out_techniques(REPORT))


def test_the_claim_lists_from_the_pilot_score_as_expected():
    """The real technique lists from the #420 pilot, scored against the
    FOUR-id key in this fixture rather than the twenty-five Cape actually
    emitted — so the counts here are not the live ones (base hits 2 of 3 against
    the real key, not 1). The point is the shape: +corr claims twice as many and
    precision is what separates them, and precision did not exist as a number
    before this."""
    base = _cell(["T1055.003", "T1218.012", "T1574.002"])
    corr = _cell(["T1027", "T1055", "T1055.003", "T1059.001", "T1070", "T1572"],
                 arm="qwen@10+corr")
    assert (base["techniques"], base["techniques_hit"]) == (3, 1)
    assert (corr["techniques"], corr["techniques_hit"]) == (6, 4)
    assert corr["technique_precision"] == round(4 / 6, 3)
    assert base["technique_precision"] == round(1 / 3, 3)


def test_inflating_the_count_now_costs_precision():
    """Doubling the technique list was free before this. It is not now."""
    honest = _cell(["T1055"])
    padded = _cell(["T1055", "T9001", "T9002", "T9003"])
    assert honest["techniques_hit"] == padded["techniques_hit"] == 1
    assert padded["technique_precision"] < honest["technique_precision"]


def test_no_answer_key_means_no_score_rather_than_a_zero():
    """A rate computed over nothing is not a score of zero."""
    c = _cell(["T1055"], key=[])
    assert c["technique_recall"] is None
    assert c["cape_techniques"] == 0


def test_claiming_nothing_scores_no_precision_rather_than_zero():
    c = _cell([])
    assert c["technique_precision"] is None
    assert c["techniques_hit"] == 0


# --- aggregation and rendering ---


def test_the_summary_averages_only_scoreable_cells():
    cells = [_cell(["T1055"]), _cell([])]
    summary = aggregate(cells)["qwen@10"]
    assert summary["total_techniques_hit"] == 1
    assert summary["mean_technique_precision"] == 1.0, "the empty cell must not drag it"


def test_the_summary_reports_none_when_nothing_was_scoreable():
    summary = aggregate([_cell([])])["qwen@10"]
    assert summary["mean_technique_precision"] is None


@pytest.mark.parametrize("col", [
    "techniques_hit", "technique_precision", "technique_recall", "cape_techniques",
    "total_techniques_hit", "mean_technique_precision", "mean_technique_recall",
])
def test_the_scorecard_renders_the_new_figures(col):
    """A number nobody can see is not a fix (#380)."""
    cells = [_cell(["T1055"])]
    assert col in render_scorecard("t", cells, aggregate(cells))
