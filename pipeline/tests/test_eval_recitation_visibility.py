# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Restating the prompt scored the same as reading the binary (#491).

`run_arm` adds an evidence-fed arm's extra evidence to the grounding corpus.
That is right — omitting it would score claims drawn from correlation findings
as FABRICATED and penalise the arm for using exactly what the experiment gave
it. What was wrong is that it was folded in silently, so a claim copied out of
the prompt was indistinguishable from one derived from decompiled code.

The #420 pilot on 25d18a2b made it unmissable. With the tool layer dead (#490),
`+corr` reported **7 grounded / 0 fabricated** claims having read nothing at
all, while the base arm — able to read nothing and given nothing — honestly said
nothing. Its first "capability" was
`"Drops additional payloads (unclassified.tmp executable and ffmpeg.dll)"`, both
filenames verbatim from its own evidence block.

The code's own mitigation was wrong too: "compare ABSOLUTE grounded findings,
never the ratio". Absolute counts inflate identically.
"""
import json

import pytest
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import aggregate, compose_cell
from lamware_eval.runner import arm_name_from_cell_dir, cell_dir_name
from lamware_eval.scorecard import render_scorecard

SAMPLE = CorpusSample("42b9c406d556" + "0" * 52, "unclassified", "/tmp/x")

# What the model could have read out of the binary.
CODE = json.dumps({"functions": ["FUN_1000bd79"], "data": ["DAT_1006bde0"]})
# What an evidence-fed arm was additionally handed.
# Passed as the dict, not pre-serialised text: compose_cell serialises it
# itself so the size it records and the text it appends cannot drift (#502).
EVIDENCE = {"cross_correlations": [
    {"title": "Dropped file 'ffmpeg.dll' was loaded and executed"}]}


def _analysis(*iocs, techniques=(), capabilities=()):
    return {
        "code_level_iocs": [{"value": v, "type": "address", "context": "c"}
                            for v in iocs],
        "attack_techniques": [{"id": t, "name": t} for t in techniques],
        "capabilities": list(capabilities),
    }


def _cell(analysis, evidence=None, arm="qwen@10"):
    return compose_cell(arm, SAMPLE, analysis, CODE, None, 1.0, 0.0,
                        {"completed": True}, None, evidence=evidence)


# --- the split ---


def test_a_claim_only_the_prompt_supports_is_grounded_but_not_novel():
    """THE bug, in one assertion."""
    c = _cell(_analysis("ffmpeg.dll"), evidence=EVIDENCE)
    assert c["grounded"] == 1, "the evidence must still count as support"
    assert c["grounded_novel"] == 0, "but it is not something read from the code"
    assert c["grounded_recited"] == 1


def test_a_claim_the_code_supports_counts_as_novel():
    c = _cell(_analysis("FUN_1000bd79"), evidence=EVIDENCE)
    assert c["grounded"] == 1
    assert c["grounded_novel"] == 1
    assert c["grounded_recited"] == 0


def test_the_two_add_up():
    c = _cell(_analysis("FUN_1000bd79", "ffmpeg.dll"), evidence=EVIDENCE)
    assert c["grounded"] == c["grounded_novel"] + c["grounded_recited"] == 2


def test_without_evidence_novel_equals_grounded():
    """A base arm has no second corpus, so the split is a no-op by construction
    — and must not silently report a recitation of zero as an achievement."""
    c = _cell(_analysis("FUN_1000bd79"))
    assert c["grounded_novel"] == c["grounded"] == 1
    assert c["grounded_recited"] == 0


def test_an_invented_claim_is_still_fabricated_with_evidence_present():
    """Widening the corpus must not turn fabrication into support."""
    c = _cell(_analysis("0xdeadbeef"), evidence=EVIDENCE)
    assert c["grounded"] == 0
    assert len(c["fabricated"]) == 1


def test_the_pilot_shape_is_now_readable():
    """base: nothing at all. +corr: three claims, every one from its prompt.
    Before this the two read as 0 grounded against 3 grounded."""
    base = _cell(_analysis(), arm="qwen@10")
    corr = _cell(_analysis("ffmpeg.dll", "unclassified.tmp", "Grape.exe"),
                 evidence={"cross_correlations": [
                     {"detail": "ffmpeg.dll unclassified.tmp Grape.exe"}]},
                 arm="qwen@10+corr")
    assert corr["grounded"] == 3
    assert corr["grounded_novel"] == 0, "none of it came from the code"
    assert corr["grounded_recited"] == 3
    assert base["grounded_novel"] == 0
    # the honest comparison is novel-to-novel, and it is a tie at zero
    assert base["grounded_novel"] == corr["grounded_novel"]


# --- columns that were computed and never shown ---


def test_bare_symbols_and_unscoreable_reach_the_cell():
    """Both are produced by grounding_scorecard. Neither was surfaced, so a cell
    citing two Ghidra auto-generated DAT_ labels scored 1.00 and outranked one
    citing three concrete addresses at 0.75."""
    c = _cell(_analysis("DAT_1006bde0", "Visual Studio 2017 Release CRT libraries"))
    assert c["bare_symbols"] >= 1
    assert c["unscoreable"] >= 1


def test_unscored_fields_are_counted_even_though_they_are_not_scored():
    """grounding_scorecard reads code_level_ioc ONLY, which makes techniques the
    cheapest thing for an evidence-fed arm to inflate — the pilot's +corr arm
    doubled them, 3 to 6, with two appearing nowhere in its evidence."""
    c = _cell(_analysis("FUN_1000bd79", techniques=("T1055", "T1027", "T1572"),
                        capabilities=("a", "b")))
    assert c["total"] == 1, "only code_level_iocs are scored"
    assert c["techniques"] == 3
    assert c["capabilities"] == 2


# --- aggregation and rendering: a column nobody can see is not a fix ---


@pytest.mark.parametrize("key", [
    "total_grounded_novel", "total_grounded_recited",
    "total_bare_symbols", "total_unscoreable", "total_techniques",
])
def test_the_arm_summary_carries_the_new_figures(key):
    cells = [_cell(_analysis("ffmpeg.dll", techniques=("T1055",)),
                   evidence=EVIDENCE, arm="qwen@10+corr")]
    assert key in aggregate(cells)["qwen@10+corr"]


def test_the_summary_sums_recitation_across_cells():
    cells = [_cell(_analysis("ffmpeg.dll"), evidence=EVIDENCE,
                   arm="qwen@10+corr") for _ in range(3)]
    summary = aggregate(cells)["qwen@10+corr"]
    assert summary["total_grounded_recited"] == 3
    assert summary["total_grounded_novel"] == 0


def test_the_scorecard_actually_renders_them():
    """#380's lesson: a number nobody can see is not a fix. Asserting on the
    cell dict alone would pass with the scorecard's column list untouched."""
    cells = [_cell(_analysis("ffmpeg.dll", techniques=("T1055",)),
                   evidence=EVIDENCE, arm="qwen@10+corr")]
    md = render_scorecard("t", cells, aggregate(cells))
    for col in ("grounded_novel", "grounded_recited", "bare_symbols",
                "unscoreable", "techniques"):
        assert col in md, f"{col} is computed but not rendered"


# --- an offline re-score must not disagree with the sweep ---


def test_cell_directory_names_round_trip():
    for name in ("qwen@10", "qwen@10+corr", "qwen@30:s42", "claude-opus-5+corr"):
        assert arm_name_from_cell_dir(cell_dir_name(name)) == name


def test_an_unknown_cell_directory_resolves_to_nothing_rather_than_a_guess():
    assert arm_name_from_cell_dir("_archived_2026") is None
    assert arm_name_from_cell_dir("qwen_10+corrx") is None


def test_the_evidence_arm_is_identified_by_lookup_not_by_a_name_suffix():
    """Matching on "+corr" in a directory name would be the same class of proxy
    check that #490 turned on. The lookup is exact."""
    from lamware_eval.arms import resolve_arm
    name = arm_name_from_cell_dir("qwen_10+corr")
    assert name == "qwen@10+corr"
    assert resolve_arm(name).evidence == "correlated"
    assert resolve_arm(arm_name_from_cell_dir("qwen_10")).evidence == "ghidra"


def test_no_two_arms_share_a_cell_directory():
    """The reverse lookup returns the FIRST match. If two arms sanitised to the
    same directory, a re-score would silently attribute one arm's cells to the
    other — and the evidence mode is exactly what it would get wrong."""
    from lamware_eval.arms import registered_arms
    names = registered_arms()
    dirs = [cell_dir_name(n) for n in names]
    assert len(dirs) == len(set(dirs)), sorted(
        d for d in dirs if dirs.count(d) > 1)
