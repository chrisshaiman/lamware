# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A scorecard could not say how much evidence a +corr cell received (#502).

Measured across the #420 stage-2 corpus, from the deployed `correlated_evidence`:

    unclassified_25d18a2b        keys=4  26,232 bytes
    unclassified_42b9c406        keys=4  30,488 bytes
    salat_d26bc055               keys=4  28,818 bytes
    cobaltstrikebeacon_179dcccf  keys=4  30,515 bytes
    latrodectus_d22c9656         keys=1   1,449 bytes

`latrodectus` received a twentieth of the evidence the others did, and its
`+corr` row sat beside them looking like the same treatment.

The obvious challenge to any positive result — did CORRELATION help, or did more
text in the prompt help — is answerable from these numbers and unanswerable
without them. `correlations_shown` is recorded separately from total volume
because that is the variable the thesis is actually about; Cape signatures and
Volatility insights ride along with it.
"""
import json

import pytest
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import aggregate, compose_cell
from lamware_eval.scorecard import render_scorecard

SAMPLE = CorpusSample("a" * 64, "unclassified", "/tmp/x")
# The em dash is load-bearing, not decoration. `str(a_dict)` and
# `json.dumps(a_dict)` have the SAME length for plain ASCII — single quotes for
# double — and they escape backslashes identically too, so a Windows path
# cannot tell them apart either. Only a NON-ASCII character can: json.dumps
# renders it \u2014, repr keeps one character. My first fixture used a path,
# and the mutation swapping json.dumps for str passed unnoticed.
RICH = {"cross_correlations": [{"title": "one"},
                               {"detail": "dropped to C:/x.dll — observed"}],
        "correlation_warnings": ["w"],
        "cape_signatures": [{"name": "s"}],
        "volatility_insights": {"k": "v"}}
THIN = {"cape_signatures": [{"name": "s"}]}


def _cell(evidence=None, arm="qwen@10"):
    return compose_cell(arm, SAMPLE, {}, "{}", None, 1.0, 0.0,
                        {"completed": True}, None, evidence=evidence)


def test_a_base_arm_records_zero_rather_than_nothing():
    """Zero on the row is what makes the pairing visible without cross-
    referencing another table."""
    c = _cell(None)
    assert c["evidence_bytes"] == 0
    assert c["evidence_keys"] == 0
    assert c["correlations_shown"] == 0


def test_the_recorded_size_is_the_text_that_was_actually_scored():
    """Not an estimate. compose_cell serialises the evidence itself, so the size
    it reports and the text it appends to the grounding corpus are the same
    string by construction — they cannot drift."""
    c = _cell(RICH)
    assert c["evidence_bytes"] == len(json.dumps(RICH))
    assert c["evidence_bytes"] != len(str(RICH)), (
        "the fixture must distinguish json.dumps from str, or this asserts nothing")


def test_a_thin_and_a_rich_cell_are_distinguishable():
    """The latrodectus case: one key against four, and an order of magnitude of
    volume, which the scorecard previously rendered identically."""
    thin, rich = _cell(THIN), _cell(RICH)
    assert thin["evidence_keys"] == 1 and rich["evidence_keys"] == 4
    assert thin["evidence_bytes"] < rich["evidence_bytes"]


def test_correlations_are_counted_apart_from_everything_else():
    """A sample with signatures but no correlations is a LOW DOSE of the thing
    under test, not a control — and total volume alone cannot say which."""
    assert _cell(RICH)["correlations_shown"] == 2
    assert _cell(THIN)["correlations_shown"] == 0
    assert _cell(THIN)["evidence_bytes"] > 0, "it still received something"


def test_the_summary_totals_both():
    cells = [_cell(RICH), _cell(THIN)]
    s = aggregate(cells)["qwen@10"]
    assert s["total_correlations_shown"] == 2
    assert s["total_evidence_bytes"] == len(json.dumps(RICH)) + len(json.dumps(THIN))


@pytest.mark.parametrize("col", [
    "evidence_bytes", "evidence_keys", "correlations_shown",
    "total_evidence_bytes", "total_correlations_shown",
])
def test_the_scorecard_renders_them(col):
    """A number nobody can see is not a fix (#380)."""
    cells = [_cell(RICH)]
    assert col in render_scorecard("t", cells, aggregate(cells))


def test_grounding_still_sees_the_evidence():
    """The refactor moved serialisation inside compose_cell. If that broke, the
    recitation split would silently start scoring evidence-derived claims as
    fabricated — the thing #491 exists to prevent."""
    analysis = {"code_level_iocs": [{"value": "one", "type": "x", "context": "c"}]}
    c = compose_cell("qwen@10+corr", SAMPLE, analysis, "{}", None, 1.0, 0.0,
                     {"completed": True}, None, evidence=RICH)
    assert c["grounded"] == 1
    assert c["grounded_recited"] == 1, "supported by the evidence, not the code"
    assert c["fabricated"] == []
