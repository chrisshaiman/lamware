# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The shipped corpus manifest must be usable and must say what it is for (#426).

Two failures motivated this. The manifest that shipped before carried a single
amadey entry whose sha256 (`5258a241...`) did not match the amadey sample actually
deployed (`573e6860...`), so on a rebuilt host its `corpus_dir` would not exist and
the sweep would silently bootstrap to a one-sample benchmark (#313).

The larger failure was that neither the 7-sample eval corpus nor the 29-sample MOTIF
corpus produced a single cross-tool correlation — measured 2026-08-19, `[]` on all 36
— because both were selected on family labels rather than on whether the samples
exercise the pipeline being measured. Nothing recorded the selection criterion, so
nothing could have flagged that.

These assertions are about the manifest as a contract. They deliberately do NOT check
that `corpus_dir` exists: the directories are built by re-running the pipeline on the
analysis host, and CI has neither.
"""
import json
from pathlib import Path

import pytest
from lamware_eval.corpus import load_corpus

MANIFEST = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
            / "files" / "eval" / "corpus.json")
DOC = json.loads(MANIFEST.read_text(encoding="utf-8"))
SAMPLES = DOC["samples"]


def test_manifest_loads_through_the_real_loader():
    """Extra documentation keys must not break `load_corpus`."""
    assert len(load_corpus(str(MANIFEST))) == len(SAMPLES)


def test_every_sha256_is_well_formed_and_unique():
    shas = [s["sha256"] for s in SAMPLES]
    assert len(set(shas)) == len(shas), "duplicate sample in the corpus"
    for sha in shas:
        assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), sha


def test_corpus_dir_matches_the_sample_it_names():
    """A dir naming one sample's hash while the entry names another is how #313's
    mismatch went unnoticed."""
    for s in SAMPLES:
        assert s["corpus_dir"].endswith(f"{s['mb_family']}_{s['sha256'][:8]}"), s["sha256"]


def test_selection_criterion_is_recorded():
    sel = DOC.get("_selection", {})
    assert sel.get("criterion"), "the manifest must say why these samples were chosen"
    assert sel.get("build"), "the manifest must say how corpus_dir is produced"


@pytest.mark.parametrize("role", ["positive", "negative-control"])
def test_both_roles_are_present(role):
    """A corpus of only positives cannot distinguish a rule that fires appropriately
    from one that fires indiscriminately."""
    assert [s for s in SAMPLES if s.get("role") == role], f"no {role} samples"


def test_every_sample_states_why_it_is_here():
    for s in SAMPLES:
        assert s.get("selected_because"), s["sha256"]
        assert s.get("role") in ("positive", "negative-control"), s["sha256"]


def test_positives_claim_injection_buffers_and_negatives_do_not():
    """The claim that makes a sample a positive is checkable once it is built, and
    stating it here is what lets a rebuild verify rather than assume."""
    for s in SAMPLES:
        n = s.get("expected_injection_buffers")
        assert isinstance(n, int), s["sha256"]
        if s["role"] == "positive":
            assert n > 0, f"{s['sha256']} is a positive claiming 0 buffers"
            assert s.get("source_cape_task"), "a positive must name the analysis it came from"
        else:
            assert n == 0, f"{s['sha256']} is a control claiming {n} buffers"
