# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Sample selection for targeted probes.

A depth probe runs one sample very deep; without a filter the only option is the
whole corpus, which on the local arm is a multi-hour sweep.
"""
import pytest
from lamware_eval.corpus import CorpusSample, filter_samples

CORPUS = [
    CorpusSample("982a0d1bdeadbeef", "raccoonstealer", "/c/raccoon"),
    CorpusSample("d22c9656cafebabe", "latrodectus", "/c/latro"),
    CorpusSample("591d32ae12345678", "emotet", "/c/emotet"),
]


def test_empty_selector_returns_whole_corpus():
    assert filter_samples(CORPUS, "") == CORPUS


def test_select_by_family_name():
    got = filter_samples(CORPUS, "raccoonstealer")
    assert [s.sha256 for s in got] == ["982a0d1bdeadbeef"]


def test_select_by_sha_prefix():
    got = filter_samples(CORPUS, "982a0d1b")
    assert [s.mb_family for s in got] == ["raccoonstealer"]


def test_selection_is_case_insensitive():
    assert len(filter_samples(CORPUS, "RaccoonStealer")) == 1
    assert len(filter_samples(CORPUS, "982A0D1B")) == 1


def test_multiple_selectors_and_no_duplicates():
    got = filter_samples(CORPUS, "raccoonstealer,emotet,982a0d1b")
    assert [s.mb_family for s in got] == ["raccoonstealer", "emotet"]


def test_unmatched_selector_raises_rather_than_silently_running_everything():
    """A typo must not turn a one-sample probe into a full-corpus sweep."""
    with pytest.raises(ValueError, match="matched nothing"):
        filter_samples(CORPUS, "raccoonstealr")


def test_error_names_the_known_samples():
    with pytest.raises(ValueError) as e:
        filter_samples(CORPUS, "nope")
    assert "raccoonstealer" in str(e.value)
