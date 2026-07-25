# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
import json

import pytest

from lamware_eval.corpus import load_corpus, CorpusSample


def _write(tmp_path, obj):
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(obj))
    return str(p)


def test_loads_valid_corpus(tmp_path):
    path = _write(tmp_path, {"samples": [
        {"sha256": "a" * 64, "mb_family": "amadey", "corpus_dir": "/opt/pipeline/eval-corpus/amadey"}]})
    out = load_corpus(path)
    assert out == [CorpusSample("a" * 64, "amadey", "/opt/pipeline/eval-corpus/amadey", None)]


def test_analyst_label_optional_default_none(tmp_path):
    path = _write(tmp_path, {"samples": [
        {"sha256": "b" * 64, "mb_family": "stealc", "corpus_dir": "/d", "analyst_label": "stealc_v2"}]})
    assert load_corpus(path)[0].analyst_label == "stealc_v2"


def test_rejects_entry_missing_required_field(tmp_path):
    path = _write(tmp_path, {"samples": [{"sha256": "c" * 64, "mb_family": "x"}]})  # no corpus_dir
    with pytest.raises(ValueError):
        load_corpus(path)
