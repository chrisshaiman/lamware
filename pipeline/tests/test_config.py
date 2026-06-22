# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for PipelineConfig (malfind slice POC)."""

import json

import pytest
from pydantic import ValidationError

from lamware_pipeline.config import PipelineConfig

_VALID = {
    "malfind_enabled": True,
    "malfind_max_candidates": 5,
    "malfind_min_size": 256,
    "malfind_max_size": 10485760,
    "malfind_min_score": 2,
    "malfind_benign_processes": ["csrss.exe", "smss.exe"],
}


def test_loads_valid_config(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    assert cfg.malfind_min_score == 2
    assert cfg.malfind_benign_processes == ["csrss.exe", "smss.exe"]


def test_rejects_wrong_type(tmp_path):
    bad = dict(_VALID, malfind_min_score="two")
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        PipelineConfig.load(str(p))


def test_rejects_missing_field(tmp_path):
    bad = {k: v for k, v in _VALID.items() if k != "malfind_min_score"}
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        PipelineConfig.load(str(p))
