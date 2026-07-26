# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Grounding must accept every IOC shape the models actually emit.

Models disagree on the schema: claude-sonnet-5 emits dicts
({"type","value","context"}), qwen3.6 emits bare strings. Assuming dicts raised
`AttributeError: 'str' object has no attribute 'get'` and killed 5 of 7 local
cells mid-scoring in benchmark pass 4 (2026-07-25) — after their results were
written, so the run reported "0 claims, 28% completion" instead of a crash, and
the local arm's grounding was never measured at all.
"""
from grounding_check import grounding_scorecard

SOURCE = "the loader calls GetTempPathW and builds ~%u.tmp then resolves LoadLibraryA"


def test_dict_shaped_iocs_score():
    a = {"code_level_iocs": [{"value": "GetTempPathW"}, {"value": "notreal.example"}]}
    s = grounding_scorecard(a, SOURCE)
    assert s["total"] == 2 and s["grounded"] == 1
    assert s["fabricated"] == ["notreal.example"]


def test_string_shaped_iocs_score():
    """The shape qwen emits - this used to raise AttributeError."""
    a = {"code_level_iocs": ["GetTempPathW", "notreal.example"]}
    s = grounding_scorecard(a, SOURCE)
    assert s["total"] == 2 and s["grounded"] == 1
    assert s["fabricated"] == ["notreal.example"]


def test_mixed_and_odd_shapes_do_not_raise():
    a = {"code_level_iocs": [{"value": "GetTempPathW"}, "~%u.tmp", 12345, None, ""]}
    s = grounding_scorecard(a, SOURCE)
    assert s["grounded"] == 2          # both real ones found
    assert "12345" in s["fabricated"]  # coerced, not crashed


def test_empty_list_is_not_a_perfect_score_by_accident():
    s = grounding_scorecard({"code_level_iocs": []}, SOURCE)
    assert s["total"] == 0 and s["grounded_ratio"] == 1.0  # aggregate() excludes these
