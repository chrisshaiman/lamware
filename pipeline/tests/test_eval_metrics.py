# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import aggregate, compose_cell

SAMPLE = CorpusSample("a" * 64, "amadey", "/d")


def test_compose_cell_scores_grounding_and_carries_refs():
    analysis = {"malware_family_guess": "stage1_loader",
                "code_level_iocs": [{"value": "GetTempPathW"}, {"value": "notreal.xyz"}]}
    source = "the binary calls GetTempPathW to build a path"
    cell = compose_cell("qwen@25", SAMPLE, analysis, source, claude_family="dcrat",
                        wall_seconds=571.1, cost_usd=0.0,
                        tool_metrics={"completed": True, "tool_calls_used": 10, "tool_call_error_rate": 0.0},
                        error=None)
    assert cell["arm"] == "qwen@25"
    assert cell["family_guess"] == "stage1_loader"
    assert cell["mb_family"] == "amadey" and cell["claude_family"] == "dcrat"
    assert cell["grounded"] == 1 and cell["total"] == 2 and cell["fabricated"] == ["notreal.xyz"]
    assert cell["completed"] is True and cell["cost_usd"] == 0.0


def test_aggregate_summarizes_per_arm():
    cells = [
        {"arm": "qwen@25", "grounded_ratio": 1.0, "total": 3, "fabricated": [], "completed": True, "wall_seconds": 100.0, "cost_usd": 0.0},
        {"arm": "qwen@25", "grounded_ratio": 0.5, "total": 2, "fabricated": ["x"], "completed": False, "wall_seconds": 200.0, "cost_usd": 0.0},
    ]
    summ = aggregate(cells)["qwen@25"]
    assert summ["mean_grounded_ratio"] == 0.75
    assert summ["total_fabricated"] == 1
    assert summ["completed_rate"] == 0.5
    assert summ["mean_wall_seconds"] == 150.0
    assert summ["total_cost_usd"] == 0.0


def test_silent_arm_does_not_score_a_vacuous_perfect_grounding():
    """A cell claiming NO IOCs scores grounded_ratio 1.0 (nothing claimed =
    nothing to fake). Averaging those in would rank a model that says nothing
    above one that makes checkable claims.

    Observed live 2026-07-25: qwen@10 on IcedID emitted 0 code_level_iocs and
    scored a 'perfect' 1.0, while the Opus 4.6 baseline made 15 real claims on
    the same sample.
    """
    cells = [
        {"arm": "silent", "grounded_ratio": 1.0, "total": 0, "fabricated": [], "completed": True, "wall_seconds": 700.0, "cost_usd": 0.0},
        {"arm": "silent", "grounded_ratio": 1.0, "total": 0, "fabricated": [], "completed": True, "wall_seconds": 700.0, "cost_usd": 0.0},
    ]
    s = aggregate(cells)["silent"]
    assert s["n"] == 2
    assert s["n_with_claims"] == 0
    assert s["total_claims"] == 0
    # No scored cells -> the ratio is undefined, NOT a perfect 1.0.
    assert s["mean_grounded_ratio"] is None


def test_grounding_ratio_averages_only_cells_that_made_claims():
    cells = [
        {"arm": "mixed", "grounded_ratio": 0.5, "total": 4, "fabricated": ["a", "b"], "completed": True, "wall_seconds": 10.0, "cost_usd": 0.0},
        {"arm": "mixed", "grounded_ratio": 1.0, "total": 0, "fabricated": [], "completed": True, "wall_seconds": 10.0, "cost_usd": 0.0},
    ]
    s = aggregate(cells)["mixed"]
    assert s["n"] == 2 and s["n_with_claims"] == 1
    assert s["total_claims"] == 4
    # The silent cell must not drag the ratio up to 0.75.
    assert s["mean_grounded_ratio"] == 0.5
