# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
from lamware_eval.metrics import aggregate
from lamware_eval.scorecard import render_scorecard

CELLS = [{"arm": "qwen@25", "sample": "abc123", "family_guess": "stage1_loader",
          "mb_family": "amadey", "claude_family": "dcrat", "grounded": 1, "total": 2,
          "fabricated": ["x"], "grounded_ratio": 0.5, "completed": True,
          "tool_calls_used": 10, "tool_call_error_rate": 0.0, "wall_seconds": 571.1,
          "cost_usd": 0.0, "error": None}]


def test_render_has_title_arms_and_family_refs():
    # Build the summary with the real aggregate() so the renderer's columns and
    # the metric shape cannot drift apart (a hand-written dict silently did).
    md = render_scorecard("re-turns-vs-sonnet5", CELLS, aggregate(CELLS))
    assert "# RE Eval — re-turns-vs-sonnet5" in md
    assert "qwen@25" in md
    assert "stage1_loader" in md and "amadey" in md and "dcrat" in md  # guess + refs
    assert "mean_grounded_ratio" in md  # summary present


def test_render_surfaces_claim_volume_next_to_the_ratio():
    """A grounding ratio is uninterpretable without how many claims it covers."""
    md = render_scorecard("x", CELLS, aggregate(CELLS))
    assert "n_with_claims" in md and "total_claims" in md


def test_render_handles_undefined_ratio_for_a_silent_arm():
    silent = [dict(CELLS[0], arm="silent", total=0, grounded=0, fabricated=[],
                   grounded_ratio=1.0)]
    md = render_scorecard("x", silent, aggregate(silent))
    assert "None" in md  # undefined ratio renders, does not crash
