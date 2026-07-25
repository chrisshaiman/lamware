# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
from lamware_eval.scorecard import render_scorecard


def test_render_has_title_arms_and_family_refs():
    cells = [{"arm": "qwen@25", "sample": "abc123", "family_guess": "stage1_loader",
              "mb_family": "amadey", "claude_family": "dcrat", "grounded": 1, "total": 2,
              "fabricated": ["x"], "grounded_ratio": 0.5, "completed": True,
              "tool_calls_used": 10, "tool_call_error_rate": 0.0, "wall_seconds": 571.1,
              "cost_usd": 0.0, "error": None}]
    summary = {"qwen@25": {"n": 1, "mean_grounded_ratio": 0.5, "total_fabricated": 1,
                           "completed_rate": 1.0, "mean_wall_seconds": 571.1, "total_cost_usd": 0.0}}
    md = render_scorecard("re-turns-vs-sonnet5", cells, summary)
    assert "# RE Eval — re-turns-vs-sonnet5" in md
    assert "qwen@25" in md
    assert "stage1_loader" in md and "amadey" in md and "dcrat" in md  # guess + refs
    assert "mean_grounded_ratio" in md  # summary present
