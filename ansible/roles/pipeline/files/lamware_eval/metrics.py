# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Per-cell metric composition + per-arm aggregation for the eval scorecard."""
from collections import defaultdict

from grounding_check import grounding_scorecard

from lamware_eval.corpus import CorpusSample


def compose_cell(arm_name: str, sample: CorpusSample, analysis: dict, source_text: str,
                 claude_family: str | None, wall_seconds: float, cost_usd: float,
                 tool_metrics: dict, error: str | None) -> dict:
    g = grounding_scorecard(analysis or {}, source_text)
    return {
        "arm": arm_name,
        "sample": sample.sha256[:12],
        "family_guess": (analysis or {}).get("malware_family_guess"),
        "mb_family": sample.mb_family,
        "claude_family": claude_family,
        "grounded": g["grounded"], "total": g["total"],
        "fabricated": g["fabricated"], "grounded_ratio": g["grounded_ratio"],
        "completed": tool_metrics.get("completed"),
        "tool_calls_used": tool_metrics.get("tool_calls_used"),
        "tool_call_error_rate": tool_metrics.get("tool_call_error_rate"),
        "wall_seconds": wall_seconds, "cost_usd": cost_usd,
        "error": error,
    }


def aggregate(cells: list[dict]) -> dict:
    by_arm: dict[str, list[dict]] = defaultdict(list)
    for c in cells:
        by_arm[c["arm"]].append(c)
    out = {}
    for arm, cs in by_arm.items():
        n = len(cs)
        out[arm] = {
            "n": n,
            "mean_grounded_ratio": round(sum(c["grounded_ratio"] for c in cs) / n, 3),
            "total_fabricated": sum(len(c["fabricated"]) for c in cs),
            "completed_rate": round(sum(1 for c in cs if c["completed"]) / n, 3),
            "mean_wall_seconds": round(sum(c["wall_seconds"] for c in cs) / n, 1),
            "total_cost_usd": round(sum(c["cost_usd"] for c in cs), 4),
        }
    return out
