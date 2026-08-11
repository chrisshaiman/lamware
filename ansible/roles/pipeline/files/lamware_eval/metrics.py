# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Per-cell metric composition + per-arm aggregation for the eval scorecard."""
from collections import defaultdict

from grounding_check import grounding_scorecard

from lamware_eval.corpus import CorpusSample


def compose_cell(arm_name: str, sample: CorpusSample, analysis: dict, source_text: str,
                 claude_family: str | None, wall_seconds: float, cost_usd: float,
                 tool_metrics: dict, error: str | None,
                 seed: int | None = None, sampling: dict | None = None) -> dict:
    """Compose one scorecard cell.

    `seed` is the seed REQUESTED for this cell (None = unpinned, so the run is not
    reproducible). `sampling` is what the inference server reported it actually
    applied. Both are recorded per cell rather than once per sweep because the
    server can be restarted mid-sweep, and a result whose sampling config is only
    known by recollection is not a result anyone can reproduce.
    """
    g = grounding_scorecard(analysis or {}, source_text)
    return {
        "arm": arm_name,
        "seed": seed,
        "sampling": sampling,
        "sample": sample.sha256[:12],
        # NOT a capability metric for this stage — see ADR-019. Measured: qwen 0/14
        # and the Claude reference 0/7 on the same samples, against labels that
        # disagree with the reference on every one of them. The MOTIF paper puts
        # AVClass at 46.78% and AV majority voting at 62.10%, so the label itself is
        # under 50% reliable.
        #
        # Scope the claim: supervised byte-level classifiers DO reach ~91% on packed
        # samples. What cannot work is an LLM reading DECOMPILED code over an open set
        # of 454+ families — a packer stub is generic as source while staying
        # distinctive as bytes.
        #
        # Read it as a CONTAMINATION PROBE. Near-zero is correct. An unexpectedly high
        # score is evidence of memorised published analyses rather than analysis of the
        # code, because analysis cannot get there from a packer stub.
        #
        # Do not tune prompts against this column.
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
    """Summarise cells per arm.

    Grounding is reported as a PAIR: the ratio, plus how many claims it was
    computed over. A cell that claims no IOCs scores a vacuous grounded_ratio of
    1.0 ("nothing claimed = nothing to fake"), so averaging every cell would
    rank a silent model above one making checkable claims — observed live on
    2026-07-25, where qwen@10 emitted 0 IOCs on IcedID and scored a 'perfect'
    1.0 against an Opus 4.6 baseline that made 15 real claims. mean_grounded_ratio
    therefore covers only cells with claims, and is None when there are none.
    """
    by_arm: dict[str, list[dict]] = defaultdict(list)
    for c in cells:
        by_arm[c["arm"]].append(c)
    out = {}
    for arm, cs in by_arm.items():
        n = len(cs)
        scored = [c for c in cs if (c.get("total") or 0) > 0]
        out[arm] = {
            "n": n,
            "n_with_claims": len(scored),
            "total_claims": sum(c.get("total") or 0 for c in cs),
            "mean_grounded_ratio": (
                round(sum(c["grounded_ratio"] for c in scored) / len(scored), 3)
                if scored else None
            ),
            "total_fabricated": sum(len(c["fabricated"]) for c in cs),
            "completed_rate": round(sum(1 for c in cs if c["completed"]) / n, 3),
            "mean_wall_seconds": round(sum(c["wall_seconds"] for c in cs) / n, 1),
            "total_cost_usd": round(sum(c["cost_usd"] for c in cs), 4),
        }
    return out
