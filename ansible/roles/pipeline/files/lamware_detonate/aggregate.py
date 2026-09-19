# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Stratify a batch by detonation tier, because pooling across tiers is the bug.

#518 spent six weeks on an apparent +/-15-25 "noise floor" in observed_behaviour.
It was never measurement error. It was three measurement conditions averaged
together. Conditioned on tier the same instrument is near-deterministic:

    CLEAN     every hollowed child traced    signatures 34.3 +/- 0.7
    PARTIAL   some traced, some lost         signatures 32.2 +/- 0.4
    ALL-LOST  none traced                    signatures 20.8 +/- 0.4

Two back-to-back batches of the SAME sample on the SAME host averaged 53.5 and
45.7 purely because their CLEAN/PARTIAL mix differed.

So the pooled mean is not merely less informative than the strata -- it is the
artefact that made the question unanswerable. summarize() therefore reports the
pooled figure only alongside the strata, and labels it as not a measurement
whenever more than one tier is present.
"""
from __future__ import annotations

import statistics
from collections import defaultdict

# The metrics worth stratifying. observed_behaviour is the #518 primary; the
# other two are its volatile and stable components respectively -- signatures is
# the robust term, payloads_extracted is what makes observed_behaviour fragile
# because it counts per-process dumps.
METRICS = ("observed_behaviour", "signatures", "payloads_extracted")

TIER_ORDER = ("CLEAN", "PARTIAL", "ALL-LOST", "NO-HOLLOW")


def stratify(runs) -> dict[str, list]:
    """Group completed runs by tier, in a stable, documented order."""
    by_tier: dict[str, list] = defaultdict(list)
    for r in runs:
        by_tier[r.tier or "UNKNOWN"].append(r)
    ordered = {t: by_tier[t] for t in TIER_ORDER if t in by_tier}
    for t in sorted(by_tier):          # anything CAPE grows later still shows up
        ordered.setdefault(t, by_tier[t])
    return ordered


def _stats(values: list[float]) -> dict:
    """n / mean / sd. sd is None at n<2 rather than 0.0.

    Reporting sd=0 for a single run would say "perfectly reproducible" about a
    sample size that cannot support any statement about spread -- and calling a
    result at n=4 is a mistake this project has already made more than once.
    """
    if not values:
        return {"n": 0, "mean": None, "sd": None}
    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 2),
        "sd": round(statistics.stdev(values), 2) if len(values) > 1 else None,
    }


def summarize(result) -> dict:
    """Per-tier statistics, plus a pooled figure that is explicitly caveated."""
    completed = result.completed
    by_tier = stratify(completed)

    strata = {}
    for tier, runs in by_tier.items():
        strata[tier] = {
            "runs": [r.index for r in runs],
            "tasks": [r.task_id for r in runs],
            **{m: _stats([r.metrics.get(m) for r in runs
                          if isinstance(r.metrics.get(m), (int, float))])
               for m in METRICS},
        }

    pooled = {m: _stats([r.metrics.get(m) for r in completed
                         if isinstance(r.metrics.get(m), (int, float))])
              for m in METRICS}

    mixed = len(by_tier) > 1
    return {
        "sample": getattr(result, "sample_name", None),
        "machine": completed[0].machine if completed else None,
        "runs_requested": len(result.runs),
        "runs_completed": len(completed),
        "aborted": result.aborted,
        "abort_reason": result.abort_reason,
        "tiers": strata,
        "pooled": pooled,
        "pooled_is_a_measurement": not mixed,
        "pooled_caveat": (
            f"{len(by_tier)} tiers present ({', '.join(by_tier)}): the pooled mean "
            "mixes measurement conditions and is NOT a measurement. Compare strata. "
            "This is exactly the artefact that produced the #518 noise floor."
        ) if mixed else "single tier: pooled and stratified figures coincide.",
    }


def render(summary: dict) -> str:
    """Human-readable scorecard. The caveat is not optional and not a footnote."""
    L = []
    L.append(f"sample            {summary.get('sample')}")
    L.append(f"machine           {summary.get('machine')}  (pinned)")
    L.append(f"runs              {summary['runs_completed']}/{summary['runs_requested']} completed")
    if summary["aborted"]:
        L.append(f"ABORTED           {summary['abort_reason']}")
    L.append("")
    head = f"{'tier':<10} {'n':>3}  " + "  ".join(f"{m:>22}" for m in METRICS)
    L.append(head)
    L.append("-" * len(head))
    for tier, s in summary["tiers"].items():
        cells = []
        for m in METRICS:
            st = s[m]
            mean, sd = st["mean"], st["sd"]
            cells.append(f"{'--' if mean is None else mean:>10} +/- {'n/a' if sd is None else sd:<8}")
        L.append(f"{tier:<10} {s[METRICS[0]]['n']:>3}  " + "  ".join(cells))
    L.append("")
    if not summary["pooled_is_a_measurement"]:
        L.append("POOLED IS NOT A MEASUREMENT")
    L.append(f"  {summary['pooled_caveat']}")
    st = summary["pooled"]["observed_behaviour"]
    L.append(f"  pooled observed_behaviour: n={st['n']} mean={st['mean']} sd={st['sd']}")
    return "\n".join(L)
