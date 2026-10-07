# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Distributions over order-variants, and paired arm comparisons (#715).

Pure functions over scorecard cells, stdlib only.

Why paired, and why by variant: the variance that matters here is between
ORDERINGS of one sample's input (amadey's technique recall spanned 0.00-0.67
over five of them, 2026-10-05). Two arms run on the same ordering see the same
first message, so their difference on that ordering is free of it; two arms
compared on different orderings, or on their means, carry it whole. So a pair
is (sample, variant k), both arms, both valid — never "the i-th cell of each".

Which cells are draws:

* `invalid`     tool layer broken or not completed: it measured the
                infrastructure, as in the Summary table (#316).
* `ineffective` a variant whose reordering moved nothing (`variant_effective:
                false`) is v0's input again; output is deterministic, so it is
                v0's draw again and counting it would shrink every interval for
                nothing.
* `duplicate`   two variants of one sample that produced the same agent-visible
                text (`input_sha`), for the same reason.

`ineffective` and `duplicate` depend only on the sample's input, never on the
arm, so dropping them removes the same k from both sides of a pair.

The bootstrap CI resamples SAMPLES with replacement and, inside each drawn
sample, its per-variant differences with replacement: two levels because the
claim is about samples like these, and a single sample's variants are not
independent evidence about other samples. Seeded, so a scorecard re-renders
byte-identical; drawn with `Random.random()`, the one generator output Python
guarantees across versions for a given seed.
"""
import random
from collections import defaultdict
from collections.abc import Callable
from itertools import combinations
from statistics import median

#: Fixed so the same cells always render the same interval.
BOOTSTRAP_SEED = 715
BOOTSTRAP_RESAMPLES = 2000

#: Metric name -> value of one cell, or None when the cell has no such value.
#: grounded_ratio over a cell with no claims is a vacuous 1.0, which is why the
#: Summary averages it over claim-bearing cells only; same rule here.
METRICS: dict[str, Callable[[dict], float | None]] = {
    "technique_recall": lambda c: c.get("technique_recall"),
    "grounded_ratio": lambda c: (c.get("grounded_ratio")
                                 if (c.get("total") or 0) > 0 else None),
    "fabricated": lambda c: len(c.get("fabricated") or []),
    "grounded": lambda c: c.get("grounded"),
}


def variant_of(cell: dict) -> int | None:
    """The cell's variant k, or None for a cell from a run without variants."""
    return (cell.get("input_detail") or {}).get("variant")


def is_valid(cell: dict) -> bool:
    """A cell that measured the model (see the module docstring)."""
    return bool(cell.get("completed")) and not cell.get("tool_layer_broken")


def draws(cells: list[dict]) -> tuple[dict[tuple[str, str, int], dict], dict]:
    """The cells that count as draws, keyed (sample, arm, k), and what was excluded.

    Returns `(kept, excluded)` where `excluded[(sample, arm)]` counts
    `invalid` / `ineffective` / `duplicate`.
    """
    by_cell: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for c in cells:
        if variant_of(c) is not None:
            by_cell[(c["sample"], c["arm"])].append(c)
    kept: dict[tuple[str, str, int], dict] = {}
    excluded: dict[tuple[str, str], dict[str, int]] = {}
    for (sample, arm), cs in by_cell.items():
        counts = {"invalid": 0, "ineffective": 0, "duplicate": 0}
        seen: set[str] = set()
        for c in sorted(cs, key=variant_of):
            k = variant_of(c)
            detail = c.get("input_detail") or {}
            sha = detail.get("input_sha")
            if k > 0 and detail.get("variant_effective") is False:
                counts["ineffective"] += 1
                continue
            if sha is not None and sha in seen:
                counts["duplicate"] += 1
                continue
            if sha is not None:
                seen.add(sha)
            if not is_valid(c):
                counts["invalid"] += 1
                continue
            kept[(sample, arm, k)] = c
        excluded[(sample, arm)] = counts
    return kept, excluded


def describe(values: list[float]) -> dict:
    """n, median, min, max of a list; the three statistics are None when empty."""
    if not values:
        return {"n": 0, "median": None, "min": None, "max": None}
    return {"n": len(values), "median": round(median(values), 4),
            "min": round(min(values), 4), "max": round(max(values), 4)}


def distributions(cells: list[dict]) -> dict[tuple[str, str], dict]:
    """Per (sample, arm): n draws, exclusions, modality, and each metric's spread."""
    kept, excluded = draws(cells)
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for (sample, arm, _k), c in sorted(kept.items()):
        grouped[(sample, arm)].append(c)
    modality = {}
    for c in cells:
        if variant_of(c) == 0:
            modality[(c["sample"], c["arm"])] = c.get("modality")
    out = {}
    for key in excluded:
        cs = grouped.get(key, [])
        out[key] = {
            "n": len(cs),
            "excluded": excluded[key],
            "modality": modality.get(key),
            **{name: describe([v for v in (fn(c) for c in cs) if v is not None])
               for name, fn in METRICS.items()},
        }
    return out


def _quantile(sorted_vals: list[float], q: float) -> float:
    """Linear-interpolation quantile of an already sorted list."""
    pos = (len(sorted_vals) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def bootstrap_ci(groups: list[list[float]], resamples: int = BOOTSTRAP_RESAMPLES,
                 seed: int = BOOTSTRAP_SEED, level: float = 0.95) -> tuple[float, float]:
    """Percentile CI of the mean-of-group-means, resampling groups then members.

    `groups` is one list of paired differences per sample, in a fixed order.
    """
    rng = random.Random(seed)  # nosec B311 — seeded bootstrap resampling, reproducible by design, not security/crypto

    def pick(n: int) -> int:
        return min(int(rng.random() * n), n - 1)

    stats = []
    for _ in range(resamples):
        means = []
        for _ in range(len(groups)):
            g = groups[pick(len(groups))]
            means.append(sum(g[pick(len(g))] for _ in range(len(g))) / len(g))
        stats.append(sum(means) / len(means))
    stats.sort()
    tail = (1 - level) / 2
    return round(_quantile(stats, tail), 4), round(_quantile(stats, 1 - tail), 4)


def paired_comparison(cells: list[dict], arm_a: str, arm_b: str, metric: str,
                      resamples: int = BOOTSTRAP_RESAMPLES,
                      seed: int = BOOTSTRAP_SEED) -> dict:
    """B − A on `metric`, paired by (sample, variant k).

    Sample effect = mean of its paired differences; overall effect = mean of
    sample effects, so a sample with more variants does not weigh more.
    `unpaired` counts valid draws whose partner (same sample, same k, other
    arm) is missing or invalid; `no_metric` counts pairs where either side has
    no value for the metric (a sample with no Cape techniques has no recall).
    """
    fn = METRICS[metric]
    kept, _ = draws(cells)
    keys_a = {(s, k) for (s, arm, k) in kept if arm == arm_a}
    keys_b = {(s, k) for (s, arm, k) in kept if arm == arm_b}
    per_sample: dict[str, list[float]] = defaultdict(list)
    unpaired = len(keys_a ^ keys_b)
    no_metric = 0
    for s, k in sorted(keys_a & keys_b):
        va, vb = fn(kept[(s, arm_a, k)]), fn(kept[(s, arm_b, k)])
        if va is None or vb is None:
            no_metric += 1
            continue
        per_sample[s].append(vb - va)
    samples = sorted(per_sample)
    effects = {s: round(sum(per_sample[s]) / len(per_sample[s]), 4) for s in samples}
    result = {
        "arm_a": arm_a, "arm_b": arm_b, "metric": metric,
        "samples": len(samples), "pairs": sum(len(v) for v in per_sample.values()),
        "unpaired": unpaired, "no_metric": no_metric,
        "sample_effects": effects,
        "positive": sum(1 for e in effects.values() if e > 0),
        "negative": sum(1 for e in effects.values() if e < 0),
        "zero": sum(1 for e in effects.values() if e == 0),
        "effect": None, "ci": None, "verdict": "no paired cells",
    }
    if not samples:
        return result
    result["effect"] = round(sum(effects.values()) / len(effects), 4)
    lo, hi = bootstrap_ci([per_sample[s] for s in samples], resamples, seed)
    result["ci"] = (lo, hi)
    if len(samples) < 2:
        result["verdict"] = ("one sample: the interval covers its orderings only, "
                             "not other samples")
    elif lo <= 0 <= hi:
        result["verdict"] = "not distinguishable from 0"
    else:
        result["verdict"] = f"{arm_b} {'>' if lo > 0 else '<'} {arm_a}"
    return result


def _fmt(d: dict) -> str:
    if not d["n"]:
        return "—"
    return f"{d['median']} [{d['min']}–{d['max']}] n={d['n']}"


def render_variant_stats(cells: list[dict]) -> str:
    """The "Distribution per sample" and "Paired comparison" sections, or "".

    Empty for a run without variants, so `--variants 0` renders exactly the
    scorecard it always did.
    """
    if not any(variant_of(c) is not None for c in cells):
        return ""
    lines = ["\n## Distribution per sample\n",
             "Each row is one sample × arm over its order-variants (#715): v0 is the "
             "input as recorded, v1..vK reorder the shown imports and strings. "
             "`excluded` counts cells that are not draws: invalid (tool layer broken "
             "or not completed), ineffective (the reordering moved nothing) and "
             "duplicate (same agent-visible text as an earlier variant). The Summary "
             "table above pools every variant cell of an arm.\n"]
    cols = ["sample", "arm", "modality", "n", "excluded", *METRICS]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * len(cols))
    dist = distributions(cells)
    for (sample, arm), d in sorted(dist.items()):
        ex = d["excluded"]
        ex_s = ", ".join(f"{k}={v}" for k, v in ex.items() if v) or "0"
        mod = d["modality"]
        if mod and mod.startswith("dotnet"):
            mod = f"{mod} (v0 only: no .NET variants in this change)"
        lines.append(f"| {sample} | {arm} | {mod} | {d['n']} | {ex_s} | "
                     + " | ".join(_fmt(d[m]) for m in METRICS) + " |")

    arms: list[str] = []
    for c in cells:
        if variant_of(c) is not None and c["arm"] not in arms:
            arms.append(c["arm"])
    if len(arms) < 2:
        return "\n".join(lines) + "\n"
    lines += ["\n## Paired comparison\n",
              f"Effect = B − A, paired by (sample, variant k) with both cells valid; "
              f"a sample's effect is the mean over its pairs, the overall effect the "
              f"mean over samples. 95% CI: percentile bootstrap, {BOOTSTRAP_RESAMPLES} "
              f"resamples of samples and then of variants within each sample, seed "
              f"{BOOTSTRAP_SEED}. `unpaired` cells have no valid partner and are "
              f"excluded.\n"]
    cols = ["A", "B", "metric", "samples", "pairs", "effect", "95% CI",
            "samples +/−/0", "unpaired", "no_metric", "verdict"]
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * len(cols))
    per_sample_lines = []
    for a, b in combinations(arms, 2):
        for metric in METRICS:
            r = paired_comparison(cells, a, b, metric)
            ci = f"[{r['ci'][0]}, {r['ci'][1]}]" if r["ci"] else "—"
            lines.append(f"| {a} | {b} | {metric} | {r['samples']} | {r['pairs']} | "
                         f"{r['effect']} | {ci} | "
                         f"{r['positive']}/{r['negative']}/{r['zero']} | "
                         f"{r['unpaired']} | {r['no_metric']} | {r['verdict']} |")
            if metric == "technique_recall" and r["sample_effects"]:
                per_sample_lines.append(
                    f"- {b} − {a}: " + ", ".join(f"{s} {e:+}" for s, e
                                                 in r["sample_effects"].items()))
    if per_sample_lines:
        lines.append("\nPer-sample technique_recall effect:\n")
        lines += per_sample_lines
    return "\n".join(lines) + "\n"
