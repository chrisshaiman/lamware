# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Paired statistics over order-variants (#715).

Synthetic cells with a KNOWN effect, so each test can say what the right answer
is: a planted +0.2 must be found with an interval excluding 0; identical arms
must give an interval containing 0; and the pairing must be by (sample, k), not
by list position and not by comparing unpaired means — the two mutants that
produce plausible-looking numbers from the same cells.
"""
import pytest
from lamware_eval import stats
from lamware_eval.stats import (
    bootstrap_ci,
    distributions,
    draws,
    paired_comparison,
    render_variant_stats,
)


def cell(sample: str, arm: str, k: int, recall: float | None, *, completed=True,
         effective=True, sha: str | None = None, total=2, grounded=1,
         fabricated=("x",), broken=False) -> dict:
    return {"sample": sample, "arm": arm, "technique_recall": recall,
            "completed": completed, "tool_layer_broken": broken,
            "total": total, "grounded": grounded, "fabricated": list(fabricated),
            "grounded_ratio": (grounded / total) if total else 1.0,
            "modality": "native_pe",
            "input_detail": {"variant": k, "variant_effective": None if k == 0 else effective,
                             "input_sha": sha or f"{sample}-{k}"}}


def base_value(i: int, k: int) -> float:
    """Wide per-variant spread, like the host measurement (0.00-0.67)."""
    return round(((i * 7 + k * 13) % 10) / 15, 4)


def planted(effect: float, samples=8, variants=5, jitter=0.0) -> list[dict]:
    cells = []
    for i in range(samples):
        for k in range(variants):
            a = base_value(i, k)
            noise = jitter * (1 if (i + k) % 2 else -1)
            cells.append(cell(f"s{i}", "A", k, a))
            cells.append(cell(f"s{i}", "B", k, round(a + effect + noise, 4)))
    return cells


def test_a_planted_effect_is_found_and_its_interval_excludes_zero():
    r = paired_comparison(planted(0.2, jitter=0.05), "A", "B", "technique_recall")
    assert r["samples"] == 8 and r["pairs"] == 40 and r["unpaired"] == 0
    assert r["effect"] == pytest.approx(0.2, abs=0.02)
    lo, hi = r["ci"]
    assert 0 < lo <= r["effect"] <= hi
    assert r["verdict"] == "B > A"
    assert (r["positive"], r["negative"], r["zero"]) == (8, 0, 0)


def test_a_planted_negative_effect_reads_the_other_way():
    r = paired_comparison(planted(-0.15, jitter=0.05), "A", "B", "technique_recall")
    assert r["ci"][1] < 0 and r["verdict"] == "B < A"


def test_identical_arms_are_not_distinguishable_from_zero():
    r = paired_comparison(planted(0.0), "A", "B", "technique_recall")
    assert r["effect"] == 0 and r["ci"] == (0.0, 0.0)
    assert r["verdict"] == "not distinguishable from 0"
    assert r["zero"] == 8


def test_a_noisy_null_spans_zero():
    """Mean-zero noise per pair: the interval must straddle 0, not exclude it."""
    cells = []
    for i in range(10):
        for k in range(4):
            a = base_value(i, k)
            cells.append(cell(f"s{i}", "A", k, a))
            # +0.1 / -0.1 alternating by sample, so samples disagree in sign.
            cells.append(cell(f"s{i}", "B", k, round(a + (0.1 if i % 2 else -0.1), 4)))
    r = paired_comparison(cells, "A", "B", "technique_recall")
    lo, hi = r["ci"]
    assert lo < 0 < hi and r["verdict"] == "not distinguishable from 0"
    assert (r["positive"], r["negative"]) == (5, 5)


def test_pairing_is_by_variant_not_by_position_or_by_unpaired_means():
    """B = A + 0.1 on EVERY variant, so paired by k each difference is exactly
    0.1 and the interval is a point. B's cells arrive in reverse k order, so
    pairing by position gives differences of either sign. A's v3 is an outlier
    whose B partner was invalid: dropped and counted as unpaired, it changes
    nothing; compared as an unpaired mean, it drags the effect down.
    Mutation-tested: both mutants fail here."""
    cells = []
    for i in range(4):
        a_vals = {k: base_value(i, k) for k in range(4)}
        a_vals[3] = 0.9
        for k in range(4):
            cells.append(cell(f"s{i}", "A", k, a_vals[k]))
        for k in reversed(range(4)):
            cells.append(cell(f"s{i}", "B", k, round(a_vals[k] + 0.1, 4),
                              completed=(k != 3)))
    r = paired_comparison(cells, "A", "B", "technique_recall")
    assert r["sample_effects"] == {f"s{i}": 0.1 for i in range(4)}
    assert r["effect"] == 0.1 and r["ci"] == (0.1, 0.1)
    assert r["unpaired"] == 4 and r["pairs"] == 12


def test_the_bootstrap_is_reproducible_with_its_seed():
    groups = [[0.1, 0.3, -0.2], [0.0, 0.5], [0.2, 0.2, 0.4, -0.1]]
    assert bootstrap_ci(groups, 500, seed=1) == bootstrap_ci(groups, 500, seed=1)
    assert bootstrap_ci(groups, 500, seed=1) != bootstrap_ci(groups, 500, seed=2)
    a = render_variant_stats(planted(0.1, jitter=0.07))
    assert a == render_variant_stats(planted(0.1, jitter=0.07))


def test_the_bootstrap_resamples_within_samples_too():
    """One sample whose variants disagree: resampling samples alone would give
    a point interval; resampling its variants gives a spread."""
    lo, hi = bootstrap_ci([[0.0, 0.4, -0.4, 0.2]], 1000)
    assert lo < hi


def test_one_sample_is_not_called_a_finding():
    cells = [c for c in planted(0.3, jitter=0.05) if c["sample"] == "s0"]
    r = paired_comparison(cells, "A", "B", "technique_recall")
    assert r["samples"] == 1 and r["verdict"].startswith("one sample")


def test_ineffective_duplicate_and_invalid_cells_are_not_draws():
    cells = [cell("s", "A", 0, 0.5, sha="h0"),
             cell("s", "A", 1, 0.5, effective=False, sha="h0"),
             cell("s", "A", 2, 0.1, sha="h2"),
             cell("s", "A", 3, 0.7, sha="h2"),          # same input as v2
             cell("s", "A", 4, 0.0, sha="h4", broken=True),
             cell("s", "A", 5, 0.3, sha="h5")]
    kept, excluded = draws(cells)
    assert sorted(k for (_s, _a, k) in kept) == [0, 2, 5]
    assert excluded[("s", "A")] == {"invalid": 1, "ineffective": 1, "duplicate": 1}
    d = distributions(cells)[("s", "A")]
    assert d["n"] == 3
    assert d["technique_recall"] == {"n": 3, "median": 0.3, "min": 0.1, "max": 0.5}


def test_cells_without_a_variant_are_not_in_the_statistics():
    plain = cell("s", "A", 0, 0.5)
    plain["input_detail"] = {"kind": "native_pe"}
    assert draws([plain]) == ({}, {})
    assert render_variant_stats([plain]) == ""


def test_a_ratio_over_no_claims_is_no_value_not_a_perfect_score():
    cells = [cell("s", "A", 0, 0.5, total=0, grounded=0, fabricated=()),
             cell("s", "B", 0, 0.5)]
    r = paired_comparison(cells, "A", "B", "grounded_ratio")
    assert r["no_metric"] == 1 and r["pairs"] == 0 and r["verdict"] == "no paired cells"


def test_the_scorecard_sections_say_what_they_found():
    md = render_variant_stats(planted(0.0) + [
        cell("s0", "C", k, base_value(0, k)) for k in range(5)])
    assert "## Distribution per sample" in md and "## Paired comparison" in md
    assert "not distinguishable from 0" in md
    # Every pair of arms present.
    for a, b in (("A", "B"), ("A", "C"), ("B", "C")):
        assert f"| {a} | {b} | technique_recall |" in md
    assert f"seed {stats.BOOTSTRAP_SEED}" in md
