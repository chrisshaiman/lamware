# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Render the composite eval scorecard as markdown for analyst adjudication."""
from pathlib import Path

from lamware_eval.provenance import render as render_provenance


def write_scorecard(out: Path, md: str, force: bool) -> None:
    """Write it, refusing to silently replace a different run's scorecard.

    The path is derived from `--label`, which defaults to a fixed string in both
    entry points, so a second run overwrote the first with no backup and no way
    to tell what it destroyed — #405, one directory over. Refusing is the right
    default because the destroyed file is usually the one somebody wanted.
    """
    if out.exists() and not force:
        raise SystemExit(
            f"refusing to overwrite {out}\n"
            f"  it already holds a scorecard, and the numbers in it may not be\n"
            f"  comparable to this run's (#486). Pass --force to replace it, or\n"
            f"  --label something else to keep both.")
    out.write_text(md)


def render_scorecard(label: str, cells: list[dict], summary: dict,
                     provenance: dict | None = None) -> str:
    # The title used to be the whole of a scorecard's identity, and `label` is
    # whatever an operator typed. Two runs against different corpora, or either
    # side of a fix that changed what a sample means, were indistinguishable
    # (#486). The block goes directly under the title because a reader who
    # scrolls past it has already started reading the numbers.
    lines = [f"# RE Eval — {label}\n"]
    block = render_provenance(provenance)
    if block:
        lines.append(block)
    lines.append("## Summary (per arm)\n")
    # n_with_claims/total_claims sit next to the ratio on purpose: a ratio over
    # zero claims is not a good score, it is an absent one.
    # parse_failures sits beside completed_rate for the same reason
    # n_with_claims sits beside the ratio: a completed_rate of 1.0 that hides
    # two unparseable answers is not a good score, it is a misleading one
    # (#380). The 29-sample MOTIF sweep reported exactly that.
    # n_valid and tool_layer_broken sit immediately after n, because every rate
    # to their right is computed over n_valid rather than n. Without them the
    # summary silently reports a smaller denominator than the row's own `n`
    # (#316) — the same "a number nobody can see is not a fix" trap as #380.
    # total_grounded_novel and total_grounded_recited sit next to each other on
    # purpose: `grounded` counts both, so across the evidence axis it is not a
    # comparison. An arm restating its own prompt earns grounded claims and zero
    # fabrications — the best-looking cell this table can render — and until
    # these two columns existed nothing here could say so (#491).
    #
    # total_bare_symbols and total_unscoreable were computed all along and never
    # shown. Both change the reading of the ratio beside them: a cell citing two
    # Ghidra auto-generated DAT_ labels scored 1.00 and outranked one citing
    # three concrete addresses at 0.75.
    #
    # total_techniques is here because grounding scores code_level_ioc ONLY.
    # attack_techniques are unscored, which makes them the cheapest thing for an
    # evidence-fed arm to inflate; the pilot's +corr arm doubled them, 3 to 6,
    # with two that appear nowhere in its evidence.
    cols = ["n", "n_valid", "tool_layer_broken",
            "n_with_claims", "total_claims", "mean_grounded_ratio",
            "total_grounded_novel", "total_grounded_recited",
            "total_fabricated", "total_bare_symbols", "total_unscoreable",
            "total_techniques",
            "completed_rate", "parse_failures",
            "cells_with_ghidra_warnings",
            "mean_wall_seconds", "total_cost_usd"]
    lines.append("| arm | " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * (len(cols) + 1))
    for arm, s in summary.items():
        lines.append(f"| {arm} | " + " | ".join(str(s[c]) for c in cols) + " |")
    lines.append("\n## Per sample × arm\n")
    # `seed` sits next to `arm` because a local cell without one is not
    # reproducible, and that has to be visible on the same row as its score
    # rather than inferred from the arm name.
    cell_cols = ["arm", "seed", "sample", "family_guess", "mb_family", "claude_family",
                 "grounded", "grounded_novel", "grounded_recited",
                 "total", "fabricated", "bare_symbols", "unscoreable",
                 "techniques", "capabilities", "completed", "parse_failed",
                 "tool_calls_used",
                 # tool_layer_broken sits next to the rate because the rate alone
                 # is easy to skim past: 1.0 there means the cell measured the
                 # infrastructure, not the model, and is out of the aggregates.
                 "tool_call_error_rate", "tool_layer_broken",
                 # The static analysis that fed this cell, contradicting itself:
                 # a 150KB PE yielding 1 function reads as a quiet model unless
                 # this column says otherwise (#367).
                 "ghidra_warnings",
                 "wall_seconds", "cost_usd", "error"]
    lines.append("| " + " | ".join(cell_cols) + " |")
    lines.append("|" + "---|" * len(cell_cols))
    for c in cells:
        lines.append("| " + " | ".join(str(c.get(col)) for col in cell_cols) + " |")
    return "\n".join(lines) + "\n"
