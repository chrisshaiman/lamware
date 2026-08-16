# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Render the composite eval scorecard as markdown for analyst adjudication."""


def render_scorecard(label: str, cells: list[dict], summary: dict) -> str:
    lines = [f"# RE Eval — {label}\n", "## Summary (per arm)\n"]
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
    cols = ["n", "n_valid", "tool_layer_broken",
            "n_with_claims", "total_claims", "mean_grounded_ratio",
            "total_fabricated", "completed_rate", "parse_failures",
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
                 "grounded", "total", "fabricated", "completed", "parse_failed",
                 "tool_calls_used",
                 # tool_layer_broken sits next to the rate because the rate alone
                 # is easy to skim past: 1.0 there means the cell measured the
                 # infrastructure, not the model, and is out of the aggregates.
                 "tool_call_error_rate", "tool_layer_broken",
                 "wall_seconds", "cost_usd", "error"]
    lines.append("| " + " | ".join(cell_cols) + " |")
    lines.append("|" + "---|" * len(cell_cols))
    for c in cells:
        lines.append("| " + " | ".join(str(c.get(col)) for col in cell_cols) + " |")
    return "\n".join(lines) + "\n"
