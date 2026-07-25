# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Render the composite eval scorecard as markdown for analyst adjudication."""


def render_scorecard(label: str, cells: list[dict], summary: dict) -> str:
    lines = [f"# RE Eval — {label}\n", "## Summary (per arm)\n"]
    cols = ["n", "mean_grounded_ratio", "total_fabricated", "completed_rate",
            "mean_wall_seconds", "total_cost_usd"]
    lines.append("| arm | " + " | ".join(cols) + " |")
    lines.append("|" + "---|" * (len(cols) + 1))
    for arm, s in summary.items():
        lines.append(f"| {arm} | " + " | ".join(str(s[c]) for c in cols) + " |")
    lines.append("\n## Per sample × arm\n")
    cell_cols = ["arm", "sample", "family_guess", "mb_family", "claude_family",
                 "grounded", "total", "fabricated", "completed", "tool_calls_used",
                 "tool_call_error_rate", "wall_seconds", "cost_usd", "error"]
    lines.append("| " + " | ".join(cell_cols) + " |")
    lines.append("|" + "---|" * len(cell_cols))
    for c in cells:
        lines.append("| " + " | ".join(str(c.get(col)) for col in cell_cols) + " |")
    return "\n".join(lines) + "\n"
