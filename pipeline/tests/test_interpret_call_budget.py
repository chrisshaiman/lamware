# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A tool call the run budget rejects must not be counted as used.

The agentic loop counted first and checked afterwards:

    tool_calls_used += 1
    if tool_calls_used > max_tool_calls:
        ... refuse the call ...
        continue

so every refused call kept its increment. With `max_tool_calls = 20` and 23
attempted calls the run executed 20 and reported 23 — the counter that appears
in `emit_status`, in the final message, and in the eval scorecard.

The per-turn deferral branch a few lines above already gets this right, and
says why in its comment: "Deliberately not counted against tool_calls_used —
nothing was executed, and charging for a deferral would silently shrink the
run's real depth." The same reasoning applies to a budget refusal; the two
branches simply disagreed.

The check now reads the pre-increment value with `>=`, which admits exactly the
same calls the post-increment `>` did — asserted below rather than argued.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "ansible" / "roles" / "interpret" / "files"
       / "interpret-ghidra.py").read_text(encoding="utf-8")


def _simulate(attempted: int, cap: int) -> tuple[list[int], int]:
    """The loop's accounting, in the order the source now performs it."""
    used, ran = 0, []
    for i in range(1, attempted + 1):
        if used >= cap:
            continue
        used += 1
        ran.append(i)
    return ran, used


def test_the_budget_is_checked_before_the_increment():
    """THE bug, structurally: the increment must not precede the guard."""
    start = SRC.index("calls_this_turn += 1")
    window = SRC[start:start + 1600]
    guard = window.index("if tool_calls_used >= max_tool_calls:")
    increment = window.index("tool_calls_used += 1")
    assert guard < increment, (
        "tool_calls_used is incremented before the budget check again, so a "
        "refused call is still charged to the run")


def test_the_old_post_increment_comparison_is_gone():
    assert "if tool_calls_used > max_tool_calls:" not in SRC


def test_a_refused_call_is_not_counted():
    for cap in (1, 3, 20):
        _, used = _simulate(cap + 3, cap)
        assert used == cap, f"cap={cap}: reported {used} calls for a {cap}-call budget"


def test_the_execution_boundary_is_unchanged():
    """The fix must not change WHICH calls run — only the reported count. This
    replays the previous accounting and compares."""
    def old(attempted, cap):
        used, ran = 0, []
        for i in range(1, attempted + 1):
            used += 1
            if used > cap:
                continue
            ran.append(i)
        return ran
    for cap in (1, 3, 20):
        assert _simulate(cap + 3, cap)[0] == old(cap + 3, cap), f"cap={cap}"


def test_a_run_under_budget_is_unaffected():
    ran, used = _simulate(5, 20)
    assert ran == [1, 2, 3, 4, 5] and used == 5


def test_the_deferral_branch_still_does_not_count():
    """The sibling this was made consistent with. If deferrals ever start
    counting, the two branches disagree again — in the other direction."""
    start = SRC.index("if calls_this_turn >= max_tool_calls_per_turn:")
    block = SRC[start:SRC.index("continue", start)]
    assert "tool_calls_used += 1" not in block


def test_the_script_still_compiles():
    compile(SRC, "interpret-ghidra.py", "exec")
    assert isinstance(ast.parse(SRC), ast.Module)
    assert re.search(r"max_tool_calls\b", SRC)
