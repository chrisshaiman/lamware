# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tool-result size cap — bounds transcript growth for the local backend.

Tool results are appended to the transcript verbatim and never fall out, so every
oversized body is re-paid on each subsequent turn. The 2026-07-27 depth probe died at
20 tool calls with 46,216 tokens against a 32k window (~2.3k tokens/call, dominated by
decompiled function bodies) — the ceiling was context, not the cycle cap.
"""
import json

from stages import interpret
from stages.interpret import TOOL_RESULT_CHAR_CAP, cap_tool_result


def test_long_field_is_truncated_with_an_explicit_marker():
    """`cap` is now the budget for the WHOLE result, not for each field.

    Changed in #242. A note allowance is reserved from the budget, because the
    bookkeeping used to be appended after budgeting and pushed the result over cap.
    So the payload keeps slightly less than `cap` — the exact split is an
    implementation detail, the bound on the total is the contract.
    """
    body = "A" * 10_000
    out = cap_tool_result({"decompiled": body}, cap=6000)
    assert len(out["decompiled"]) < len(body)
    assert out["decompiled"].startswith("A" * 5000)   # most of the budget is payload
    assert "TRUNCATED" in out["decompiled"]
    assert "more characters" in out["decompiled"]
    assert len(json.dumps(out)) <= 6000 * 1.05


def test_marker_warns_against_assuming_the_remainder_is_empty():
    """A model given half a function must not infer the rest is absent — that would
    turn a harness-side omission into what the grounding metric reads as fabrication."""
    out = cap_tool_result({"decompiled": "X" * 9000}, cap=6000)
    assert "do not assume the remainder is empty" in out["decompiled"]


def test_short_values_are_untouched():
    src = {"decompiled": "int main(){return 0;}", "name": "main", "count": 3}
    assert cap_tool_result(src, cap=6000) == src


def test_list_values_are_now_bounded_too():
    """DECISION REVERSED in #242 — this test previously asserted the opposite.

    It read:

        def test_non_string_values_are_left_alone():
            src = {"functions": [{"name": "a"}] * 50, "count": 50, "ok": True}
            assert cap_tool_result(src, cap=10) == src

    That was deliberate, and it is what let a list-valued result escape the cap
    entirely: `get_strings_at` was measured returning **49,613 bytes against a
    12,000-char cap** on 2026-07-28, and the turn carrying it cost 33.4 minutes of a
    180-minute run. Tool results never fall out of the transcript, so an oversized one
    is re-paid on every later turn — the same argument this module's docstring already
    makes for strings applies to lists.

    Scalars (`count`, `ok`) are still preserved: they are metadata, they are tiny, and
    they are what makes a truncated result interpretable.
    """
    src = {"functions": [{"name": "a"}] * 50, "count": 50, "ok": True}
    out = cap_tool_result(src, cap=200)
    assert len(out["functions"]) < 50, "list must be bounded (#242)"
    assert out["count"] == 50 and out["ok"] is True, "metadata must survive"
    assert "TRUNCATED" in out["note"]


def test_note_records_which_fields_were_truncated():
    out = cap_tool_result({"decompiled": "A" * 9000, "listing": "B" * 9000}, cap=100)
    assert "decompiled" in out["note"] and "listing" in out["note"]


def test_existing_note_is_preserved():
    """cap_list_functions may already have set a note; it must not be clobbered."""
    out = cap_tool_result({"note": "showing top 15 of 200 functions by xref_count",
                           "decompiled": "A" * 9000}, cap=100)
    assert "top 15 of 200" in out["note"]
    assert "TRUNCATED" in out["note"]


def test_noop_on_unexpected_shapes():
    assert cap_tool_result(["not", "a", "dict"]) == ["not", "a", "dict"]
    assert cap_tool_result({"error": "no project"}) == {"error": "no project"}


class _FakeProc:
    returncode = 0
    stderr = ""
    stdout = json.dumps({"decompiled": "Z" * 20_000, "name": "FUN_0040b477"})


def test_run_ghidra_tool_caps_only_when_requested(monkeypatch):
    """Cloud Claude keeps full bodies; only the local backend is trimmed."""
    monkeypatch.setattr(interpret.subprocess, "run", lambda *a, **k: _FakeProc())

    full = interpret.run_ghidra_tool("/p", "prog", "decompile_function",
                                     {"name": "x"}, "ghidra")
    assert len(full["decompiled"]) == 20_000
    assert "note" not in full

    capped = interpret.run_ghidra_tool("/p", "prog", "decompile_function",
                                       {"name": "x"}, "ghidra", None, 6000)
    assert "TRUNCATED" in capped["decompiled"]
    assert len(capped["decompiled"]) < 20_000


def test_default_cap_does_not_trim_a_typical_decompiled_body():
    """Measured from the 2026-07-27 probe: decompiled bodies cluster at ~9,000 chars.

    A cap below that trims most real functions by a third to save ~12% of context —
    a bad trade. The default must target outliers, not the common case.
    """
    typical = {"decompiled": "A" * 9500}
    assert cap_tool_result(typical) == typical, (
        "default cap trims a typical ~9 KB decompiled body; it should only cut outliers")
    assert TOOL_RESULT_CHAR_CAP > 9500
