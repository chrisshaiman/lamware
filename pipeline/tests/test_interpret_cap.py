# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for cap_list_functions — the tool-output cap that keeps small local
models from derailing on the full function list."""
import json

from stages import interpret
from stages.interpret import cap_list_functions


def _funcs(n):
    return {"count": n, "functions": [{"name": f"FUN_{i}", "address": hex(i),
            "xref_count": i} for i in range(n)]}


def test_caps_to_top_n_by_xref():
    out = cap_list_functions(_funcs(200), cap=15)
    assert out["count"] == 15
    assert len(out["functions"]) == 15
    # highest xref_count (199) kept, lowest (0) dropped; sorted desc
    assert out["functions"][0]["xref_count"] == 199
    assert all(f["xref_count"] >= out["functions"][-1]["xref_count"] for f in out["functions"])
    assert "top 15 of 200" in out["note"]


def test_noop_when_within_cap():
    small = _funcs(10)
    assert cap_list_functions(small, cap=15) == small
    assert "note" not in cap_list_functions(small, cap=15)


def test_noop_on_unexpected_shapes():
    assert cap_list_functions({"error": "no project"}) == {"error": "no project"}
    assert cap_list_functions(["not", "a", "dict"]) == ["not", "a", "dict"]


class _FakeProc:
    returncode = 0
    stderr = ""
    stdout = json.dumps({"count": 200,
                         "functions": [{"name": f"F{i}", "xref_count": i} for i in range(200)]})


def test_run_ghidra_tool_caps_only_when_requested(monkeypatch):
    """list_functions is capped ONLY when a cap is passed (local backend);
    the default (cloud Claude) leaves the full 200-function list intact."""
    monkeypatch.setattr(interpret.subprocess, "run", lambda *a, **k: _FakeProc())
    # No cap (production/cloud) -> full list preserved.
    full = interpret.run_ghidra_tool("/p", "prog", "list_functions", {}, "ghidra")
    assert full["count"] == 200
    assert "note" not in full
    # Cap set (local backend) -> trimmed to top-N.
    capped = interpret.run_ghidra_tool("/p", "prog", "list_functions", {}, "ghidra", 15)
    assert capped["count"] == 15
    assert "top 15 of 200" in capped["note"]
