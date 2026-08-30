# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The live eval and its re-score disagreed on ghidra_warnings (#496).

`runner.py` read `ghidra.analysis_warnings` directly; `rebuild.py` fell back to
deriving warnings from the per-file records when that list was empty. Reports
written before #367 carry warnings only per file, and the eval NEVER analyses a
sample — it runs against persisted corpus reports, which are precisely those
older ones. So the fallback was the normal case, and only one path had it.

Measured on the #420 pilot, same cells, same `result.json`: live reported 0,
`lamware_eval.rebuild` reported 2. `unclassified_42b9c406` has two analysed
files that recovered zero functions each — the #367 state, an analysis that read
nothing presented as clean, which is the exact thing
`cells_with_ghidra_warnings` exists to surface.

`cell_error` in this same module was already shared because the two paths had
diverged once before (#380). This is the same defect one field over.
"""
import pytest
from lamware_eval.metrics import ghidra_warnings_for

# Shaped like the real corpus reports: no top-level list, per-file records that
# a detector added later would have flagged.
LEGACY = {
    "analysis_warnings": [],
    "analyzed_files": [
        {"analysis_success": True, "program_name": "a" * 64, "functions_count": 0},
        {"analysis_success": True, "program_name": "b" * 64, "functions_count": 0},
    ],
}


def test_the_legacy_shape_yields_warnings_rather_than_silence():
    """THE bug: the live path saw [] here and reported a clean analysis."""
    out = ghidra_warnings_for(LEGACY)
    assert len(out) == 2, out
    assert all("function" in w for w in out), out


def test_a_stored_list_is_used_as_is():
    """A report from a pipeline that ran the detector must not be re-derived —
    the stored warnings are the analyser's own output and say more."""
    gr = {"analysis_warnings": ["the analyser said this"],
          "analyzed_files": [{"analysis_success": True, "functions_count": 0}]}
    assert ghidra_warnings_for(gr) == ["the analyser said this"]


def test_derived_warnings_stay_marked_as_derived():
    """A warning the detector never emitted is a different claim from one it
    did. Collapsing the two would be its own small lie."""
    out = ghidra_warnings_for(LEGACY)
    assert all("derived" in w.lower() for w in out), out


@pytest.mark.parametrize("gr", [
    {},
    {"analyzed_files": []},
    {"analysis_warnings": [], "analyzed_files": [
        {"analysis_success": True, "functions_count": 900}]},
    {"analysis_warnings": [], "analyzed_files": [
        {"analysis_success": False, "functions_count": 0}]},
])
def test_a_healthy_or_empty_report_warns_about_nothing(gr):
    """Positive control: the helper is not unconditionally non-empty. A failed
    analysis in particular has nothing to derive — `analysis_success: False`
    already says it."""
    assert ghidra_warnings_for(gr) == []


def test_both_paths_call_the_same_resolver():
    """Parsed, not grepped: this file and both modules discuss the two paths at
    length, so a text search would find the names whether or not the calls
    survive. Asserting each path in isolation is what let them drift for the
    length of a whole sweep."""
    import ast
    from pathlib import Path

    files = (Path(__file__).resolve().parents[2]
             / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval")
    for module in ("runner.py", "rebuild.py"):
        tree = ast.parse((files / module).read_text(encoding="utf-8"))
        called = {n.func.id for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "ghidra_warnings_for" in called, f"{module} resolves warnings its own way"
        assert "_ghidra_warnings" not in called, f"{module} kept a private copy"


def test_the_resolver_is_actually_importable_where_it_is_called():
    """The AST check above passes against a module that CALLS the helper without
    importing it — which is exactly what the first version of this fix did, and
    only ruff caught it. Import both modules for real."""
    import importlib
    for module in ("lamware_eval.runner", "lamware_eval.rebuild"):
        m = importlib.import_module(module)
        assert callable(getattr(m, "ghidra_warnings_for", None)), module
