# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""On the native path the RE agent reads the canonical program, not successful[0] (#649).

Stage 4.5 handed the agent the first successful analysed file by list position.
run_ghidra ranks and verifies a canonical program (top-level project_dir /
program_name), and the eval has always passed report["ghidra"] itself, so
production and the eval read different programs (#667's survey). #649 put the
submitted sample first in the list, which would have made position decide the
agent's program; the owner chose canonical instead (2026-10-02).
"""
import ast
from pathlib import Path

from stages.ghidra import native_input_record, select_native_target

RUN_PIPELINE = (Path(__file__).resolve().parents[2]
                / "ansible/roles/pipeline/files/run-pipeline.py")


def _f(name, fns, source=None, ok=True, in_project=None):
    f = {"program_name": name, "functions_count": fns, "analysis_success": ok,
         "project_dir": f"/r/{name}/project"}
    if source is not None:
        f["source"] = source
    if in_project is not None:
        f["in_project"] = in_project
    return f


def _ghidra(canonical, files, **extra):
    g = {"program_name": canonical, "project_dir": f"/r/{canonical}/project",
         "analyzed_files": files}
    g.update(extra)
    return g


def test_the_canonical_program_is_read_not_the_first_success():
    """cobaltstrike: the first success had 0 functions, the canonical 1,945."""
    files = [_f("empty", 0, source="cape_payload"), _f("real", 1945)]
    target, why = select_native_target(_ghidra("real", files))
    assert target["program_name"] == "real"
    assert why == "canonical"


def test_the_original_first_in_the_list_does_not_win_by_position():
    """#649's ordering must not choose the agent's program."""
    files = [_f("orig", 120), _f("dropped", 928)]
    g = _ghidra("dropped", files, original_sample_included=True,
                trigger_reason="dropped_pe_with_signatures")
    target, why = select_native_target(g)
    assert target["program_name"] == "dropped" and why == "canonical"
    rec = native_input_record(g, target, why)
    assert rec["source"] == "dropped_pe"


def test_a_canonical_original_is_recorded_as_the_original():
    files = [_f("orig", 2000), _f("dropped", 928)]
    g = _ghidra("orig", files, original_sample_included=True,
                trigger_reason="dropped_pe_with_signatures")
    target, why = select_native_target(g)
    rec = native_input_record(g, target, why)
    assert rec == {"kind": "canonical", "program_name": "orig", "source": "original_sample",
                   "functions_count": 2000, "cape_type": None,
                   "chosen_because": "canonical"}


def test_no_canonical_match_falls_back_and_says_so():
    """A report with no verified pair (every candidate rejected, #490)."""
    files = [_f("a", 10), _f("b", 20)]
    g = {"analyzed_files": files}
    target, why = select_native_target(g)
    assert target["program_name"] == "a"
    assert why == "first_success_fallback"
    assert native_input_record(g, target, why)["kind"] == "first_success_fallback"


def test_a_canonical_name_not_in_the_project_is_not_read():
    files = [_f("a", 10), _f("real", 1945, in_project=False)]
    target, why = select_native_target(_ghidra("real", files))
    assert why == "first_success_fallback" and target["program_name"] == "a"


def test_nothing_successful_returns_none():
    assert select_native_target({"analyzed_files": [_f("a", 0, ok=False)]}) == (None, None)


# Structural, and only because main() is one long function that needs a live
# CAPE task to reach Stage 4.5: pin that the native branch uses the selector
# and records its input. The selection itself is tested behaviourally above.
def _native_branch() -> ast.If:
    tree = ast.parse(RUN_PIPELINE.read_text())
    for node in ast.walk(tree):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Name)
                and node.test.id == "successful"):
            return node
    raise AssertionError("no `elif successful:` branch: the probe is broken, not the code")


def test_the_native_branch_reads_the_selected_target():
    branch = _native_branch()
    calls = [n for s in branch.body for n in ast.walk(s) if isinstance(n, ast.Call)]
    interp = [c for c in calls if getattr(c.func, "id", None) == "_interpret_ghidra_program"]
    assert len(interp) == 1
    [arg] = interp[0].args
    assert isinstance(arg, ast.Name) and arg.id == "native_target", ast.dump(arg)
    assert any(getattr(c.func, "id", None) == "select_native_target" for c in calls)


def test_the_native_branch_records_what_was_read():
    branch = _native_branch()
    stores = [t for s in branch.body if isinstance(s, ast.Assign) for t in s.targets
              if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
              and t.slice.value == "input"]
    assert stores, "llm_interpretation['input'] is not written on the native path"
