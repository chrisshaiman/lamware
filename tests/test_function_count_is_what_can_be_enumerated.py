# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""functions_count must count the functions that can be enumerated (#639).

`ExportAnalysis.java` reported `fm.getFunctionCount()`, which also counts
EXTERNAL functions — the imports, which live in Ghidra's EXTERNAL space and are
not in the program's own address space. Measured against the corpus:

    sample        declared   enumerable   gap   imports
    amadey             434          336    98       106
    cobaltstrike      1227          928   299       301
    emotet             170          169     1         1
    rhadamanthys       707          617    90        97

The gap IS the externals: it tracks the import count, exactly on emotet and
within a few elsewhere (the report lists imported symbols, not external Function
objects).

Two consumers both wanted the smaller number:

  * `decompileTopFunctions`, in the SAME file, iterates `getFunctions(true)` —
    so the export disagreed with itself about what it had analysed.
  * `propagate_project_dir` ranks candidate programs by `functions_count` to
    pick the canonical one (#490). An inflated count prefers a program with many
    imports over one with more analysable code.

`ExportAnalysis.py.j2` — not deployed — already used `list(fm.getFunctions(True))`,
which is independent evidence of which number was intended.

Structural assertions: Ghidra compiles these inside a container at run time, so
there is no build step to hook. Behavioural verification happens on the host
before merge (#636), and the numbers above are what it checks against.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "ansible" / "roles" / "ghidra" / "templates"
JAVA = (TPL / "ExportAnalysis.java.j2").read_text()
TOOL = (TPL / "GhidraTool.java.j2").read_text()


def test_the_export_script_exists_and_reports_a_count():
    """Guards the guard: a rename would make everything below vacuous."""
    assert "functions_count" in JAVA
    assert "getFunctions(true)" in JAVA


def test_the_count_is_not_taken_from_getFunctionCount():
    """The defect. `getFunctionCount()` may still appear — it is how the external
    total is derived — but it must not be what `functionCount` is assigned."""
    assign = [ln.strip() for ln in JAVA.splitlines()
              if "int functionCount" in ln]
    assert assign, "functionCount is no longer declared"
    assert not any("getFunctionCount()" in ln for ln in assign), assign


def test_the_count_comes_from_iterating_the_program_space():
    body = JAVA[JAVA.index("int functionCount"):][:600]
    assert "getFunctions(true)" in body, body[:200]
    assert "functionCount++" in body


def test_the_external_total_is_still_reported():
    """Externals are real and were previously folded in. Dropping them silently
    would trade one wrong number for a missing one."""
    # Anchored on the EMITTING statement. `"external_functions_count" in JAVA`
    # passed with the json.append deleted, because the variable declaration and
    # the comment still contain the word — matching prose rather than behaviour,
    # which a mutation caught here.
    emitted = [ln for ln in JAVA.splitlines()
               if "external_functions_count" in ln and "json.append" in ln]
    assert emitted, "the external total is computed but never emitted"
    assert "externalFunctionCount" in emitted[0], emitted[0]
    assert "getFunctionCount()" in JAVA, "the external total has no source"


def test_the_export_agrees_with_its_own_function_list():
    """`decompileTopFunctions` iterates getFunctions(true). The count and the work
    must be over the same set, or the report contradicts itself."""
    assert JAVA.count("getFunctions(true)") >= 2


def test_the_tool_layer_counts_the_same_way():
    """`list_functions` reports `total_count` from getFunctions(true) (#633). If
    the export used a different API the agent and the report would disagree —
    which is the state this fixes."""
    assert "getFunctions(true)" in TOOL


@pytest.mark.parametrize("sample,declared,enumerable", [
    ("amadey", 434, 336),
    ("cobaltstrike", 1227, 928),
    ("emotet", 170, 169),
    ("rhadamanthys", 707, 617),
])
def test_the_measured_gaps_are_recorded_in_the_source(sample, declared, enumerable):
    """The measurement that motivated the change, pinned so a later reader can
    check it rather than trust it. If these numbers are ever revised, the comment
    and this test move together."""
    assert str(declared) in JAVA and str(enumerable) in JAVA, sample
