# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Which Ghidra project the interpret stage is pointed at (#390).

Measured on latrodectus (Cape task 1018), and the reason this matters:

  - Cape's extracted payloads already reached Ghidra as shellcode candidates
    (`source: cape_payload`) at 124/135/127 functions.
  - #377 sent the same files through the PE loader as well, which produced
    15 and 1 functions — they are memory images, not on-disk files.
  - The PE results are appended first, and propagate_project_dir took the
    FIRST success, so the worse copy became canonical.
  - Worse still, it rewrote every winner's project_dir to `output_dir/project`
    regardless of loader. The shellcode loader writes to a per-candidate
    subdirectory, so that path held a different program — on latrodectus, an
    empty project. All 5 of the interpret stage's Ghidra tool calls failed
    with "GhidraTool.java did not emit TOOL_RESULT".

A report that says `analysis_success: True, functions=124` while the model
cannot open the project is the exact failure class this codebase keeps hitting.
"""
from pathlib import Path

from stages.ghidra import _drop_already_queued, propagate_project_dir

OUT = Path("/reports/sample")


def pe_result(name, functions, ok=True, imports=0):
    """What run_ghidra_on_file returns: project lives in output_dir itself."""
    return {"program_name": name, "functions_count": functions,
            "analysis_success": ok, "project_dir": "/output/project",
            "imports": list(range(imports)), "host_output_dir": str(OUT)}


def shellcode_result(name, functions, ok=True, pid=0, addr="N/A"):
    """What run_ghidra_shellcode returns: its own per-candidate directory."""
    sub = OUT / f"shellcode_{pid}_{str(addr).replace('0x', '')}"
    return {"program_name": name, "functions_count": functions,
            "analysis_success": ok, "project_dir": "/output/project",
            "source": "cape_payload", "host_output_dir": str(sub)}


# ---------------------------------------------------------------------------
# Selection by quality, not list position
# ---------------------------------------------------------------------------


def test_the_best_analysis_wins_not_the_first():
    """The latrodectus shape: a 15-function PE copy ahead of a 124-function one."""
    files = [
        pe_result("49a9b25a", 15, imports=9),
        pe_result("9f3ed585", 1),
        shellcode_result("9f3ed585", 124),
        shellcode_result("b688d1a5", 135),
    ]

    project, program = propagate_project_dir(files, OUT)

    assert program == "b688d1a5", f"picked {program!r} — list position decided again"
    assert project.endswith("/project")


def test_the_canonical_project_is_the_winners_own_directory():
    """A shellcode analysis does not live in output_dir/project."""
    files = [pe_result("orig", 0, ok=False), shellcode_result("payload", 124, pid=7)]

    project, program = propagate_project_dir(files, OUT)

    assert program == "payload"
    assert project == str(OUT / "shellcode_7_N/A" / "project"), project
    assert project != str(OUT / "project"), (
        "pointed the interpret stage at the PE loader's project, which holds a "
        "different program — or none, which is what happened on latrodectus"
    )


def test_a_pe_analysis_still_resolves_to_output_dir():
    """Positive control: the PE loader's project really is output_dir/project."""
    files = [pe_result("sample", 42)]

    project, _ = propagate_project_dir(files, OUT)

    assert project == str(OUT / "project")


def test_failed_analyses_are_never_canonical():
    files = [pe_result("broken", 999, ok=False), shellcode_result("real", 5)]

    _, program = propagate_project_dir(files, OUT)

    assert program == "real"


def test_no_successful_analysis_returns_nothing():
    files = [pe_result("a", 0, ok=False), shellcode_result("b", 0, ok=False)]

    assert propagate_project_dir(files, OUT) == (None, None)


def test_every_successful_entry_loses_the_container_path():
    """A consumer picking a non-canonical entry must not get /output/project.

    Failed records keep theirs — nothing reads them, and leaving them untouched
    is an existing contract (test_ghidra.py).
    """
    files = [pe_result("a", 10), shellcode_result("b", 99, pid=3),
             pe_result("dead", 0, ok=False)]

    propagate_project_dir(files, OUT)

    live = [af for af in files if af["analysis_success"]]
    assert all(af["project_dir"] != "/output/project" for af in live), live
    assert files[2]["project_dir"] == "/output/project", "failed record was rewritten"


def test_results_without_host_output_dir_still_resolve():
    """Reports predating #390 have no host_output_dir; they came from the PE loader."""
    legacy = {"program_name": "old", "functions_count": 7,
              "analysis_success": True, "project_dir": "/output/project"}

    project, program = propagate_project_dir([legacy], OUT)

    assert program == "old"
    assert project == str(OUT / "project")


# ---------------------------------------------------------------------------
# Not analysing the same payload twice
# ---------------------------------------------------------------------------


def test_payloads_queued_for_the_shellcode_loader_are_dropped(tmp_path):
    a, b = tmp_path / "a.bin", tmp_path / "b.bin"
    for p in (a, b):
        p.write_bytes(b"MZ" + b"\x00" * 2048)

    kept, skipped = _drop_already_queued(
        [a, b], [{"path": a, "analyze_with_ghidra": True}])

    assert kept == [b]
    assert skipped == ["a.bin"]


def test_a_candidate_too_small_for_ghidra_keeps_its_pe_copy(tmp_path):
    """analyze_with_ghidra: False means artifact extraction only.

    Dropping its PE copy would lose the file from the analysis entirely.
    """
    a = tmp_path / "a.bin"
    a.write_bytes(b"MZ" + b"\x00" * 2048)

    kept, skipped = _drop_already_queued(
        [a], [{"path": a, "analyze_with_ghidra": False}])

    assert kept == [a]
    assert skipped == []


def test_no_candidates_changes_nothing(tmp_path):
    a = tmp_path / "a.bin"
    a.write_bytes(b"MZ" + b"\x00" * 2048)

    assert _drop_already_queued([a], None) == ([a], [])
    assert _drop_already_queued([a], []) == ([a], [])


def test_unrelated_candidates_do_not_drop_anything(tmp_path):
    """Positive control: dedupe must match on path, not drop indiscriminately."""
    a, other = tmp_path / "a.bin", tmp_path / "other.bin"
    for p in (a, other):
        p.write_bytes(b"MZ" + b"\x00" * 2048)

    kept, skipped = _drop_already_queued(
        [a], [{"path": other, "analyze_with_ghidra": True}])

    assert kept == [a]
    assert skipped == []
