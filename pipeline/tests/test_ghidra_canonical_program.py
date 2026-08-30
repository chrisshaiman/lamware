# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The canonical pairing named a program the project could not open (#490).

`propagate_project_dir` ranks by function count and took the top candidate. But
the project retains one program while `analyzed_files` claims five or six
successes, so on 3 of the 10 corpus samples with any Ghidra output the winner
was absent. Ghidra answered "Requested project program file(s) not found", every
tool call in the interpret stage failed, and the report said `triggered: true`
with 63 analyzed files and no warning.

That is what invalidated the first #420 pilot: both cells scored
`tool_layer_broken`, and the arm handed correlated evidence "won" by reciting
its prompt because it was the only input either model actually had.

Two halves, and the second matters as much as the first:

  SELECT what the project can open, not what looks best on paper.
  SAY SO when the two differ, instead of returning a pairing known to fail.
"""
import json
import subprocess
from pathlib import Path

import pytest
from stages.ghidra import make_ghidra_verifier, propagate_project_dir

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = ROOT / "ansible" / "roles" / "ghidra" / "templates"
OUT = Path("/opt/pipeline/reports/task-1")


def _af(name, funcs, success=True):
    return {"analysis_success": success, "project_dir": "/output/project",
            "host_output_dir": str(OUT), "program_name": name,
            "functions_count": funcs}


# The real thing, from unclassified_25d18a2b: the 18143-function analysis is the
# one selection preferred and the one Ghidra cannot find.
ABSENT = "890a9fdf8216f97142c6f96545cc2e1026dcef80b81c947d63cf28932f0d5697"
PRESENT = "91ed576cc595105bc63f853bb46a7218a6f106cc3f9c9634b2a8e309186e1a88"


def _only(*openable):
    """A verifier where exactly these program names open and the rest are
    definitively absent — the shape a redeployed wrapper reports."""
    return lambda project, program: program in openable


# --- selection ---


def test_the_best_candidate_wins_when_it_opens():
    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    project, program = propagate_project_dir(files, OUT, verify=_only(ABSENT, PRESENT))
    assert program == ABSENT
    assert project == str(OUT / "project")


def test_selection_falls_back_when_the_best_cannot_be_opened():
    """THE bug. 18143 > 11252, but only the 11252 one is in the project."""
    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    project, program = propagate_project_dir(files, OUT, verify=_only(PRESENT))
    assert program == PRESENT, "selection still prefers the absent program"
    assert project == str(OUT / "project")


def test_no_pairing_at_all_when_nothing_opens():
    """Returning the top candidate anyway would hand the interpret stage a
    pairing known to fail, and it would spend its whole budget finding out one
    call at a time — which is exactly what the first pilot did."""
    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    assert propagate_project_dir(files, OUT, verify=_only()) == (None, None)


def test_the_rejection_is_recorded_not_silent():
    warnings: list[str] = []
    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    propagate_project_dir(files, OUT, verify=_only(PRESENT), warnings=warnings)
    joined = " ".join(warnings)
    assert ABSENT[:16] in joined, warnings
    assert "18143" in joined, warnings
    assert any("fell back" in w for w in warnings), warnings


def test_every_rejection_is_recorded_when_several_fail():
    files = [_af("aaa", 900), _af("bbb", 800), _af(PRESENT, 700)]
    warnings: list[str] = []
    _, program = propagate_project_dir(files, OUT, verify=_only(PRESENT),
                                       warnings=warnings)
    assert program == PRESENT
    assert sum("could not be opened" not in w for w in warnings) == 2, warnings


def test_failed_analyses_are_never_probed():
    """A failed analysis has no program to open. Probing it would cost a Ghidra
    launch to learn what `analysis_success: False` already said."""
    probed = []

    def verify(project, program):
        probed.append(program)
        return program == PRESENT

    files = [_af("dead", 99999, success=False), _af(PRESENT, 10)]
    _, program = propagate_project_dir(files, OUT, verify=verify)
    assert program == PRESENT
    assert probed == [PRESENT], probed


# --- back-compat: the selection stays pure for callers that cannot run Ghidra ---


def test_without_a_verifier_the_historical_choice_is_unchanged():
    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    _, program = propagate_project_dir(files, OUT)
    assert program == ABSENT


def test_without_a_verifier_nothing_is_warned_about():
    warnings: list[str] = []
    propagate_project_dir([_af(PRESENT, 1)], OUT, warnings=warnings)
    assert warnings == []


# --- the verifier ---


def test_the_probe_asks_about_that_exact_pairing(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout='{"count": 0}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert make_ghidra_verifier("/opt/ghidra/run-ghidra")("/p", "prog") is True
    argv = seen["argv"]
    assert argv[:5] == ["/opt/ghidra/run-ghidra", "--tool", "/p", "prog",
                        "list_functions"]
    # a filter nothing matches: opening the program is the part under test,
    # serialising 18k functions is not
    assert json.loads(argv[5])["filter"]


def test_a_bare_tool_result_failure_is_inconclusive(monkeypatch):
    """Without the cause attached this could be anything — a crashed container,
    a script error. It is not evidence the program is missing."""
    payload = json.dumps({"error": "GhidraTool.java did not emit TOOL_RESULT"})
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw:
                        subprocess.CompletedProcess(argv, 0, stdout=payload, stderr=""))
    assert make_ghidra_verifier("/opt/ghidra/run-ghidra")("/p", "prog") is None


@pytest.mark.parametrize("stdout,exc", [
    ("not json at all", None),
    ("", None),
    (None, subprocess.TimeoutExpired("run-ghidra", 180)),
    (None, OSError("no such binary")),
])
def test_a_probe_that_cannot_run_is_inconclusive_not_a_verdict(monkeypatch, stdout, exc):
    """None, not False. The probe failing says nothing about whether the program
    is there, and treating it as absence would discard working projects."""
    def fake_run(argv, **kw):
        if exc:
            raise exc
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert make_ghidra_verifier("/opt/ghidra/run-ghidra")("/p", "prog") is None


# --- the wrapper's error message ---


def _load_run_tool():
    """Exec run_tool alone, with a namespace standing in for the container."""
    src = (GHIDRA / "run-ghidra.py.j2").read_text(encoding="utf-8")
    start = src.index("def run_tool")
    end = src.index("def ", start + 1)
    ns: dict = {"Path": Path, "json": json, "subprocess": subprocess,
                "ANALYZE_HEADLESS": "/opt/ghidra/analyzeHeadless"}
    exec(compile(src[start:end], "run-ghidra.py.j2", "exec"), ns)  # noqa: S102
    return ns["run_tool"]


# Verbatim from the failing run, minus the surrounding 4KB of INFO lines.
ABORT_LINE = (
    "ERROR Abort due to Headless analyzer error: Requested project program "
    f"file(s) not found: {ABSENT} (HeadlessAnalyzer) java.io.IOException: "
    f"Requested project program file(s) not found: {ABSENT}"
)


def _run_tool_with(stdout, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw:
                        subprocess.CompletedProcess(argv, 1, stdout=stdout, stderr=""))
    return _load_run_tool()(Path("/p"), "prog", "list_functions", "{}")


def test_the_real_cause_travels_with_the_failure(monkeypatch):
    """It was always in ghidra_stdout, 4000 characters in. Nobody read it, and
    diagnosing one eval run cost more than surfacing it ever would."""
    out = _run_tool_with(f"INFO  noise\n{ABORT_LINE}\nINFO  more noise\n", monkeypatch)
    assert "Requested project program file(s) not found" in out["error"], out["error"]
    assert "did not emit TOOL_RESULT" in out["error"], out["error"]
    # the java exception echo is dropped; the readable half is kept
    assert "java.io.IOException" not in out["error"], out["error"]


def test_a_missing_program_is_flagged_for_the_caller(monkeypatch):
    """Not "Ghidra broke" — "this project does not hold this program", which has
    a different fix and a caller that can act on it."""
    out = _run_tool_with(f"{ABORT_LINE}\n", monkeypatch)
    assert out.get("program_not_in_project") is True


def test_an_unrelated_abort_is_not_flagged_as_a_missing_program(monkeypatch):
    out = _run_tool_with(
        "ERROR Abort due to Headless analyzer error: Import file does not exist "
        "(HeadlessAnalyzer)\n", monkeypatch)
    assert "Import file does not exist" in out["error"]
    assert "program_not_in_project" not in out


def test_silence_from_ghidra_still_reports_the_symptom(monkeypatch):
    out = _run_tool_with("INFO  nothing useful here\n", monkeypatch)
    assert out["error"] == "GhidraTool.java did not emit TOOL_RESULT"
    assert "program_not_in_project" not in out


def test_the_raw_output_is_still_kept(monkeypatch):
    """Surfacing the summary must not throw away the detail behind it."""
    out = _run_tool_with(f"INFO  x\n{ABORT_LINE}\n", monkeypatch)
    assert ABSENT in out["ghidra_stdout"]
    assert out["ghidra_returncode"] == 1


# --- tri-state: an inconclusive probe must not destroy a working project ---


def test_an_unverifiable_candidate_is_used_rather_than_discarded():
    """A busy container, a timeout, or a wrapper too old to report the
    distinction must not turn a working project into "Ghidra unavailable".
    That trades a silent failure for a louder one; it does not fix it."""
    files = [_af(ABSENT, 18143)]
    _, program = propagate_project_dir(files, OUT, verify=lambda p, n: None)
    assert program == ABSENT


def test_an_unverifiable_candidate_is_still_said_out_loud():
    warnings: list[str] = []
    propagate_project_dir([_af(ABSENT, 18143)], OUT,
                          verify=lambda p, n: None, warnings=warnings)
    assert any("could not verify" in w for w in warnings), warnings


def test_a_definitive_answer_beats_an_inconclusive_one():
    """Top candidate unverifiable, second definitively openable: prefer the one
    known to work rather than the one merely unrefuted."""
    def verify(project, program):
        return None if program == ABSENT else True

    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    _, program = propagate_project_dir(files, OUT, verify=verify)
    assert program == PRESENT


def test_absent_beats_unverifiable_only_by_being_skipped():
    """Definitively-absent is dropped; the unverifiable one is what remains."""
    def verify(project, program):
        return False if program == ABSENT else None

    files = [_af(PRESENT, 11252), _af(ABSENT, 18143)]
    _, program = propagate_project_dir(files, OUT, verify=verify)
    assert program == PRESENT


@pytest.mark.parametrize("payload,expected", [
    ({"count": 0, "functions": []}, True),
    ({"error": "x", "program_not_in_project": True}, False),
    ({"error": "GhidraTool.java did not emit TOOL_RESULT: Requested project "
               "program file(s) not found: abc"}, False),
    # an un-redeployed wrapper: the text is only in the raw stdout
    ({"error": "GhidraTool.java did not emit TOOL_RESULT",
      "ghidra_stdout": "ERROR ... Requested project program file(s) not found: abc"},
     False),
    ({"error": "Ghidra tool timeout (120s)"}, None),
    ({"error": "Invalid JSON from Ghidra tool"}, None),
])
def test_only_a_missing_program_counts_as_definitively_absent(monkeypatch, payload,
                                                              expected):
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw:
                        subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload),
                                                    stderr=""))
    assert make_ghidra_verifier("/opt/ghidra/run-ghidra")("/p", "prog") is expected
