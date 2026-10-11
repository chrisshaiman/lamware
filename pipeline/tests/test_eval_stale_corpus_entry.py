# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A corpus entry whose program is not in its project fails before the container starts (#754).

2026-10-10, `pre-fencing-native-qwen10-v3`: 8 of 17 native cells were
tool_layer_broken. latrodectus_d22c9656 and salat_d26bc055 were hand-promoted
before `lamware_eval.promote` existed and point the agent at a program their
project does not hold, so every tool call failed with "Requested project program
file(s) not found", for a whole cell budget, per ordering.

Behavioural: `run_arm` on a corpus fixture with a real `~index.dat`, with the
container replaced by a stub that records whether it was called.
"""
import json
from pathlib import Path

import pytest
from lamware_eval import runner
from lamware_eval.arms import resolve_arm
from lamware_eval.corpus import CorpusSample
from lamware_eval.runner import StaleCorpusEntry, stale_corpus_input

RUN = "/opt/pipeline/reports/r_latrodectus_d22c9656"
WANTED = "e946c7775adf" + "0" * 52
OTHER = "49a9b25a27f6" + "0" * 52
SUB = "shellcode_0_unknown_eeeeeeeeeeee"


def _report() -> dict:
    f = {"program_name": WANTED, "sha256": WANTED, "functions_count": 40,
         "analysis_success": True, "in_project": True, "source": None,
         "project_dir": f"{RUN}/{SUB}/project", "host_output_dir": f"{RUN}/{SUB}",
         "entry_point": "entry", "imports": [], "strings_of_interest": [],
         "decompiled_functions": []}
    return {"ghidra": {"triggered": True, "project_dir": f"{RUN}/{SUB}/project",
                       "program_name": WANTED, "analyzed_files": [f]}}


def _corpus(tmp_path: Path, held: list[str] | None, make_project: bool = True) -> Path:
    d = tmp_path / "latrodectus_d22c9656"
    d.mkdir()
    (d / "report.json").write_text(json.dumps(_report()))
    if make_project:
        idata = d / SUB / "project" / "analysis.rep" / "idata"
        idata.mkdir(parents=True)
        if held is not None:
            (idata / "~index.dat").write_text(
                "VERSION=1\n/\n" + "".join(f"  {i:08x}:{n}:uuid{i}\n" for i, n in enumerate(held)))
    return d


def _run(corpus: Path, monkeypatch) -> tuple[dict | None, list]:
    called = []
    monkeypatch.setattr(runner, "run_interpret",
                        lambda init, *a, **kw: called.append(init) or {"analysis": {}, "usage": {}})
    monkeypatch.setattr(runner, "make_ghidra_verifier", lambda cmd: None)
    monkeypatch.setattr(runner, "_server_sampling", lambda: {})
    sample = CorpusSample("d22c9656" + "0" * 56, "latrodectus", str(corpus))
    return runner.run_arm(sample, resolve_arm("qwen@10"), {}, "/bin/true", "/bin/true"), called


def test_a_program_missing_from_its_project_fails_before_the_container(tmp_path, monkeypatch):
    corpus = _corpus(tmp_path, held=[OTHER])
    with pytest.raises(StaleCorpusEntry, match="not in .*Re-promote"):
        _run(corpus, monkeypatch)


def test_the_container_is_never_started_for_a_stale_entry(tmp_path, monkeypatch):
    corpus = _corpus(tmp_path, held=[OTHER])
    called = []
    monkeypatch.setattr(runner, "run_interpret", lambda *a, **kw: called.append(1))
    monkeypatch.setattr(runner, "make_ghidra_verifier", lambda cmd: None)
    monkeypatch.setattr(runner, "_server_sampling", lambda: {})
    sample = CorpusSample("d22c9656" + "0" * 56, "latrodectus", str(corpus))
    with pytest.raises(StaleCorpusEntry):
        runner.run_arm(sample, resolve_arm("qwen@10"), {}, "/bin/true", "/bin/true")
    assert called == []


def test_a_program_its_project_holds_runs(tmp_path, monkeypatch):
    corpus = _corpus(tmp_path, held=[OTHER, WANTED])
    _, called = _run(corpus, monkeypatch)
    assert len(called) == 1 and called[0]["program_name"] == WANTED


def test_an_unreadable_index_is_not_evidence(tmp_path, monkeypatch):
    """The legacy corpus layouts have no readable index; they must keep running."""
    corpus = _corpus(tmp_path, held=None)
    _, called = _run(corpus, monkeypatch)
    assert len(called) == 1


def test_a_project_directory_that_does_not_exist_is_stale(tmp_path):
    assert "does not exist" in stale_corpus_input(
        {"project_dir": str(tmp_path / "gone" / "project"), "program_name": WANTED})


def test_inputs_without_a_project_are_not_checked():
    """A single-shot .NET payload names no Ghidra project."""
    assert stale_corpus_input({"decompiled_source": "class A {}"}) is None
