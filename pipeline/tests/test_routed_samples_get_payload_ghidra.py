# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A sample routed to another analyser still gets its CAPE payloads analysed (#646).

Every Stage 4 branch that hands a sample to a non-Ghidra analyser (.NET, Office,
PowerShell, scripts, Go, PyInstaller, Java) ended with
``report["ghidra"] = {..., "analyzed_files": []}``. For a loader that discards
the malware. formbook_5b4f596d (2026-09-27): the .NET stage is a card game plus
six lines of reflective load; CAPE extracted 24 payloads including one typed
"Formbook Payload"; Ghidra saw none of them, and the LLM, given 97k characters
of game UI, reported "Local Game Logic Execution".

run-pipeline now calls ``run_ghidra(..., include_original=False)`` after the
branch chain for any routed sample. The wrapper stays with its own analyser.
"""
import ast
import hashlib
from pathlib import Path

import pytest
from stages import ghidra
from stages.ghidra import ROUTED_FLAGS, run_ghidra

RUN_PIPELINE = (Path(__file__).resolve().parents[2]
                / "ansible/roles/pipeline/files/run-pipeline.py")
PE = b"MZ" + b"\x90" * 510
CAPE = {"id": 1264, "status": "reported"}


@pytest.fixture
def ghidra_calls(monkeypatch):
    """Record what would reach Ghidra, by loader, without running it."""
    seen = {"pe": [], "shellcode": []}

    def fake_pe(pe_path, output_dir, ghidra_cmd):
        seen["pe"].append(Path(pe_path))
        return {"analysis_success": True, "functions_count": 10,
                "program_name": Path(pe_path).name, "project_dir": str(output_dir)}

    def fake_sc(candidate, output_dir, ghidra_cmd):
        seen["shellcode"].append(candidate["sha256"])
        return {"source": candidate["source"], "analysis_success": True,
                "functions_count": 124, "program_name": candidate["sha256"],
                "project_dir": str(output_dir / candidate["sha256"][:12] / "project")}

    monkeypatch.setattr(ghidra, "run_ghidra_on_file", fake_pe)
    monkeypatch.setattr(ghidra, "run_ghidra_shellcode", fake_sc)
    monkeypatch.setattr(ghidra, "make_ghidra_verifier",
                        lambda _cmd: (lambda *_a, **_k: True))
    return seen


@pytest.fixture
def wrapper(tmp_path):
    """The routed sample itself: readable, a PE (a .NET assembly is one)."""
    p = tmp_path / "formbook.bin"
    p.write_bytes(PE)
    return p


def _no_payload_pes(monkeypatch, error=None):
    monkeypatch.setattr(ghidra, "discover_pe_files", lambda *_a, **_k: ([], error))


def test_the_wrapper_is_never_handed_to_ghidra(tmp_path, wrapper, ghidra_calls, monkeypatch):
    _no_payload_pes(monkeypatch)
    payload = {"source": "cape_payload", "sha256": hashlib.sha256(b"p").hexdigest(),
               "analyze_with_ghidra": True}
    out = run_ghidra(CAPE, tmp_path / "out", wrapper, "ghidra",
                     get_cape_signatures_fn=lambda d: [],
                     shellcode_candidates=[payload], include_original=False)
    assert ghidra_calls["pe"] == [], "the routed wrapper reached the PE loader"
    assert ghidra_calls["shellcode"] == [payload["sha256"]]
    assert out["trigger_reason"] == "cape_payloads_via_shellcode_loader", out
    assert "original_sample_source" not in out


def test_the_default_still_analyses_the_original(tmp_path, wrapper, ghidra_calls, monkeypatch):
    """The native path must not change: include_original defaults to True."""
    _no_payload_pes(monkeypatch)
    monkeypatch.setattr(ghidra, "resolve_original_sample",
                        lambda *_a, **_k: (wrapper, "cape_storage", None))
    out = run_ghidra(CAPE, tmp_path / "out", wrapper, "ghidra",
                     get_cape_signatures_fn=lambda d: [])
    assert ghidra_calls["pe"] == [wrapper]
    assert out["trigger_reason"] == "original_sample_is_pe"


def test_nothing_unpacked_is_not_an_error(tmp_path, wrapper, ghidra_calls, monkeypatch):
    """A routed sample that dropped nothing is covered by its own analyser.
    "no PE files found" would be a false claim about the wrapper."""
    _no_payload_pes(monkeypatch)
    out = run_ghidra(CAPE, tmp_path / "out", wrapper, "ghidra",
                     get_cape_signatures_fn=lambda d: [], include_original=False)
    assert "error" not in out, out
    assert out["analyzed_files"] == []
    assert ghidra_calls == {"pe": [], "shellcode": []}


def test_an_unreadable_cape_tree_still_says_so(tmp_path, wrapper, ghidra_calls, monkeypatch):
    """An empty list because we could not look must not read as 'nothing unpacked'."""
    _no_payload_pes(monkeypatch, error="EACCES on storage/analyses/1264")
    out = run_ghidra(CAPE, tmp_path / "out", wrapper, "ghidra",
                     get_cape_signatures_fn=lambda d: [], include_original=False)
    assert out.get("payload_access_error") == "EACCES on storage/analyses/1264", out


# --- run-pipeline wiring -----------------------------------------------------
# Structural, and only because main() is one 1,500-line function that needs a
# live CAPE task to reach Stage 4. The behaviour above is tested directly; these
# pin the two facts that connect it to the pipeline.

def _tree():
    return ast.parse(RUN_PIPELINE.read_text())


def test_every_routed_branch_is_in_routed_flags():
    """A new routed branch that is not in ROUTED_FLAGS silently keeps
    analyzed_files: []. Derive the set from the code, not from a list."""
    in_code = {
        k.value for node in ast.walk(_tree()) if isinstance(node, ast.Dict)
        for k, v in zip(node.keys, node.values)
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
        and k.value.endswith("_routed")
        and isinstance(v, ast.Constant) and v.value is True
    }
    assert in_code, "found no *_routed flags: the probe is broken, not the code"
    assert in_code == set(ROUTED_FLAGS), (in_code ^ set(ROUTED_FLAGS))


def test_run_pipeline_sends_routed_payloads_without_the_wrapper():
    calls = [
        n for n in ast.walk(_tree())
        if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "run_ghidra"
    ]
    kw = [{k.arg: k.value for k in c.keywords} for c in calls]
    payload_only = [k for k in kw if "include_original" in k]
    assert len(payload_only) == 1, f"{len(payload_only)} payload-only run_ghidra calls"
    val = payload_only[0]["include_original"]
    assert isinstance(val, ast.Constant) and val.value is False
    assert "shellcode_candidates" in payload_only[0], "payloads are not passed"


# --- option (c): the agent reads the payload, not the wrapper -----------------

from stages.ghidra import select_payload_target  # noqa: E402


def _ghidra(canonical: str, files: list[dict], project_dir="/r/x/project") -> dict:
    return {"dotnet_routed": True, "program_name": canonical,
            "project_dir": project_dir, "analyzed_files": files}


def _f(name, fns, source="cape_payload", ok=True):
    f = {"program_name": name, "functions_count": fns, "analysis_success": ok,
         "project_dir": f"/r/{name}/project"}
    if source is not None:
        f["source"] = source
    return f


def test_the_canonical_payload_is_chosen_not_the_first_success():
    """cobaltstrike's first successful payload had 0 functions; the canonical
    one had 1,945. List position is not a quality signal."""
    files = [_f("empty", 0), _f("real", 1945)]
    assert select_payload_target(_ghidra("real", files))["program_name"] == "real"


def test_a_dropped_pe_qualifies():
    """The PE loader sets no "source"; for a routed sample that is a dropped PE."""
    files = [_f("dropped", 300, source=None)]
    assert select_payload_target(_ghidra("dropped", files)) is not None


@pytest.mark.parametrize("canonical_file", [
    _f("c", 0),                                   # loaded, no functions
    _f("c", 50, ok=False),                        # analysis failed
    _f("c", 50, source="cape_injection"),         # a process fragment
    _f("c", 50, source="malfind_injection"),      # a process fragment
])
def test_nothing_worth_reading_keeps_the_wrapper(canonical_file):
    assert select_payload_target(_ghidra("c", [canonical_file])) is None


def test_no_verified_project_keeps_the_wrapper():
    """run_ghidra sets project_dir only after verifying the program opens (#490).
    Without it the agent's every tool call would fail."""
    assert select_payload_target(_ghidra("c", [_f("c", 50)], project_dir=None)) is None


def test_a_canonical_name_with_no_matching_file_keeps_the_wrapper():
    assert select_payload_target(_ghidra("ghost", [_f("c", 50)])) is None


def _stage45_if():
    """The If node that starts the Stage 4.5 dispatch chain."""
    for node in ast.walk(_tree()):
        if isinstance(node, ast.If) and "payload_target" in ast.unparse(node.test):
            return node
    return None


def test_the_payload_branch_comes_before_every_routed_analyser():
    """If any routed branch (dotnet, office, ...) is tested first, the wrapper
    wins and option (c) is dead code."""
    node = _stage45_if()
    assert node is not None, "no Stage 4.5 branch tests payload_target"
    # Exact, because "payload_target is None" would satisfy every other check
    # here while reading the wrapper for exactly the samples that have a payload.
    assert ast.unparse(node.test) == "payload_target is not None and INTERPRET_ENABLED"
    later = node.orelse[0]
    assert isinstance(later, ast.If) and "dotnet_data" in ast.unparse(later.test), (
        "the payload branch is not immediately ahead of the .NET branch")


def test_the_report_says_what_was_read():
    """A .NET sample's interpretation of its payload must not read as an
    interpretation of its C#; the eval keys on this."""
    body = ast.unparse(_stage45_if())
    assert "'input'" in body and "'wrapper_routed_by'" in body, body[:400]
