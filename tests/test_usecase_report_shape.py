# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""ADR-031's use-case check: a stage that stops working must be reported."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/usecase-check/report-shape.py"
NS: dict = {"__name__": "report_shape"}
exec(compile(SCRIPT.read_text(), str(SCRIPT), "exec"), NS)  # noqa: S102


def _healthy() -> dict:
    return {
        "triage": {"yara_status": {"rules": 3}, "floss": {"strings": 10}},
        "cape": {"status": "reported", "memory_dump_requested": True},
        "pcap_analysis": {"pcap_size": 1000, "zeek": {"conn": 3}, "suricata": {"alerts": 1}},
        "volatility": {"plugins_run": ["pslist"]},
        "dotnet_analysis": {"analysis_success": True},
        "ghidra": {"analyzed_files": ["a.bin"]},
        "llm_interpretation": {"analysis": {"summary": "x"}},
        "screenshots": {"analysis_success": True},
        "visual_analysis": {"analysis": {"x": 1}},
        "executive_summary": {"executive_summary": "x"},
        "extracted_iocs": [1], "mitre_mapping": [1],
    }


@pytest.fixture
def report_dir(tmp_path):
    (tmp_path / "report.pdf").write_bytes(b"%PDF")
    for d in ("pcap_analysis", "vol_procdump", "cape_injections", "llm_audit"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "x").write_text("x")
    return tmp_path


def _stage_preds(p: dict) -> dict:
    return {k: v for k, v in p.items() if not k.startswith(("branch.", "path."))}


def test_a_healthy_report_holds_every_stage_predicate(report_dir):
    p = _stage_preds(NS["predicates"](_healthy(), str(report_dir)))
    assert all(p.values()), [k for k, v in p.items() if not v]


@pytest.mark.parametrize("break_it, lost", [
    (lambda r: r["volatility"].update(plugins_run=[]), "volatility.plugins_ran"),
    (lambda r: r["ghidra"].update(analyzed_files=[]), "ghidra.analyzed_files"),
    (lambda r: r["cape"].update(status="failed"), "cape.reported"),
    (lambda r: r.pop("llm_interpretation"), "interpret.analysis"),
    (lambda r: r["pcap_analysis"].update(pcap_size=0), "pcap.has_pcap"),
])
def test_a_stage_that_comes_back_empty_is_a_regression(report_dir, break_it, lost):
    base = NS["predicates"](_healthy(), str(report_dir))
    r = _healthy()
    break_it(r)
    assert NS["compare"](NS["predicates"](r, str(report_dir)), base) == [lost]


def test_an_artifact_that_goes_empty_is_a_regression(report_dir):
    base = NS["predicates"](_healthy(), str(report_dir))
    (report_dir / "vol_procdump" / "x").unlink()
    assert NS["compare"](NS["predicates"](_healthy(), str(report_dir)), base) == ["artifact.vol_procdump"]


def test_a_predicate_false_in_the_baseline_is_not_required(report_dir):
    r = _healthy()
    r["dotnet_analysis"]["analysis_success"] = False
    base = NS["predicates"](r, str(report_dir))
    assert NS["compare"](base, base) == []


def test_the_cli_exits_1_and_names_the_lost_stage(report_dir, tmp_path_factory):
    good = report_dir / "report.json"
    good.write_text(json.dumps(_healthy()))
    base = tmp_path_factory.mktemp("b") / "base.json"
    base.write_text(subprocess.run([sys.executable, "-I", str(SCRIPT), str(good)], capture_output=True,
                                   text=True, check=True).stdout)
    bad = _healthy()
    bad["ghidra"]["analyzed_files"] = []
    good.write_text(json.dumps(bad))
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(good), "--baseline", str(base)],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "ghidra.analyzed_files" in r.stdout


# --- branches: which tool branch the sample took, and the ride-along paths ----------

BRANCH_KEYS = {"branch.office": "office_analysis", "branch.script": "script_analysis",
               "branch.go": "go_analysis", "branch.pyinstaller": "pyinstaller_analysis",
               "branch.java": "java_analysis"}


def _routes(r: dict, report_dir) -> set[str]:
    p = NS["predicates"](r, str(report_dir))
    return {k for k, v in p.items() if v and k.startswith(("branch.", "path."))}


@pytest.mark.parametrize("pred, key", sorted(BRANCH_KEYS.items()))
def test_each_branch_is_named_by_its_own_result(report_dir, pred, key):
    r = _healthy()
    r.pop("dotnet_analysis")
    r[key] = {"analysis_success": True}
    assert _routes(r, report_dir) == {pred}
    r[key]["analysis_success"] = False          # ran but failed: not exercised
    assert _routes(r, report_dir) == set()


def test_dotnet_input_and_dotnet_payload_are_told_apart(report_dir):
    assert _routes(_healthy(), report_dir) == {"branch.dotnet"}
    r = _healthy()
    r["dotnet_analysis"]["extraction_source"] = {"path": "/x/carve.bin"}
    assert _routes(r, report_dir) == {"path.dotnet_payload"}


def test_powershell_input_and_powershell_from_behaviour_are_told_apart(report_dir):
    r = _healthy()
    r.pop("dotnet_analysis")
    r["powershell_analysis"] = {"analysis_success": True, "input_mode": "file"}
    assert _routes(r, report_dir) == {"branch.powershell_script"}
    r["powershell_analysis"]["cape_extracted"] = True
    assert _routes(r, report_dir) == {"path.powershell_from_behaviour"}


def test_a_baseline_recorded_before_the_branch_predicates_still_compares(report_dir, tmp_path):
    """The recorded use-case baseline predates these keys; new truths are fine."""
    old = {k: v for k, v in NS["predicates"](_healthy(), str(report_dir)).items()
           if not k.startswith(("branch.", "path."))}
    assert NS["compare"](NS["predicates"](_healthy(), str(report_dir)), old) == []


# --- the coverage corpus manifest ------------------------------------------------------

CORPUS = json.loads((ROOT / "scripts/usecase-check/coverage-corpus.json").read_text())["samples"]


def test_every_branch_and_path_has_a_corpus_sample(report_dir):
    """A branch added to report-shape.py without a sample to exercise it fails here."""
    keys = {k for k in NS["predicates"](_healthy(), str(report_dir)) if k.startswith(("branch.", "path."))}
    expected = {e for s in CORPUS for e in s["expect"]}
    assert keys == expected, (keys ^ expected)


def test_each_branch_is_claimed_once():
    branches = [e for s in CORPUS for e in s["expect"] if e.startswith("branch.")]
    assert len(branches) == len(set(branches)), branches


@pytest.mark.parametrize("s", CORPUS, ids=lambda s: s["id"])
def test_corpus_entries_are_complete(s):
    assert s["status"] in ("have", "wanted", "optional")
    if s["status"] == "have":
        assert len(s["sha256"]) == 64 and int(s["sha256"], 16) >= 0
    else:
        assert "sha256" not in s and s["select"]
        for c in s.get("candidates", []):
            assert c["role"] in ("pick", "backup") and len(c["sha256"]) == 64


def test_every_pick_is_in_the_intake_manifest():
    """A pick that is not in its intake manifest would never be detonated."""
    for s in CORPUS:
        picks = [c["sha256"] for c in s.get("candidates", []) if c["role"] == "pick"]
        if not picks:
            continue
        manifest = json.loads((ROOT / s["intake"]).read_text())
        assert picks[0] in {e["sha256"] for e in manifest}, s["id"]
