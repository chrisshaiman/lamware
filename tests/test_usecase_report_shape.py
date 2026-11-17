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


def test_a_healthy_report_holds_every_predicate(report_dir):
    p = NS["predicates"](_healthy(), str(report_dir))
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
