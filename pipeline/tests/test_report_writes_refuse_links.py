# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""report.json and the LLM audit trail are never written through a planted link.

Report directories are group-writable by every lamware member and receive
container output. write_json_atomic used a predictable temp name opened with a
plain open("w"); the turn trail appended with open("a"); per-tool results and
the audit log used open("w"). Each followed a link.
"""
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.interpret import TurnTrail  # noqa: E402


def _run_pipeline():
    spec = importlib.util.spec_from_file_location(
        "run_pipeline_under_test", ROOT / "ansible" / "roles" / "pipeline" / "files"
        / "run-pipeline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_report_json_replaces_a_planted_link(tmp_path):
    rp = _run_pipeline()
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (report_dir / "report.json").symlink_to(victim)
    rp.write_json_atomic(report_dir / "report.json", {"ok": True})
    assert victim.read_text() == "untouched"
    p = report_dir / "report.json"
    assert not p.is_symlink() and json.loads(p.read_text()) == {"ok": True}


def test_the_trail_refuses_a_linked_audit_directory(tmp_path):
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (report_dir / "llm_audit").symlink_to(elsewhere)
    trail = TurnTrail(report_dir / "llm_audit" / "t.trail.jsonl", started=0.0,
                      root=report_dir)
    trail.event("run_start")
    assert list(elsewhere.iterdir()) == []
    assert trail._broken, "the trail must disable itself, not write elsewhere"


def test_the_trail_still_writes_normally(tmp_path):
    report_dir = tmp_path / "report"
    (report_dir / "llm_audit").mkdir(parents=True)
    trail = TurnTrail(report_dir / "llm_audit" / "t.trail.jsonl", started=0.0,
                      root=report_dir)
    trail.event("run_start")
    trail.event("turn")
    rows = (report_dir / "llm_audit" / "t.trail.jsonl").read_text().splitlines()
    assert [json.loads(r)["event"] for r in rows] == ["run_start", "turn"]


def test_the_temp_file_cannot_be_predicted_and_hijacked(tmp_path):
    """The old temp name was `.report.json.<pid>.tmp`, opened with open("w"): a
    link planted there was written through, then os.replace'd over report.json."""
    rp = _run_pipeline()
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (report_dir / f".report.json.{os.getpid()}.tmp").symlink_to(victim)
    rp.write_json_atomic(report_dir / "report.json", {"ok": True})
    assert victim.read_text() == "untouched"
    assert json.loads((report_dir / "report.json").read_text()) == {"ok": True}
