# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A replay must never destroy the run it replays (#405).

``run-pipeline --replay`` used to load ``reports/<task>/report.json``, re-run
stages that can produce LESS than the original (correlate -> ``[]``, summary ->
``{"error": ...}``), and write the result back over the same file with
``open("w")``, then re-render ``report.pdf`` in place. The pre-replay evidence
was unrecoverable.

These tests call the real ``run_replay`` / ``write_report`` against a temp
reports directory. Only the stage functions, the DB and the PDF subprocess are
stubbed; every file operation is real.
"""
import hashlib
import importlib.util
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

RUN_PIPELINE = (Path(__file__).resolve().parents[2]
                / "ansible/roles/pipeline/files/run-pipeline.py")

TASK = "t405_replay"
ORIGINAL = {
    "task_id": TASK,
    "completed_at": "2026-09-01T00:00:00+00:00",
    "family": "agenttesla",
    "severity": "critical",
    "cross_correlations": [
        {"severity": "critical", "title": "cmdline spoofing", "sources": ["cape", "volatility"]},
    ],
    "extracted_iocs": [{"type": "domain", "value": "evil.example"}],
    "executive_summary": {"executive_summary": "A good summary.", "key_findings": ["x"]},
}
ORIGINAL_PDF = b"%PDF-1.7 original render\n"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def rp():
    spec = importlib.util.spec_from_file_location("run_pipeline_405", RUN_PIPELINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def replay_env(rp, tmp_path, monkeypatch):
    """A task directory holding an original report.json + report.pdf, and a
    replay whose every stage degrades: correlate and iocs return nothing, the
    summary LLM call fails."""
    reports = tmp_path / "reports"
    task_dir = reports / TASK
    task_dir.mkdir(parents=True)
    original = task_dir / "report.json"
    original.write_text(json.dumps(ORIGINAL, indent=2))
    (task_dir / "report.pdf").write_bytes(ORIGINAL_PDF)

    monkeypatch.setattr(rp, "REPORTS_DIR", reports)
    monkeypatch.setattr(rp, "add_file_logging", lambda _d: None)
    monkeypatch.setattr(rp, "cross_correlate", lambda _r: [])
    monkeypatch.setattr(rp, "determine_family", lambda _r: "unknown")
    monkeypatch.setattr(rp, "calculate_severity", lambda _r: "low")
    monkeypatch.setattr(rp, "build_mitre_mapping", lambda _r: [])
    monkeypatch.setattr(rp, "extract_iocs", lambda _r: [])
    monkeypatch.setattr(rp, "INTERPRET_ENABLED", True)
    monkeypatch.setattr(rp, "run_summarize", lambda *_a, **_k: {"error": "LLM unreachable"})

    calls = {"ingest": [], "mark_pdf": [], "pdf_cmd": []}

    def fake_ingest(report, *args, **kwargs):
        calls["ingest"].append((args, kwargs))
        return 999

    def fake_run(cmd, **_kwargs):
        calls["pdf_cmd"].append(cmd)
        Path(cmd[2]).write_bytes(b"%PDF-1.7 replay render\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(rp, "ingest_to_db", fake_ingest)
    monkeypatch.setattr(rp, "mark_pdf_generated", lambda aid: calls["mark_pdf"].append(aid))
    monkeypatch.setattr(rp.subprocess, "run", fake_run)

    # Two replays in the same second must still get distinct files, so pin
    # the clock to two instants that differ only in microseconds.
    instants = iter([datetime(2026, 10, 1, 12, 0, 0, 1, tzinfo=UTC),
                     datetime(2026, 10, 1, 12, 0, 0, 2, tzinfo=UTC)])

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return next(instants)

    monkeypatch.setattr(rp, "datetime", FixedClock)
    return {"dir": task_dir, "original": original, "calls": calls}


def _replay_files(task_dir: Path, suffix: str) -> list[Path]:
    return sorted(task_dir.glob(f"report.replay-*{suffix}"))


def test_degraded_replay_leaves_original_report_bytes_intact(rp, replay_env):
    """The issue's acceptance case: correlate yields [] and the original
    cross_correlations must survive — byte for byte, not just the key."""
    original = replay_env["original"]
    before = _sha(original)

    rp.run_replay(original)

    assert _sha(original) == before
    assert json.loads(original.read_text())["cross_correlations"] == ORIGINAL["cross_correlations"]
    assert json.loads(original.read_text())["executive_summary"]["executive_summary"] == "A good summary."


def test_replay_result_is_written_beside_original_with_provenance(rp, replay_env):
    original = replay_env["original"]
    before = _sha(original)

    rp.run_replay(original)

    [replay] = _replay_files(replay_env["dir"], ".json")
    body = json.loads(replay.read_text())
    # The degraded output is recorded — just not over the evidence.
    assert body["cross_correlations"] == []
    assert body["executive_summary"] == {"error": "LLM unreachable"}
    assert body["replay_of"] == {"path": str(original), "sha256": before}
    assert body["replayed_at"] == "2026-10-01T12:00:00.000001+00:00"
    assert replay.name == "report.replay-20261001T120000000001Z.json"


def test_replay_does_not_overwrite_original_pdf(rp, replay_env):
    rp.run_replay(replay_env["original"])

    assert (replay_env["dir"] / "report.pdf").read_bytes() == ORIGINAL_PDF
    [cmd] = replay_env["calls"]["pdf_cmd"]
    [replay_json] = _replay_files(replay_env["dir"], ".json")
    [replay_pdf] = _replay_files(replay_env["dir"], ".pdf")
    assert cmd[1:] == [str(replay_json), str(replay_pdf)]


def test_replay_db_ingest_inserts_new_row_and_claims_no_pdf(rp, replay_env):
    """Passing existing_analysis_id would UPDATE the original row in place.
    pdf_generated is not set because the API serves <task>/report.pdf, which
    is the original's PDF, for every row with this task_id."""
    rp.run_replay(replay_env["original"])

    [(args, kwargs)] = replay_env["calls"]["ingest"]
    assert args == () and "existing_analysis_id" not in kwargs
    assert replay_env["calls"]["mark_pdf"] == []


def test_two_replays_in_one_second_do_not_collide(rp, replay_env):
    original = replay_env["original"]
    before = _sha(original)

    rp.run_replay(original)
    rp.run_replay(original)

    assert len(_replay_files(replay_env["dir"], ".json")) == 2
    assert len(_replay_files(replay_env["dir"], ".pdf")) == 2
    assert _sha(original) == before


class _Unprintable:
    """str() raises, so json.dump (default=str) dies after it has already
    written the earlier keys — a real crash part-way through the write."""

    def __str__(self):
        raise RuntimeError("crash mid-write")


@pytest.mark.parametrize("name", ["report.json", "report.replay-x.json"])
def test_crash_mid_write_leaves_previous_file_readable(rp, tmp_path, name):
    task_dir = tmp_path / TASK
    task_dir.mkdir()
    target = task_dir / name
    target.write_text(json.dumps(ORIGINAL))
    before = _sha(target)

    doomed = {"task_id": TASK, "padding": "y" * 100_000, "zz_last": _Unprintable()}
    with pytest.raises(RuntimeError, match="crash mid-write"):
        rp.write_report(TASK, doomed, tmp_path, name=name)

    assert _sha(target) == before
    assert json.loads(target.read_text()) == ORIGINAL
    # The partial temp file is cleaned up rather than left beside the report.
    assert sorted(p.name for p in task_dir.iterdir()) == [name]


def test_live_write_report_still_targets_canonical_path(rp, tmp_path):
    """The live pipeline's call (no name) must keep writing report.json —
    the API, the feeder and the PDF route all read that path."""
    path = rp.write_report(TASK, {"task_id": TASK}, tmp_path)
    assert path == tmp_path / TASK / "report.json"
    assert json.loads(path.read_text()) == {"task_id": TASK}
