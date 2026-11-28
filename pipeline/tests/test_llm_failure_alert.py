# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A failed LLM stage is alerted, not only logged (ADR-038, amended 2026-11-28).

Without the silent cloud fallback a failing local model fails; this is how that gets
seen. run-pipeline is loaded as a module (as test_llm_profiles does), with the ntfy
queue script replaced by a fake that records its arguments.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUN_PIPELINE = ROOT / "ansible/roles/pipeline/files/run-pipeline.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "config.json"


@pytest.fixture
def rp(tmp_path, monkeypatch):
    calls = tmp_path / "enqueued"
    fake = tmp_path / "ntfy_enqueue.py"
    fake.write_text(f"import json, sys\nopen({str(calls)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n")
    data = json.loads(FIXTURE.read_text())
    data["ntfy_enqueue"] = str(fake)
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(data))
    monkeypatch.setenv("LAMWARE_PIPELINE_CONFIG", str(cfg))
    sys.path.insert(0, str(RUN_PIPELINE.parent))
    spec = importlib.util.spec_from_file_location("run_pipeline_alert_test", RUN_PIPELINE)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(RUN_PIPELINE.parent))
    mod._calls = calls
    return mod


SECRETISH = "C2 at evil.example from sample invoice.exe"


def test_every_kind_of_llm_failure_is_found(rp):
    report = {
        "llm_interpretation": {"enabled": True, "analysis": {"error": SECRETISH}},   # #821's shape
        "evasion_analysis": {"enabled": False, "reason": "not_triggered"},
        "visual_analysis": {"error": "timeout"},
        "executive_summary": {"error": "litellm 500: local model unavailable"},
        "plain_english_error": "no reply",
    }
    assert rp.llm_failures(report) == ["llm_interpretation", "visual_analysis",
                                       "executive_summary", "plain_english"]


def test_a_clean_run_has_no_failures_and_queues_nothing(rp):
    report = {"llm_interpretation": {"analysis": {"summary": "ok"}}, "executive_summary": {"executive_summary": "ok"}}
    assert rp.llm_failures(report) == []
    assert rp.alert_llm_failures(report, "1234", []) is False
    assert not rp._calls.exists()


def test_the_alert_names_stages_profile_and_models_and_nothing_sample_derived(rp):
    report = {"executive_summary": {"error": SECRETISH}, "plain_english_error": SECRETISH}
    assert rp.alert_llm_failures(report, "1234", rp.llm_failures(report)) is True
    (args,) = [json.loads(line) for line in rp._calls.read_text().splitlines()]
    title, message = args[0], args[1]
    assert title == "lamware: LLM stage failed" and args[2:] == ["--priority", "high", "--tags", "warning"]
    assert "Report 1234" in message and "executive_summary, plain_english" in message
    assert "profile local" in message
    assert "evil.example" not in message and "invoice" not in message and "C2" not in message


def test_a_queue_that_cannot_be_reached_never_fails_the_run(rp, monkeypatch):
    monkeypatch.setattr(rp._PIPELINE_CONFIG, "ntfy_enqueue", "/nonexistent/ntfy_enqueue.py")
    assert rp.alert_llm_failures({"executive_summary": {"error": "x"}}, "1", ["executive_summary"]) is False


def test_run_pipeline_records_and_alerts_before_writing_the_report():
    """Structural, because no test can run a detonation: the check sits before
    write_report in run_pipeline, so the report file carries llm_failures."""
    import ast
    fn = next(n for n in ast.walk(ast.parse(RUN_PIPELINE.read_text()))
              if isinstance(n, ast.FunctionDef) and n.name == "run_pipeline")
    calls = {getattr(n.func, "id", ""): n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call)}
    assert calls["llm_failures"] < calls["write_report"] and "alert_llm_failures" in calls
