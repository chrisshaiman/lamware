"""run_yara must say why it found nothing (#736).

From 2026-05-09 to 2026-10-08 the triage container could not read /rules, and
run_yara returned [] — the same answer as "this sample matched no rule". Every
report said "0 YARA matches". These tests execute the real run-triage.py
(the template holds no Jinja) with stub third-party modules, and assert the
status it returns for each way of getting no matches.

What this cannot see: real YARA compiling real rules. That is asserted on the
host by the deploy's smoke test (`triage_yara_min_compiled`).
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ansible/roles/triage/templates/run-triage.py.j2"


class _YaraError(Exception):
    pass


class _Rules:
    def __init__(self, path: str):
        self.path = path

    def match(self, sample: str):
        text = Path(self.path).read_text()
        if "MATCHES" in text:
            yield types.SimpleNamespace(rule=Path(self.path).stem, tags=[], meta={})


def _compile(filepath: str):
    if "BROKEN" in Path(filepath).read_text():
        raise _YaraError("syntax error")
    return _Rules(filepath)


@pytest.fixture()
def triage(monkeypatch):
    stubs = {
        "yara": types.SimpleNamespace(compile=_compile, Error=_YaraError),
        "magic": types.ModuleType("magic"),
        "pefile": types.ModuleType("pefile"),
        "ppdeep": types.ModuleType("ppdeep"),
    }
    for name, mod in stubs.items():
        monkeypatch.setitem(sys.modules, name, mod)
    ns: dict = {"__name__": "run_triage_under_test"}
    exec(compile(SCRIPT.read_text(), str(SCRIPT), "exec"), ns)
    return ns


@pytest.fixture()
def sample(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ")
    return p


def _rules(root: Path, **files: str) -> Path:
    d = root / "rules"
    for rel, body in files.items():
        f = d / rel.replace("__", "/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body)
    return d


def test_rules_that_compile_and_match_are_counted(triage, sample, tmp_path):
    d = _rules(tmp_path, a__one_yar="", b__two_yar="MATCHES")
    for f in list(d.rglob("*_yar")):
        f.rename(f.with_name(f.name.replace("_yar", ".yar")))
    matches, status = triage["run_yara"](sample, str(d))
    assert [m["rule"] for m in matches] == ["two"]
    assert status == {"rules_dir": str(d), "rule_files": 2, "compiled": 2,
                      "compile_errors": 0, "error": None}


def test_a_missing_rules_dir_is_an_error_not_an_empty_result(triage, sample, tmp_path):
    matches, status = triage["run_yara"](sample, str(tmp_path / "nope"))
    assert matches == []
    assert status["error"] and "not found" in status["error"]
    assert status["compiled"] == 0


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads through mode 000")
def test_an_unreadable_rules_dir_is_an_error_not_an_empty_result(triage, sample, tmp_path):
    """The #736 case: the dir exists, and listing it raises EACCES."""
    d = _rules(tmp_path, x="")
    (d / "x").rename(d / "x.yar")
    d.chmod(0o000)
    try:
        matches, status = triage["run_yara"](sample, str(d))
    finally:
        d.chmod(0o755)
    assert matches == []
    assert status["compiled"] == 0
    assert status["error"] and "unreadable" in status["error"], status


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads through mode 000")
def test_one_unreadable_subdir_is_reported_while_the_rest_still_run(triage, sample, tmp_path):
    d = _rules(tmp_path)
    (d / "ok").mkdir(parents=True)
    (d / "ok" / "r.yar").write_text("MATCHES")
    (d / "locked").mkdir()
    (d / "locked" / "s.yar").write_text("")
    (d / "locked").chmod(0o000)
    try:
        matches, status = triage["run_yara"](sample, str(d))
    finally:
        (d / "locked").chmod(0o755)
    assert [m["rule"] for m in matches] == ["r"]
    assert status["compiled"] == 1
    assert status["error"] and "unreadable" in status["error"], status


def test_compile_failures_are_counted_and_all_failing_is_an_error(triage, sample, tmp_path):
    d = _rules(tmp_path)
    d.mkdir(parents=True, exist_ok=True)
    (d / "bad1.yar").write_text("BROKEN")
    (d / "bad2.yara").write_text("BROKEN")
    matches, status = triage["run_yara"](sample, str(d))
    assert matches == []
    assert status["rule_files"] == 2
    assert status["compile_errors"] == 2
    assert status["compiled"] == 0
    assert status["error"] and "no rule compiled" in status["error"]


def test_some_compile_failures_alone_are_not_an_error(triage, sample, tmp_path):
    """58 of 904 community rules need modules this build lacks. That is normal
    and must not read as an outage."""
    d = _rules(tmp_path)
    d.mkdir(parents=True, exist_ok=True)
    (d / "good.yar").write_text("")
    (d / "bad.yar").write_text("BROKEN")
    _, status = triage["run_yara"](sample, str(d))
    assert status["compiled"] == 1 and status["compile_errors"] == 1
    assert status["error"] is None


def test_the_status_reaches_the_triage_report(triage):
    """The report is what the pipeline and the deploy smoke test read."""
    src = SCRIPT.read_text()
    assert '"yara_status": yara_status' in src
    assert "yara_matches, yara_status = run_yara(" in src
