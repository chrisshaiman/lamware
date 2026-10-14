# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The nightly report cleanup deletes what it can and names what it cannot.

Under `set -e` with one `find -exec rm -rf {} +`, the first report directory the
pipeline user could not delete aborted the whole run. Five directories from May
held files owned by a container's mapped uid; they survived four and a half
months past the 7-day retention, the CAPE memory-dump lines after them never
ran, and nothing reported it because cron discards the output (found
2026-10-01).

Renders the real template and runs it against real directories.
"""
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

TEMPLATE = (Path(__file__).resolve().parents[1]
            / "ansible/roles/pipeline/templates/pipeline-cleanup.sh.j2")

pytestmark = [
    pytest.mark.skipif(os.geteuid() == 0, reason="root can delete anything"),
    pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash"),
]


def _age(path: Path, days: int) -> None:
    t = time.time() - days * 86400
    os.utime(path, (t, t))


@pytest.fixture
def reports(tmp_path):
    root = tmp_path / "reports"
    root.mkdir()
    # Sorted first, so a run that stops at the first failure never reaches the rest.
    stuck = root / "a_stuck_may"
    (stuck / "project").mkdir(parents=True)
    (stuck / "project" / "f").write_text("x")
    (stuck / "project").chmod(0o555)          # its contents cannot be removed
    old = root / "b_old"
    old.mkdir()
    (old / "report.json").write_text("{}")
    recent = root / "c_recent"
    recent.mkdir()
    for d, days in ((stuck, 140), (old, 30), (recent, 1)):
        _age(d, days)
    yield root, stuck, old, recent
    (stuck / "project").chmod(0o755)


def _render(root: Path, tmp_path: Path, harvest: str = "") -> str:
    """The real template, with the keep-list builder replaced by a fake python
    that writes `harvest` as keep.txt (or fails, for `harvest=None`)."""
    hdir = tmp_path / "harvest"
    hdir.mkdir(exist_ok=True)
    fake = tmp_path / "fake-python"
    if harvest is not None:
        (hdir / "keep.txt").write_text(harvest)
    fake.write_text(f"#!/bin/bash\nexit {1 if harvest is None else 0}\n")
    fake.chmod(0o755)
    return jinja2.Environment().from_string(TEMPLATE.read_text()).render(
        pipeline_reports_dir=str(root), pipeline_report_retention_days=7,
        pipeline_install_dir=str(tmp_path / "install"), pipeline_python=str(fake),
        pipeline_harvest_dir=str(hdir), pipeline_correlated_report_keep_days=60,
        pipeline_correlated_report_keep_max=40)


def _run(root: Path, tmp_path: Path, harvest: str | None = "") -> subprocess.CompletedProcess:
    script = tmp_path / "cleanup.sh"
    script.write_text(_render(root, tmp_path, harvest))
    # A logger that records instead of writing to the real syslog.
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "logger").write_text(f'#!/bin/bash\necho "$@" >> {tmp_path}/syslog\n')
    (shim / "logger").chmod(0o755)
    env = {**os.environ, "PATH": f"{shim}:{os.environ['PATH']}"}
    return subprocess.run(["bash", str(script)], capture_output=True, text=True,
                          env=env, timeout=30)


def test_an_undeletable_directory_does_not_stop_the_rest(reports, tmp_path):
    root, stuck, old, recent = reports
    _run(root, tmp_path)
    assert not old.exists(), "a deletable expired report survived"
    assert recent.exists(), "a report inside retention was deleted"
    assert stuck.exists()


def test_the_failure_is_named_and_the_run_fails(reports, tmp_path):
    root, stuck, _, _ = reports
    proc = _run(root, tmp_path)
    assert proc.returncode != 0, "a failed delete exited 0"
    assert str(stuck) in proc.stderr
    assert str(stuck) in (tmp_path / "syslog").read_text(), "nothing reached syslog"


def test_a_clean_run_exits_zero(tmp_path):
    root = tmp_path / "reports"
    (root / "old").mkdir(parents=True)
    _age(root / "old", 30)
    proc = _run(root, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert not (root / "old").exists()


def test_no_step_pretends_to_clean_cape_storage(tmp_path):
    """pipeline cannot write CAPE storage (SECURITY_CONSTRAINTS.md); a delete
    there could only ever fail, and `|| true` made that look like success."""
    rendered = _render(Path("/r"), tmp_path)
    commands = [ln for ln in rendered.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert not any("/opt/CAPEv2" in ln for ln in commands), commands


def test_a_correlated_report_on_the_keep_list_outlives_retention(reports, tmp_path):
    """#420: the eval corpus needs these, and re-detonating does not bring a
    finding back (Salat: one finding on 2026-09-28, none on 2026-10-12)."""
    root, _, old, _ = reports
    other = root / "d_old_uncorrelated"
    other.mkdir()
    _age(other, 30)
    _run(root, tmp_path, harvest=f"{old.name}\n")
    assert old.exists(), "a report on the keep-list was deleted"
    assert not other.exists(), "the keep-list kept a report it does not name"


def test_no_keep_list_means_nothing_is_deleted(reports, tmp_path):
    """Fail closed: a database outage must not cost the week's correlated report."""
    root, _, old, _ = reports
    proc = _run(root, tmp_path, harvest=None)
    assert old.exists(), "reports were deleted without a keep-list"
    assert proc.returncode != 0
    assert "keep-list" in proc.stderr
