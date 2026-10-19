# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A run killed mid-way must not leave its analysis row `running` forever (#802).

create_analysis_row writes the row before any stage; complete_pipeline writes the
terminal status at the end. A reboot, an OOM or the intake runner's `timeout 5400`
ends the process in between and nothing corrects the row: on 2026-10-18 four
rows were `running`, two of them since September, shown next to real runs.

The fix reconciles at the next run's start. These drive reconcile_stale_running
against a recording stand-in for the connection: the statement it issues must
touch only `running` rows older than the hard timeout, set them `failed`, and
the timeout constant must equal the shell's, or the rule reconciles rows that
could still be alive.
"""
import re
from pathlib import Path

import pipeline_status

ROOT = Path(__file__).resolve().parents[2]
INTAKE_RUN = ROOT / "scripts" / "lib" / "intake_run.sh"


class _Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.sql = None
        self.params = None

    def execute(self, sql, params=None):
        self.sql, self.params = sql, params

    def fetchall(self):
        return self.rows

    def close(self):
        pass


class _Conn:
    def __init__(self, rows):
        self.cursor_obj = _Cursor(rows)
        self.autocommit = False
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


def test_only_running_rows_older_than_the_hard_timeout_are_marked_failed(monkeypatch, capsys):
    conn = _Conn(rows=[(1094,), (1150,), (1194,)])
    monkeypatch.setattr(pipeline_status, "_get_conn", lambda: conn)

    n = pipeline_status.reconcile_stale_running()

    sql = " ".join(conn.cursor_obj.sql.split())
    assert n == 3
    assert "UPDATE analyses" in sql
    assert "SET pipeline_status = 'failed'" in sql
    assert "WHERE pipeline_status = 'running'" in sql
    assert "started_at < NOW() - make_interval(secs => %s)" in sql, sql
    assert conn.cursor_obj.params == (pipeline_status.PIPELINE_HARD_TIMEOUT_SECONDS,)
    assert conn.autocommit is True and conn.closed
    assert "[1094, 1150, 1194]" in capsys.readouterr().out


def test_nothing_to_reconcile_is_silent(monkeypatch, capsys):
    conn = _Conn(rows=[])
    monkeypatch.setattr(pipeline_status, "_get_conn", lambda: conn)
    assert pipeline_status.reconcile_stale_running() == 0
    assert capsys.readouterr().out == ""


def test_no_database_is_zero_not_an_error(monkeypatch):
    monkeypatch.setattr(pipeline_status, "_get_conn", lambda: None)
    assert pipeline_status.reconcile_stale_running() == 0


def test_the_hard_timeout_matches_the_intake_runner():
    """The rule is only safe because nothing can still be running past the
    runner's `timeout`. If the shell changes, this must change with it."""
    text = INTAKE_RUN.read_text(encoding="utf-8")
    m = re.search(r"\btimeout (\d+) ", text)
    assert m, "intake_run.sh no longer wraps the run in `timeout N`"
    assert int(m.group(1)) == pipeline_status.PIPELINE_HARD_TIMEOUT_SECONDS


def test_the_pipeline_reconciles_before_creating_its_own_row():
    src = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py").read_text(encoding="utf-8")
    assert src.index("reconcile_stale_running()") < src.index("analysis_id_early = create_analysis_row(")
