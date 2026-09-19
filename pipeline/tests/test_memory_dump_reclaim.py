# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The consumer reclaims the dump it just read.

8.6 GB per analysis (the guest has 8 GiB of RAM) and conf/memory.conf sets
delete_memdump = no, so CAPE never reclaims one. Eight unreaped dumps filled the
disk and CAPE silently stopped scheduling below its freespace = 50000 floor
while every service still reported active.

There is already an hourly reaper -- the ansible-managed `cape-storage-maintenance`
cron, `find ... -name memory.dmp -mmin +60 -delete` at :15 past. That is the
backstop and it is sufficient for orphans. This is the primary path: reclaiming
immediately after the only consumer finishes holds peak usage at one dump rather
than up to two hours' worth.

What must NOT come back is the host-only cape-janitor.service: a 120-second
sweep that deleted every memory.dmp it found, unconditionally. Its own header
said "reaping them is NOT safe if Volatility is ever enabled" -- it would delete
the dump out from under a stage allowed to run for 45 minutes.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from stages.volatility import reap_memory_dump  # noqa: E402


def _fake_storage(tmp_path, task_id, content=b"x" * 2048):
    d = tmp_path / "analyses" / str(task_id)
    d.mkdir(parents=True)
    dump = d / "memory.dmp"
    dump.write_bytes(content)
    return dump


def test_a_dump_is_deleted_and_its_size_reported(tmp_path, monkeypatch):
    dump = _fake_storage(tmp_path, 4242)
    monkeypatch.setattr("stages.volatility.get_memory_dump_path", lambda _: dump)

    r = reap_memory_dump({"id": 4242})
    assert r["reaped"] is True
    assert r["freed_bytes"] == 2048
    assert not dump.exists(), "the dump survived the reclaim"


def test_a_missing_dump_is_not_an_error(monkeypatch):
    """Dumps are off by default, and an ad-hoc run may never have made one.
    Reclaiming nothing is the normal case, not a fault."""
    monkeypatch.setattr("stages.volatility.get_memory_dump_path", lambda _: None)
    r = reap_memory_dump({"id": 1})
    assert r["reaped"] is False
    assert "error" not in r


def test_an_undeletable_dump_reports_the_problem(tmp_path, monkeypatch):
    """A dump that cannot be deleted is exactly how the disk fills, so it must
    not fail silently -- the hourly cron is the backstop, but the operator needs
    to know the primary path stopped working."""
    dump = _fake_storage(tmp_path, 7)
    monkeypatch.setattr("stages.volatility.get_memory_dump_path", lambda _: dump)

    def boom():
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(Path, "unlink", lambda self, **kw: boom())
    r = reap_memory_dump({"id": 7})
    assert r["reaped"] is False
    assert "PermissionError" in r["error"]
    assert r["path"].endswith("memory.dmp")
