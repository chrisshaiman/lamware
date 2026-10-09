# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The feeder pause/resume controls must not follow a planted link.

/opt/pipeline/control is group-writable by every lamware member and not
sticky. A plain open() of PAUSE ("a") or PAUSE.trigger ("w") followed a symlink
there, and "w" truncated its target. These run the real helper against real
files, links and FIFOs.
"""
import ast
import os
import signal
import stat
import sys
from pathlib import Path

import pytest

for _key in list(sys.modules):
    if _key.startswith("app.investigate"):
        del sys.modules[_key]

from app.routers import feeder  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX semantics")


def test_creates_a_missing_file(tmp_path):
    p = tmp_path / "PAUSE"
    feeder._touch_nofollow(str(p))
    assert p.is_file() and not p.is_symlink()


def test_an_existing_file_keeps_its_contents(tmp_path):
    p = tmp_path / "PAUSE.trigger"
    p.write_text("keep")
    feeder._touch_nofollow(str(p))
    assert p.read_text() == "keep", "the touch must never truncate"


def test_a_planted_symlink_is_refused_and_its_target_untouched(tmp_path):
    victim = tmp_path / "lamware-api.env"
    victim.write_text("SECRET=1\n")
    before = victim.stat().st_mtime_ns
    link = tmp_path / "PAUSE.trigger"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        feeder._touch_nofollow(str(link))
    assert victim.read_text() == "SECRET=1\n"
    assert victim.stat().st_mtime_ns == before


def test_a_planted_dangling_symlink_does_not_create_its_target(tmp_path):
    target = tmp_path / "elsewhere" / "created"
    (tmp_path / "elsewhere").mkdir()
    link = tmp_path / "PAUSE"
    link.symlink_to(target)
    with pytest.raises(OSError):
        feeder._touch_nofollow(str(link))
    assert not target.exists()


def test_a_planted_fifo_does_not_hang_the_request(tmp_path):
    """Without O_NONBLOCK this blocks forever; the alarm turns a regression into
    a failure instead of a hung CI job."""
    fifo = tmp_path / "PAUSE.trigger"
    os.mkfifo(fifo)

    def _hung(*_):
        raise AssertionError("opening a planted FIFO blocked; O_NONBLOCK is missing")
    old = signal.signal(signal.SIGALRM, _hung)
    signal.alarm(5)
    try:
        with pytest.raises(OSError):    # ENXIO with no reader, instead of blocking
            feeder._touch_nofollow(str(fifo))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def test_a_directory_is_refused(tmp_path):
    d = tmp_path / "PAUSE"
    d.mkdir()
    with pytest.raises(OSError):
        feeder._touch_nofollow(str(d))


def test_new_files_are_not_world_readable(tmp_path):
    p = tmp_path / "PAUSE"
    old = os.umask(0)
    try:
        feeder._touch_nofollow(str(p))
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == 0o640


def test_both_endpoints_use_the_helper_and_no_plain_open():
    """Structural, because the endpoints need a DB session and auth to call;
    the behaviour itself is covered above."""
    tree = ast.parse(Path(feeder.__file__).read_text())
    for name in ("feeder_pause", "feeder_resume"):
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.AsyncFunctionDef) and n.name == name)
        calls = {c.func.id for c in ast.walk(fn)
                 if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        assert "_touch_nofollow" in calls, name
        assert "open" not in calls, f"{name} still opens a control file with open()"
