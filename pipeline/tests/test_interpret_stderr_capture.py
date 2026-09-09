# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A dead interpret container must report WHY, not just that it died.

`stderr=subprocess.PIPE` was set and then never read, so when the container died its
traceback was captured and discarded. The 2026-07-27 qwen@30 depth probe reported only
"Interpret container exited without final result" after 18 successful tool calls — no
way to distinguish a crash from an OOM from a clean exit, and no way to learn anything
without another 26-minute run.

An unread stderr pipe is also a hang risk: once the OS buffer fills, the container
blocks on write and the loop waits forever on stdout.

Reading it on the ERROR path did not work, and 2026-09-08 showed both halves of
why: _drain_stderr called proc.stderr.read() — blocking, to EOF — after the
finally block had already killed the process. The read blocked for ten minutes
(stdout loop ended t=334s, stage returned t=952s) and still produced "". So the
buffer is now filled by a reader thread started with the process, which also
removes the hang risk above rather than merely surviving it.
"""
import subprocess
import sys
import time
from pathlib import Path

from stages.interpret import _drain_stderr, _start_stderr_reader


class _FakeStream:
    def __init__(self, text, closed=False, raises=None):
        self._text, self.closed, self._raises = text, closed, raises

    def read(self):
        if self._raises:
            raise self._raises
        return self._text


class _FakeProc:
    def __init__(self, stderr):
        self.stderr = stderr


def test_returns_container_stderr():
    assert "Traceback" in _drain_stderr(
        None, ["Traceback (most recent call last):\n", "  boom\n"])


def test_returns_the_tail_of_a_long_traceback():
    """The last lines name the exception — the top is usually framework frames."""
    buf = ["noise\n"] * 5000 + ["AttributeError: the actual cause\n"]
    out = _drain_stderr(None, buf)
    assert "AttributeError: the actual cause" in out
    assert out.startswith("...[truncated]")
    assert len(out) < 5000


def test_an_uncaptured_buffer_says_so_rather_than_looking_empty():
    """"" reads as "the container said nothing", which is what the old version
    reported for the very failure it existed to explain."""
    assert _drain_stderr(None, None) == "<stderr was not being captured>"


def test_a_reader_that_dies_never_masks_the_real_failure():
    """This runs on the error path; losing the diagnostic beats replacing the
    original error with one from the diagnostic."""
    class _Boom:
        stderr = property(lambda self: (_ for _ in ()).throw(ValueError("pipe gone")))
    buf = _start_stderr_reader(_Boom())
    assert buf == []
    assert _drain_stderr(None, buf) == ""


def test_whitespace_only_stderr_is_empty():
    assert _drain_stderr(None, ["   \n", "\n", "  "]) == ""


# --- behaviours that actually broke on 2026-09-08 -------------------------
# The tests above exercise the buffer. These exercise the two properties whose
# absence produced an unexplained failure and a ten-minute stall.

def test_stderr_survives_the_process_being_killed():
    """The whole point: the traceback outlives the kill. The old version read
    the pipe AFTER terminate()/kill() and got ""."""
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time; sys.stderr.write('BOOM traceback line\\n'); "
         "sys.stderr.flush(); time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    buf = _start_stderr_reader(proc)
    time.sleep(1.0)
    proc.kill()
    proc.wait(timeout=5)
    assert "BOOM traceback line" in _drain_stderr(proc, buf)


def test_draining_does_not_block_on_a_live_process():
    """The ten-minute stall: stdout loop ended at t=334s, stage returned t=952s,
    all of it inside a blocking read on a pipe still held open."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    buf = _start_stderr_reader(proc)
    start = time.time()
    _drain_stderr(proc, buf)
    elapsed = time.time() - start
    proc.kill()
    proc.wait(timeout=5)
    assert elapsed < 2.0, f"draining blocked for {elapsed:.1f}s on a live process"


def test_every_container_launch_starts_a_reader():
    """A Popen without one is a failure that cannot be diagnosed."""
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "stages" / "interpret.py").read_text(encoding="utf-8")
    assert src.count("subprocess.Popen(") == src.count("_start_stderr_reader(proc)"), \
        "a container is launched without its stderr being captured"
