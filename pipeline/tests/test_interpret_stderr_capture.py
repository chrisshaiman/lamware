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
