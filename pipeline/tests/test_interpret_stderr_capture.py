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
"""
from stages.interpret import _drain_stderr


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
    proc = _FakeProc(_FakeStream("Traceback (most recent call last):\n  boom\n"))
    assert "Traceback" in _drain_stderr(proc)


def test_returns_the_tail_of_a_long_traceback():
    """The last lines name the exception — the top is usually framework frames."""
    text = "noise\n" * 5000 + "AttributeError: the actual cause\n"
    out = _drain_stderr(_FakeProc(_FakeStream(text)))
    assert "AttributeError: the actual cause" in out
    assert out.startswith("...[truncated]")
    assert len(out) < 5000


def test_missing_or_closed_stderr_is_not_an_error():
    assert _drain_stderr(_FakeProc(None)) == ""
    assert _drain_stderr(_FakeProc(_FakeStream("x", closed=True))) == ""


def test_a_failing_read_never_masks_the_real_failure():
    """This runs on the error path; it must not raise over the original error."""
    proc = _FakeProc(_FakeStream("", raises=ValueError("pipe gone")))
    out = _drain_stderr(proc)
    assert "could not read container stderr" in out
    assert "ValueError" in out


def test_whitespace_only_stderr_is_empty():
    assert _drain_stderr(_FakeProc(_FakeStream("   \n\n  "))) == ""
