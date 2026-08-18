# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Targeted malfind --dump must pass one argv token per PID.

`run_targeted_malfind_dump` joined the selected PIDs with commas and passed the
result as a single `--pid` argument:

    pid_str = ",".join(str(p) for p in sorted(target_pids))
    ... "--pid", pid_str, "--dump"

Volatility declares malfind's `pid` as a `ListRequirement(element_type=int)`,
which its CLI maps to argparse `nargs="*"` with `type=lambda x: int(x, 0)` —
space-separated tokens. Measured against volatility3 2.27.0:

    vol -f dump windows.malfind out --pid 1236,2104 --dump
      -> rc=2  "argument --pid: invalid <lambda> value: '1236,2104'"
    vol -f dump windows.malfind out --pid 1236 --dump
      -> gets past argparse

So whenever the heuristic filter selected regions in two or more distinct PIDs,
vol exited before doing any work and the targeted dump extracted nothing. Stage
3.5 then found no dump files and shellcode analysis was skipped for those
regions. With exactly one selected PID the command worked, which is what hid it.

Not silent — vol's stderr is printed and run-pipeline logs "N selected regions
have no dump file" — but the function still returns the dump directory and
`run_volatility` still populates `_malfind_selected`, so nothing downstream can
tell "vol refused the arguments" from "there was nothing to dump".

Scope: the fallback branch taken when `cape_has_injection_buffers` is False. The
Cape-buffer branch and the `windows.pslist --dump` procdump loop pass one PID
per call and were never affected.

The assertion is on the argv the function builds. A test that ran vol for real
would need a Windows memory image; the argument shape is the whole defect.
"""
from pathlib import Path

import pytest

# conftest.py puts ansible/roles/pipeline/files on sys.path — the modules deploy
# flat to /opt/pipeline/, so `stages` is only importable via that hook.
from stages import volatility


class _Result:
    returncode = 0
    stdout = ""
    stderr = ""


@pytest.fixture
def captured_argv(monkeypatch):
    """Run the dump helper without a real vol, returning the argv it built."""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        return _Result()

    monkeypatch.setattr(volatility.subprocess, "run", fake_run)

    def run(target_pids, tmp_path):
        volatility.run_targeted_malfind_dump(
            Path("/nonexistent/memory.dmp"), target_pids, tmp_path, "vol")
        return seen["cmd"]

    return run


def _pid_tokens(cmd):
    return cmd[cmd.index("--pid") + 1:cmd.index("--dump")]


def test_two_pids_are_two_argv_tokens(captured_argv, tmp_path):
    """THE bug. A comma-joined list makes vol exit 2 before doing any work."""
    cmd = captured_argv({2104, 1236}, tmp_path)
    assert _pid_tokens(cmd) == ["1236", "2104"], (
        f"expected one argv token per PID, got {_pid_tokens(cmd)} in {cmd}")


def test_no_argv_token_contains_a_comma(captured_argv, tmp_path):
    """The general form, so a future rewrite cannot reintroduce the join under
    another name — vol rejects a comma anywhere in an int-typed list argument."""
    cmd = captured_argv({4, 8, 15, 16, 23, 42}, tmp_path)
    offenders = [tok for tok in cmd if "," in tok]
    assert not offenders, f"comma-joined argv token(s): {offenders}"


def test_a_single_pid_still_works(captured_argv, tmp_path):
    """The case that always worked, and therefore the case that hid the bug."""
    cmd = captured_argv({1236}, tmp_path)
    assert _pid_tokens(cmd) == ["1236"]


def test_pids_stay_sorted_and_complete(captured_argv, tmp_path):
    """Every selected PID must reach vol — dropping one silently skips a
    process's shellcode, which looks identical to finding none."""
    pids = {900, 12, 7000, 44}
    cmd = captured_argv(pids, tmp_path)
    assert _pid_tokens(cmd) == ["12", "44", "900", "7000"]


def test_the_plugin_and_dump_flag_are_unchanged(captured_argv, tmp_path):
    """Guard the rest of the command line, since the fix edits it."""
    cmd = captured_argv({1236, 2104}, tmp_path)
    assert cmd[0] == "vol"
    assert "windows.malfind" in cmd
    assert cmd[-1] == "--dump"
