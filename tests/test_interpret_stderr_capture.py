# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The interpret container's stderr must survive the container being killed (#584 follow-up).

When the container exits without a final result — the failure mode seen with
local qwen on 2026-07-27 (18 tool calls) and again on 2026-09-08 (4 tool calls) —
its stderr is the only evidence of why. The previous implementation lost it, and
stalled the pipeline while doing so:

    try: ...read stdout...
    finally: proc.terminate(); proc.wait(5); proc.kill()
    return {"container_stderr": _drain_stderr(proc)}   # <- AFTER the kill

_drain_stderr called proc.stderr.read(), a blocking read to EOF, on a process
that had just been killed. Measured 2026-09-08: the stdout loop ended at t=334s
and the stage did not return until t=952s — ten minutes inside a diagnostic —
and container_stderr came back "" anyway.

So the buffer is filled by a reader thread started with the process.
"""
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "ansible" / "roles" / "pipeline" / "files" / "stages" / "interpret.py"
spec = importlib.util.spec_from_file_location("_interpret_stage", SRC)
mod = importlib.util.module_from_spec(spec)
sys.modules["_interpret_stage"] = mod
spec.loader.exec_module(mod)


def test_stderr_survives_the_process_being_killed():
    """The whole point: the traceback outlives the kill."""
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time; sys.stderr.write('BOOM traceback line\\n'); "
         "sys.stderr.flush(); time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    buf = mod._start_stderr_reader(proc)
    time.sleep(1.0)
    proc.kill()
    proc.wait(timeout=5)
    assert "BOOM traceback line" in mod._drain_stderr(proc, buf)


def test_draining_does_not_block_on_a_live_process():
    """The ten-minute stall. A process still holding the pipe open must not make
    the diagnostic hang."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    buf = mod._start_stderr_reader(proc)
    start = time.time()
    mod._drain_stderr(proc, buf)
    elapsed = time.time() - start
    proc.kill(); proc.wait(timeout=5)
    assert elapsed < 2.0, f"draining blocked for {elapsed:.1f}s on a live process"


def test_an_uncaptured_stderr_says_so_instead_of_looking_empty():
    """"" reads as 'the container said nothing'. That is what the old version
    reported for a failure it was specifically added to explain."""
    assert mod._drain_stderr(None, None) == "<stderr was not being captured>"


def test_the_tail_is_kept_when_output_is_long():
    """A traceback's last lines are the informative ones."""
    buf = ["x" * 10, "\n", "IMPORTANT LAST LINE\n"]
    buf = ["filler\n"] * 5000 + ["IMPORTANT LAST LINE\n"]
    out = mod._drain_stderr(None, buf)
    assert "IMPORTANT LAST LINE" in out
    assert out.startswith("...[truncated]")
    assert len(out) < 6000


def test_every_container_launch_starts_a_reader():
    """A Popen without one is a failure that cannot be diagnosed."""
    src = SRC.read_text(encoding="utf-8")
    assert src.count("subprocess.Popen(") == src.count("_start_stderr_reader(proc)"), \
        "a container is launched without its stderr being captured"
