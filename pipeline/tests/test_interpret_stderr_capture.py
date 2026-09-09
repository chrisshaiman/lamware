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

from stages.interpret import _describe_exit, _drain_stderr, _start_stderr_reader


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


# --- how it died, not just that it did -----------------------------------
# stderr came back genuinely empty across three runs on 2026-09-08: the
# container writes nothing before going. The exit status is then the only
# remaining signal, and it must be read BEFORE the orchestrator's own
# terminate()/kill() overwrites it.

def test_a_still_running_process_is_not_reported_as_a_crash():
    """None means it closed stdout and kept running — a protocol bug. Calling
    that a crash sends the next reader looking for the wrong thing."""
    note = _describe_exit(None)
    assert "still running" in note
    assert "not a crash" in note


def test_a_signal_death_is_named():
    assert "SIGKILL" in _describe_exit(-9)
    assert "SIGSEGV" in _describe_exit(-11)


def test_the_oom_shaped_exit_is_called_out():
    """137 is how the container runtime reports SIGKILL, and OOM is the usual
    cause — worth saying, since the report is read by whoever is on call."""
    assert "137" in _describe_exit(137)
    assert "OOM" in _describe_exit(137)


def test_a_clean_exit_without_a_result_is_named_a_protocol_bug():
    """Exit 0 with no final message is the case most likely to be misread as
    'the container crashed'."""
    note = _describe_exit(0)
    assert "cleanly" in note
    assert "protocol" in note


def test_the_exit_status_is_read_before_the_orchestrator_kills_it():
    """The ordering is the whole point. proc.poll() must happen inside the try,
    at stdout EOF — the finally block terminate()s and kill()s, so a read after
    it describes OUR signal rather than how the container died."""
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "stages" / "interpret.py").read_text(encoding="utf-8")
    eof = src.index("eof_returncode = proc.poll()")
    finally_block = src.index("    finally:", eof - 4000)
    assert eof < finally_block, \
        "the exit status is read after the finally block, so it records our own kill"


# --- a timeout is not a crash --------------------------------------------
# The timeout break and the EOF break both fell through to "Interpret container
# exited without final result". Measured on salat_d26bc055, 2026-09-08:
# heartbeat at t=304s, break at t=334s — exactly the 30s grace against a 300s
# budget, on a container that was alive and working. Three rounds of chasing
# tracebacks and exit codes went into a crash that never happened.

def _stage_src() -> str:
    return (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
            / "files" / "stages" / "interpret.py").read_text(encoding="utf-8")


def test_the_timeout_path_reports_a_timeout_not_a_death():
    """Anchored on the timeout RETURN BLOCK, not the file. "this is not a crash"
    also appears in _describe_exit, so a whole-file search passed even after the
    timeout message was gutted — verified by mutation."""
    src = _stage_src()
    start = src.index('if timed_out:')
    block = src[start:src.index("trail.event(\"container_exited_without_final\"", start)]
    assert '"timed_out": True' in block, "the timeout path is not distinguished in the result"
    assert "timed out after" in block, "the timeout message does not say it timed out"
    assert "not a crash" in block, \
        "the timeout message does not say it is not a crash — the wording IS the bug"


def test_the_budget_fits_the_local_model():
    """The EFFECTIVE value, not the template fallback.

    The first version of this test asserted config.json.j2's `| default(1800)`.
    That passed while the host kept running 300s, because roles/interpret sets
    interpret_timeout explicitly and a Jinja default only applies when the
    variable is undefined. Raising the fallback changed nothing, and the test
    said it had. Assert what ships.

    300s was sized for Claude. The local 35B took 3m26s to reach its FIRST tool
    call, so 300s cut every run short."""
    import yaml
    defaults = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "interpret"
         / "defaults" / "main.yml").read_text(encoding="utf-8"))
    budget = defaults["interpret_timeout"]
    assert budget >= 1200, (
        f"interpret_timeout ships as {budget}s; the local agentic loop needs far "
        f"longer, and a short budget gets reported as a container death")
    grace = defaults["interpret_force_final_grace"]
    assert grace >= 120, (
        f"the forced-final grace ships as {grace}s, which a local synthesis "
        f"cannot meet — the forced final never arrives and the timeout looks "
        f"like a crash")


def test_the_timeout_and_eof_paths_do_not_share_a_message():
    """They converged. That convergence IS the defect being fixed."""
    src = _stage_src()
    ti = src.index('"timed_out": True')
    eof = src.index('trail.event("container_exited_without_final"')
    assert ti < eof, "the timeout case must return before the generic exited-without-final path"


def test_the_forced_final_grace_is_not_hardcoded_to_thirty_seconds():
    """30s could never be met by a local synthesis, so the forced final never
    arrived and every timeout looked like a death."""
    src = _stage_src()
    assert "proc.wait(timeout=force_final_grace)" in src, \
        "the forced-final grace is still hardcoded"
    assert "force_final_grace: int = 300" in src, "the default grace is not 300s"
