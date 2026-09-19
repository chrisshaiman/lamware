# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The two measurement instruments must each have a working entry point.

lamware_eval was committed and tested in July and had no Makefile target. Its
last output on the host is dated 2026-08-31, while thirteen hand-written shell
drivers were created between 2026-09-04 and 2026-09-17 to do detonation work it
structurally cannot do. A harness nobody can start is a harness nobody uses, and
the replacement for a missing front door is always a fresh script that skips
whatever the last one learned.
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text()


def _code(path: Path) -> str:
    """The script with comment lines removed.

    These scripts document the mistakes they prevent, by name -- detonate.sh
    explains that `nohup ... &` was killed mid-batch, and the helper explains
    that `is-active --quiet` cannot read a oneshot unit. A prohibition asserted
    against the raw text therefore fires on its own rationale, which is the
    same defect as a test that passes by matching the comment describing the
    rule. Strip the prose and assert on what actually executes.
    """
    out = []
    for line in path.read_text().splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


DETONATE = _code(ROOT / "scripts" / "detonate.sh")
EVAL = _code(ROOT / "scripts" / "eval.sh")
HELPER = _code(ROOT / "scripts" / "lib" / "remote-oneshot.sh")


def _target_body(name: str) -> str:
    m = re.search(rf"^{name}:\n((?:\t.*\n|\n)*)", MAKEFILE, re.MULTILINE)
    assert m, f"Makefile has no `{name}` target"
    return m.group(1)


def test_both_targets_exist():
    for t in ("eval", "detonate"):
        assert _target_body(t).strip(), f"`make {t}` exists but does nothing"


def test_targets_are_phony():
    """Without .PHONY, a file or directory named `eval` makes the target a no-op.

    There IS a directory named eval/ under the pipeline role's files, so this is
    not hypothetical.
    """
    phony = " ".join(re.findall(r"^\.PHONY:(.*)$", MAKEFILE, re.MULTILINE))
    for t in ("eval", "detonate"):
        assert re.search(rf"\b{t}\b", phony), f"`{t}` is missing from .PHONY"


def test_detonate_requires_an_explicit_sample():
    """No default sample. A measurement run must name what it measured."""
    p = subprocess.run(["bash", str(ROOT / "scripts" / "detonate.sh")],
                       capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert p.returncode == 2
    assert "usage:" in p.stderr


def test_eval_requires_explicit_arms():
    p = subprocess.run(["bash", str(ROOT / "scripts" / "eval.sh")],
                       capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert p.returncode == 2
    assert "usage:" in p.stderr


def test_detonate_always_pins_the_guest():
    """--machine is passed unconditionally and defaults to clean.

    Both CAPE guests are tagged x64, so an omitted --machine is not a harmless
    default -- it is the confound that got tasks 1132/1133 discarded.
    """
    assert "--machine $MACHINE" in DETONATE
    assert "MACHINE=${MACHINE:-clean}" in DETONATE


def test_neither_front_door_enables_anything():
    """`systemctl enable` would arm a detonation unit to run unattended.

    Standing instruction: a feeder or repro unit is never started or enabled
    without being asked. These targets start a one-shot unit and nothing else.
    """
    for name, body in (("detonate.sh", DETONATE), ("eval.sh", EVAL)):
        assert "systemctl enable" not in body, f"{name} enables a unit"
        assert "--now" not in body, f"{name} uses enable --now"


def test_long_jobs_are_not_run_over_the_ssh_session():
    """`nohup ... &` inside an ssh command was killed by a signal partway through
    a 5.5-hour batch, leaving a truncated log and an untouched report."""
    for name, body in (("detonate.sh", DETONATE), ("eval.sh", EVAL)):
        assert "nohup" not in body, f"{name} uses nohup instead of a systemd unit"
        assert "TimeoutStartSec=infinity" in body, (
            f"{name} must not let systemd time out a multi-hour one-shot job")


def test_oneshot_units_are_never_probed_with_is_active_quiet():
    """A Type=oneshot unit reports `activating` for its whole run, so
    `is-active --quiet` is false throughout. That has broken this project three
    times, the third inside a guard written to prevent it."""
    for name, body in (("detonate.sh", DETONATE), ("eval.sh", EVAL),
                       ("remote-oneshot.sh", HELPER)):
        assert "is-active --quiet" not in body, (
            f"{name} probes a oneshot unit with is-active --quiet")


def test_the_busy_check_covers_every_running_state():
    """`activating` alone is not enough: a unit mid-teardown is still holding the
    guest, and starting a second batch then puts two tasks in flight."""
    for state in ("activating", "active", "reloading", "deactivating"):
        assert state in HELPER, f"busy check ignores ActiveState={state}"


def test_a_second_batch_cannot_start_on_top_of_a_running_one():
    assert "remote_unit_busy" in DETONATE and "remote_unit_busy" in EVAL


# --- behavioural: the guards are RUN, not grepped ----------------------------
#
# The two tests above that assert `remote_unit_busy` appears in a script, and
# that four state names appear in the helper, are both substring checks. A
# mutation sweep showed each surviving: `if false && remote_unit_busy` still
# contains the call, and narrowing RUNNING_STATES to "activating" still leaves
# the other three names in the follow loop's case arm. So the guards are
# exercised here against a fake ssh instead.

FAKE_SSH = r'''#!/usr/bin/env bash
# Stand-in for ssh. Answers the ActiveState probe with $FAKE_STATE and records
# every invocation -- ARGV *and STDIN* -- so the test can prove what was started.
#
# stdin matters: the unit file is piped to `ssh ... tee`, so the ExecStart line
# (which carries --machine) never appears in argv. An earlier version of these
# tests asserted against argv alone and passed vacuously.
args="$*"
{ echo "ARGV: $args"; } >> "$FAKE_SSH_CALLS"
if [ ! -t 0 ]; then
  while IFS= read -r line; do echo "STDIN: $line" >> "$FAKE_SSH_CALLS"; done
fi
case "$args" in
  *"ActiveState --value"*) echo "${FAKE_STATE:-inactive}" ;;
  *) exit 0 ;;
esac
'''


def _run_with_fake_ssh(tmp_path, script, state, env_extra):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    ssh = bindir / "ssh"
    ssh.write_text(FAKE_SSH)
    ssh.chmod(0o755)
    calls = tmp_path / "calls.txt"
    calls.write_text("")
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "FAKE_STATE": state,
        "FAKE_SSH_CALLS": str(calls),
        **env_extra,
    }
    p = subprocess.run(["bash", str(ROOT / "scripts" / script)],
                       capture_output=True, text=True, env=env)
    return p, calls.read_text()


def test_busy_states_actually_block(tmp_path):
    """Every state that means "still holding the guest" must refuse to start.

    deactivating matters as much as activating: a unit mid-teardown has not
    released the VM, and a second submission there is exactly how two tasks end
    up in flight on two different guests.
    """
    for i, state in enumerate(("activating", "active", "reloading", "deactivating")):
        d = tmp_path / f"busy{i}"
        d.mkdir()
        p, calls = _run_with_fake_ssh(d, "detonate.sh", state,
                                      {"SAMPLE": "/opt/pipeline/x.exe"})
        assert p.returncode == 1, f"ActiveState={state} did not block a new batch"
        assert "already running" in p.stderr
        assert "systemctl start" not in calls, (
            f"a batch was started while the unit was {state}")


def test_an_idle_unit_is_not_blocked(tmp_path):
    """The guard must not refuse everything -- that would pass the test above for
    the wrong reason."""
    p, calls = _run_with_fake_ssh(tmp_path, "detonate.sh", "inactive",
                                  {"SAMPLE": "/opt/pipeline/x.exe"})
    assert "systemctl start" in calls, "an idle unit should have been started"


def test_the_started_batch_pins_the_guest(tmp_path):
    """Read the pinning off the unit that was actually written, not off the source.

    This is the assertion that matters: not "the script mentions --machine" but
    "the systemd unit that just got installed on the sandbox pins the guest".
    """
    p, calls = _run_with_fake_ssh(tmp_path, "detonate.sh", "inactive",
                                  {"SAMPLE": "/opt/pipeline/x.exe"})
    execstart = [ln for ln in calls.splitlines() if "ExecStart" in ln]
    assert execstart, f"no unit file was written; calls were:\n{calls}"
    assert "--machine clean" in execstart[0], (
        f"the installed unit does not pin the guest: {execstart[0]}")
    assert "--runs 20" in execstart[0], f"default run count lost: {execstart[0]}"
    assert "memory" not in execstart[0], (
        f"a full-VM memory dump was requested: {execstart[0]}")


def test_the_started_unit_cannot_time_out_or_be_enabled(tmp_path):
    p, calls = _run_with_fake_ssh(tmp_path, "detonate.sh", "inactive",
                                  {"SAMPLE": "/opt/pipeline/x.exe"})
    assert "STDIN: TimeoutStartSec=infinity" in calls, (
        "the installed unit has a finite start timeout; a 20-run batch outlives any")
    assert "systemctl enable" not in calls, "the front door enabled a unit"
    assert "Type=oneshot" in calls


def test_eval_busy_guard_also_blocks(tmp_path):
    p, calls = _run_with_fake_ssh(tmp_path, "eval.sh", "activating", {"ARMS": "qwen@30"})
    assert p.returncode == 1 and "already running" in p.stderr
    assert "systemctl start" not in calls
