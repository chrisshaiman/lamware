# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every containerized analysis stage dies silently if podman cannot run (#576).

Ubuntu ships naming-only AppArmor profiles for podman and crun: they carry
flags=(unconfined) and their bodies hold no file rules, so the profile exists
only to give the process a label. Strip the flag and the identical profile
denies everything. On 2026-09-02 every profile on the sandbox was put into
enforce and /etc/apparmor.d/disable/ was emptied, and podman lost /proc:

    openat("/proc/self/cmdline", O_RDONLY) = -1 EACCES
    cannot retrieve cmd line

Twelve analysis tools are rootless podman containers. All twelve were dead for
five days and nothing said so -- run-pipeline still exited 0 and wrote a
CAPE-only report. The damage was not the missing enrichment but that triage no
longer set the submission filename or package, so samples went to CAPE as
<sha>.bin with package=auto instead of <name>.exe with package=exe. That is a
different detonation, which invalidated a corpus comparison.

The role's own aa-disable task CANNOT fail (aa-disable exits non-zero when the
profile is already disabled, so failed_when: false is mandatory). These tests
exist because that task looks like a guard and is not one.
"""
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "podman" / "tasks" / "main.yml").read_text(encoding="utf-8"))
NAMES = [t.get("name", "") for t in TASKS]


def _index(fragment: str) -> int:
    for i, n in enumerate(NAMES):
        if fragment.lower() in n.lower():
            return i
    raise AssertionError(f"no task matching {fragment!r}; tasks={NAMES}")


def test_podman_is_actually_executed_not_just_installed():
    """A guard that checks a proxy -- the profile file, the disable symlink --
    passes while podman itself is broken. Run the binary."""
    task = TASKS[_index("Verify Podman actually runs")]
    cmd = str(task.get("ansible.builtin.command", "")).split()
    # the EXECUTABLE must be podman. Substring matching passes for
    # `test -f /etc/apparmor.d/disable/podman`, which is the proxy check this
    # test exists to reject -- verified by mutation.
    assert cmd and cmd[0] == "podman", \
        f"the verify task does not execute podman itself: {' '.join(cmd)}"


def test_it_runs_as_the_user_that_will_actually_use_it():
    """podman worked for neither root nor pipeline here, but the two can differ --
    rootless setup is per-user, so checking as root would have passed while
    every tool stayed broken."""
    task = TASKS[_index("Verify Podman actually runs")]
    assert task.get("become_user") == "pipeline", \
        "podman is verified as the wrong user; the tools run as `pipeline`"


def test_the_failure_actually_fails_the_deploy():
    """The verify task registers with failed_when: false so the assert can
    produce a readable message -- which means the assert is the only thing
    standing between a broken podman and a green deploy."""
    task = TASKS[_index("Fail when Podman cannot run")]
    block = task.get("ansible.builtin.assert")
    assert block, "no assert task"
    conditions = [str(c) for c in block.get("that", [])]
    joined = " ".join(conditions)
    assert "podman_check.rc" in joined, "the assert does not check podman's exit code"
    # BOTH streams. podman wrote "cannot retrieve cmd line" to stdout here, but
    # dropping either check individually left the other matching a bare
    # substring search, so this asserts each stream separately.
    for stream in ("stdout", "stderr"):
        assert any("cannot retrieve cmd line" in c and stream in c for c in conditions), \
            f"the assert does not catch the AppArmor symptom on {stream}"


def test_the_guard_runs_after_the_thing_it_guards():
    """Verifying before aa-disable would test the pre-fix state."""
    assert _index("Disable AppArmor profiles") < _index("Verify Podman actually runs")
    assert _index("Verify Podman actually runs") < _index("Fail when Podman cannot run")


def test_the_disable_task_is_not_mistaken_for_a_guard():
    """It must stay failed_when: false -- aa-disable is non-zero when already
    disabled -- so this records WHY it cannot be the check."""
    task = TASKS[_index("Disable AppArmor profiles")]
    assert task.get("failed_when") is False, \
        "if aa-disable can now fail, re-read whether the separate guard is still needed"
