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
PIPE_TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text(encoding="utf-8"))
PIPE_NAMES = [t.get("name", "") for t in PIPE_TASKS]


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


def _pipe_index(fragment: str) -> int:
    for i, n in enumerate(PIPE_NAMES):
        if fragment.lower() in n.lower():
            return i
    raise AssertionError(f"no pipeline task matching {fragment!r}")


def test_the_sysctl_file_outsorts_the_hardening_drop_ins():
    """The filename decides who wins. sysctl.d merges by name across /etc, /run
    and /usr/lib, and konstruktoid ships zz-main-hardening.conf (userns = 0) and
    zz-apparmor-hardening.conf (restrict = 1). "99-podman.conf" sorts BEFORE
    both, so it lost silently on every boot while sitting there looking right."""
    tasks = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "podman" / "tasks" / "main.yml").read_text(encoding="utf-8"))
    sysctl = next(t for t in tasks if "ansible.posix.sysctl" in t)
    path = sysctl["ansible.posix.sysctl"]["sysctl_file"]
    name = path.rsplit("/", 1)[-1]
    for loser in ("zz-main-hardening.conf", "zz-apparmor-hardening.conf"):
        assert name > loser, (
            f"{name} sorts before {loser}, so the hardening value wins and "
            f"rootless podman stays broken")


def test_all_three_userns_settings_are_applied():
    """Three independent blocks, each masking the next. Setting only the two
    obvious ones leaves containers unable to mount their overlay."""
    tasks = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "podman" / "tasks" / "main.yml").read_text(encoding="utf-8"))
    sysctl = next(t for t in tasks if "ansible.posix.sysctl" in t)
    keys = {i["key"] for i in sysctl["loop"]}
    assert keys == {
        "user.max_user_namespaces",
        "kernel.unprivileged_userns_clone",
        "kernel.apparmor_restrict_unprivileged_userns",
    }, f"missing a userns setting: {sorted(keys)}"


def test_the_probe_overrides_the_image_entrypoint():
    """`podman run <image> true` does NOT run `true` when the image declares an
    ENTRYPOINT — the entrypoint runs and the argument is handed to IT.

    The interpret image's entrypoint exits 1 on a missing API key, so the first
    version of this preflight reported "podman cannot start a container" and
    aborted a deploy while podman was working perfectly. A guard that cries wolf
    gets switched off, and then the real outage goes unnoticed again."""
    task = PIPE_TASKS[_pipe_index("Start a real container")]
    cmd = str(task.get("ansible.builtin.command", ""))
    assert "--entrypoint" in cmd, (
        "the probe runs the image's own entrypoint, so its exit code says "
        "nothing about whether podman can start a container")


def test_only_podmans_own_failure_code_fails_the_deploy():
    """podman separates the two cases exactly:

        125  podman itself could not run the container   <- the real outage
        126  the command could not be invoked            <- image property
        127  the command was not found                   <- image property
        *    the container ran and exited with its own code

    The broken state returned 125. Asserting rc == 0 instead conflates a
    container that started and exited non-zero with podman being unable to
    start one at all."""
    task = PIPE_TASKS[_pipe_index("Fail when the analysis containers cannot run")]
    conditions = " ".join(str(c) for c in task["ansible.builtin.assert"]["that"])
    assert "!= 125" in conditions, (
        "the assert does not key on podman's own failure code; any container "
        "exiting non-zero will abort the deploy")
    assert "== 0" not in conditions.replace("length > 0", ""), (
        "the assert still requires a zero container exit code")


def test_the_pipeline_preflight_starts_a_container():
    """`podman --version` is NOT enough -- measured: it returned 4.9.3 while
    run-triage still died with "cannot clone". Only starting a container
    exercises all three layers."""
    task = PIPE_TASKS[_pipe_index("Start a real container")]
    cmd = str(task.get("ansible.builtin.command", ""))
    assert "podman run" in cmd, f"the preflight does not start a container: {cmd}"
    assert task.get("become_user") == "pipeline"


def test_the_preflight_fails_the_deploy_and_refuses_to_pass_vacuously():
    """No images means the check verified nothing, which must not read as
    success -- that is the same shape as the bug it guards against."""
    task = PIPE_TASKS[_pipe_index("Fail when the analysis containers cannot run")]
    conditions = " ".join(str(c) for c in task["ansible.builtin.assert"]["that"])
    assert "pipeline_container_check.rc" in conditions, "the container exit code is not asserted"
    assert "pipeline_images.stdout_lines | length > 0" in conditions, \
        "an empty image list would pass this preflight without checking anything"
