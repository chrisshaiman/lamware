# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE carries two local patches, and one of them is load-bearing.

CAPE is installed by upstream's cape2.sh and is NOT version-pinned, so any
upgrade replaces its tree wholesale. Both patches lived only on the host until
#607 — discovered during the 2026-09-16 upgrade because `git status` in
/opt/CAPEv2 showed modified tracked files nobody had recorded.

0001 fixes CAPEv2#3006 (2026-05-11), which added Explorer parent-process
spoofing to every sample launch. All four error paths in
build_parent_attribute_list() log and then CONTINUE, so on a guest with no
interactive shell GetShellWindow() returns NULL, OpenProcess fails, and a NULL
handle reaches CreateProcessW as ERROR_INVALID_HANDLE.

The failure is total and silent. Every analysis completes "successfully" with
0 processes and 0 API calls, and CAPE blames the analysis package. Measured on
this host: 0 processes before the patch, 7 processes and ~130k API calls after.

0002 is a LibreOffice fallback for the Office packages when MS Word is absent.
It predates lamware's git history and survived the upgrade only because upstream
happened not to touch those files.

These tests assert the role SHIPS and VERIFIES the patches. They deliberately do
not check the patch contents line by line — that would break on any upstream
context shift while proving nothing about whether the patch is applied.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "cape"
PATCH_DIR = ROLE / "files" / "patches"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))

PATCHES = [
    "0001-analyzer-parent-spoofing-fallback.patch",
    "0002-office-libreoffice-fallback.patch",
]


def _task(fragment):
    for t in TASKS:
        if fragment.lower() in (t.get("name") or "").lower():
            return t
    raise AssertionError(f"no cape task matching {fragment!r}")


@pytest.mark.parametrize("name", PATCHES)
def test_patch_file_exists_and_is_a_patch(name):
    p = PATCH_DIR / name
    assert p.exists(), f"{name} is not in the repo — it would live only on the host"
    body = p.read_text(encoding="utf-8")
    assert body.startswith("diff --git"), "not a unified diff"
    assert "@@" in body, "no hunks — an empty patch applies cleanly and does nothing"


def test_the_role_applies_both_patches():
    task = _task("Apply CAPE local patches")
    assert task.get("ansible.posix.patch"), "not using the patch module"
    assert sorted(task.get("loop") or []) == sorted(PATCHES), \
        "the apply loop does not cover both patches"


def test_apply_is_idempotent_and_anchored_to_the_install_dir():
    spec = _task("Apply CAPE local patches")["ansible.posix.patch"]
    assert spec.get("state") == "present", "state must be present for idempotency"
    assert spec.get("strip") == 1, "patches are git-format, they need strip: 1"
    assert "cape_install_dir" in str(spec.get("basedir")), \
        "basedir must follow cape_install_dir, not a hardcoded path"


def test_the_load_bearing_patch_is_verified_after_applying():
    """The whole point. A patch that silently stops applying leaves the sandbox
    detonating nothing while reporting success — which is exactly the class of
    failure this role keeps hitting. Assert on a marker the patch introduces,
    not on the patch command's exit code."""
    task = _task("Verify the parent-spoofing fallback")
    cmd = str(task.get("ansible.builtin.command", {}).get("cmd", ""))
    assert "Parent-process spoofing unavailable" in cmd, \
        "verification does not look for the string the patch adds"
    assert "process.py" in cmd, "verification does not check the patched file"
    assert task.get("failed_when"), "verification cannot fail, so it is not a check"


def test_verification_runs_after_the_patches_are_applied():
    names = [(t.get("name") or "") for t in TASKS]
    apply_i = next(i for i, n in enumerate(names) if "Apply CAPE local patches" in n)
    verify_i = next(i for i, n in enumerate(names) if "Verify the parent-spoofing" in n)
    assert verify_i > apply_i, "verification runs before the patch is applied"


def test_the_marker_string_matches_between_patch_and_verification():
    """If the patch is reworded and the check is not, the check passes forever
    against a file that no longer contains the fix."""
    patch = (PATCH_DIR / PATCHES[0]).read_text(encoding="utf-8")
    cmd = str(_task("Verify the parent-spoofing")["ansible.builtin.command"]["cmd"])
    marker = "Parent-process spoofing unavailable"
    assert marker in patch, "the patch no longer adds the string the check greps for"
    assert marker in cmd


# --- the staging directory must exist before anything copies into it ---------

def _cape_tasks():
    import yaml
    return yaml.safe_load(
        (ROOT / "ansible" / "roles" / "cape" / "tasks" / "main.yml").read_text())


def _index_of(tasks, predicate):
    for i, t in enumerate(tasks):
        if isinstance(t, dict) and predicate(t):
            return i
    return None


def test_the_patch_staging_directory_is_created_before_it_is_used():
    """ansible.builtin.copy does not create intermediate directories.

    Without an explicit file: task the role aborts on any host that has never
    had .lamware-patches -- which was every host, because these tasks had never
    run: the deploy that appeared to verify them came from a branch that
    predated them. The abort happened BEFORE the role's own patch verification,
    so the guard protecting the load-bearing patch never executed either.

    Asserted on parsed task order, not on the file's text.
    """
    tasks = _cape_tasks()

    mkdir_at = _index_of(tasks, lambda t: (
        isinstance(t.get("ansible.builtin.file"), dict)
        and ".lamware-patches" in str(t["ansible.builtin.file"].get("path", ""))
        and t["ansible.builtin.file"].get("state") == "directory"))
    copy_at = _index_of(tasks, lambda t: (
        isinstance(t.get("ansible.builtin.copy"), dict)
        and ".lamware-patches" in str(t["ansible.builtin.copy"].get("dest", ""))))

    assert copy_at is not None, "nothing stages the patches any more"
    assert mkdir_at is not None, (
        ".lamware-patches is copied into but never created; copy: does not "
        "create intermediate directories, so the role aborts on a fresh host")
    assert mkdir_at < copy_at, (
        f"the staging directory is created at task {mkdir_at} but copied into "
        f"at task {copy_at} -- ordering is wrong")


def test_the_patch_verification_still_runs_after_applying():
    """The abort this fixes happened upstream of the verification step, so the
    guard on the load-bearing patch never ran. Keep the order honest."""
    tasks = _cape_tasks()
    apply_at = _index_of(tasks, lambda t: "ansible.posix.patch" in t)
    verify_at = _index_of(tasks, lambda t: (
        "Parent-process spoofing unavailable" in str(t.get("ansible.builtin.command", ""))
        or "Parent-process spoofing unavailable" in str(t.get("ansible.builtin.shell", ""))))
    assert apply_at is not None, "the patches are no longer applied"
    assert verify_at is not None, "the load-bearing patch is no longer verified"
    assert apply_at < verify_at, "the patches are verified before they are applied"
