# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Malware samples must not be readable by every local account (#392).

Two stores, both relying on a directory mode to gate access:

  /opt/motif/corpus/samples     755, 29/29 samples world-readable — `nobody`
                                could read one. Not managed by Ansible at all;
                                built by an ad-hoc script under a default umask.
  /opt/CAPEv2/storage/binaries  929 files at 0644 behind a 2750 directory. Not
                                reachable today, but #385 is direct evidence
                                that the gating directory does not stay put.

The lesson these encode is #385's: a permission on a child is worthless if the
parent moves, and a check that re-reads the mode it just set proves nothing.
The monitor probe therefore reads a sample **as nobody**.
"""
import re
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"
PIPELINE_TASKS = yaml.safe_load(
    (ROLES / "pipeline" / "tasks" / "main.yml").read_text(encoding="utf-8"))
CAPE_TASKS = yaml.safe_load(
    (ROLES / "cape" / "tasks" / "main.yml").read_text(encoding="utf-8"))
MONITOR_T = (ROLES / "network-monitor" / "templates"
             / "network-monitor.sh.j2").read_text(encoding="utf-8")
SANDBOX_T = (ROLES / "python-sandbox" / "templates"
             / "run-sandbox.sh.j2").read_text(encoding="utf-8")


def _named(tasks, fragment):
    return [t for t in tasks if fragment.lower() in (t.get("name") or "").lower()]


# ---------------------------------------------------------------------------
# MOTIF
# ---------------------------------------------------------------------------


def test_motif_directories_are_group_only():
    tasks = _named(PIPELINE_TASKS, "Restrict the MOTIF corpus directories")
    assert tasks, "nothing enforces the MOTIF corpus mode"
    spec = tasks[0]["ansible.builtin.file"]

    assert spec["mode"] == "2750", spec["mode"]
    assert spec["group"] == "lamware"
    assert "samples" in " ".join(str(x) for x in tasks[0]["loop"])


def test_motif_sample_files_are_not_world_readable():
    tasks = _named(PIPELINE_TASKS, "Restrict the MOTIF sample files")
    assert tasks, "sample file modes are unmanaged"
    mode = tasks[0]["ansible.builtin.file"]["mode"]

    assert mode == "0640", mode
    assert not int(mode, 8) & 0o007, f"{mode} grants access to other"


def test_motif_tasks_are_skipped_when_no_corpus_exists():
    """A host that never built a corpus must not fail the deploy."""
    for frag in ("Restrict the MOTIF corpus directories",
                 "Restrict the MOTIF sample files",
                 "Enumerate the MOTIF sample files"):
        t = _named(PIPELINE_TASKS, frag)[0]
        assert "_pipeline_motif_samples.stat.exists" in str(t.get("when")), t.get("name")


def test_the_enumerate_task_registers_what_the_restrict_task_loops_over():
    """The first draft looped over a variable nothing registered."""
    enum = _named(PIPELINE_TASKS, "Enumerate the MOTIF sample files")[0]
    restrict = _named(PIPELINE_TASKS, "Restrict the MOTIF sample files")[0]

    assert enum["register"] in str(restrict["loop"]), (
        f"{restrict['loop']!r} does not use {enum['register']!r}"
    )


def test_ansible_never_ships_motif_samples():
    """The repo is public and MOTIF is internal-use-only under the Booz Allen PL.

    Ansible owns the MODE of the corpus, never its contents.
    """
    for t in PIPELINE_TASKS:
        for mod in ("ansible.builtin.copy", "ansible.builtin.template",
                    "ansible.posix.synchronize", "ansible.builtin.unarchive"):
            spec = t.get(mod)
            if isinstance(spec, dict):
                blob = f"{spec.get('src', '')} {spec.get('dest', '')}"
                assert "motif/corpus" not in blob, t.get("name")


def test_motif_tasks_are_tagged():
    for frag in ("Restrict the MOTIF corpus directories",
                 "Restrict the MOTIF sample files"):
        assert "motif-perms" in (_named(PIPELINE_TASKS, frag)[0].get("tags") or [])


# ---------------------------------------------------------------------------
# CAPE binaries
# ---------------------------------------------------------------------------


def test_cape_sample_binaries_lose_world_access():
    tasks = _named(CAPE_TASKS, "Remove world-read from CAPE sample binaries")
    assert tasks, "the 929 sample files keep mode 0644"
    cmd = tasks[0]["ansible.builtin.command"]["cmd"]

    assert "chmod o-rwx" in cmd
    assert "storage/binaries" in cmd
    assert "cape-storage-perms" in (tasks[0].get("tags") or [])


def test_cape_binaries_task_tolerates_an_absent_store():
    """find exits 1 on a missing path; that must not fail a deploy."""
    t = _named(CAPE_TASKS, "Remove world-read from CAPE sample binaries")[0]
    assert "1" in str(t.get("failed_when")), t.get("failed_when")


# ---------------------------------------------------------------------------
# The monitor: assert the property, not the mode
# ---------------------------------------------------------------------------


def _exposure_block() -> str:
    return MONITOR_T.split("World-readable malware")[1].split("cape_storage_status\" = \"alert")[0]


def test_the_exposure_block_locator_works():
    block = _exposure_block()
    assert "exposed_samples=0" in block
    assert "queue_alert sample_exposure" in block


def test_exposure_is_confirmed_by_reading_as_nobody():
    """A mode check would pass against exactly the state we are guarding.

    A file can be 0644 and still unreachable because a parent blocks traversal
    — which is true of CAPE binaries/ today. Only an actual read settles it.
    """
    block = _exposure_block()
    assert "su -s /bin/bash -c" in block and "nobody" in block, block


def test_both_sample_stores_are_covered():
    block = _exposure_block()
    assert "storage/binaries" in block
    assert "motif" in block


def test_exposure_alert_is_urgent_and_queued():
    block = _exposure_block()
    assert "--priority urgent" in block
    assert "curl" not in block, "must go through queue_alert, not a direct push"


def test_status_file_records_the_exposure_count():
    assert "'exposed_sample_count': $exposed_samples" in MONITOR_T


# ---------------------------------------------------------------------------
# Sandbox mount narrowing
# ---------------------------------------------------------------------------


def test_sandbox_supports_named_mounts():
    assert "--data-as)" in SANDBOX_T
    assert '-v "$AS_PATH:/data/$AS_NAME:ro"' in SANDBOX_T


def _data_as_branch() -> str:
    """The --data-as case branch, ending at its own `shift 2`.

    Splitting on `;;` does not work — the branch contains a nested `case` whose
    terminators come first, so the block ended before the allowlist check and
    the test failed against correct code.
    """
    after = SANDBOX_T.split("--data-as)")[1]
    return after.split("shift 2")[0]


def test_the_branch_locator_works():
    """Guards the guard: both assertions below are scoped by this split."""
    branch = _data_as_branch()
    assert "AS_NAME" in branch, "locator missed the branch body"
    assert "--data)" not in branch, "locator leaked into the other branch"


def test_named_mounts_keep_the_allowlist():
    """--data-as must not become a way around the path allowlist."""
    assert "python_sandbox_data_allowlist" in _data_as_branch()


def test_named_mount_names_cannot_escape_data():
    """The name becomes a path component inside the container."""
    assert "*[!A-Za-z0-9_-]*" in _data_as_branch(), (
        "no character-class guard on the mount name"
    )


@pytest.mark.skipif(not Path("/bin/bash").exists(), reason="bash required")
def test_sandbox_script_still_parses():
    rendered = re.sub(r"\{\{.*?\}\}", "PLACEHOLDER", SANDBOX_T, flags=re.S)
    rendered = re.sub(r"\{%.*?%\}", "", rendered, flags=re.S)
    proc = subprocess.run(["bash", "-n"], input=rendered, text=True,
                          capture_output=True)
    assert proc.returncode == 0, proc.stderr
