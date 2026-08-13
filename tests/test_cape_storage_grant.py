# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The CAPE storage read grant, and the check that notices when it reverts (#385).

`/opt/CAPEv2/storage` was found mode 2750 owned `cape:cape` with an empty
`cape` group, so no service user could traverse it. Every directory beneath was
already `cape:lamware` and readable, and an hourly cron kept it that way — a
grant on a child, unreachable because the parent blocked the path, while every
check of the child passed. Two shipped features returned "nothing found" for
every analysis ever run.

These assert the three things that keep it from happening silently again:
the grant is `rx` and never `rwx`, it inherits rather than being repaired on a
timer, and the monitor asserts reachability *as a group member*.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"
CAPE_TASKS = yaml.safe_load(
    (ROLES / "cape" / "tasks" / "main.yml").read_text(encoding="utf-8")
)
MONITOR_T = (ROLES / "network-monitor" / "templates"
             / "network-monitor.sh.j2").read_text(encoding="utf-8")


def _acl_tasks() -> list[dict]:
    return [t for t in CAPE_TASKS if "ansible.posix.acl" in t]


def _cron(name: str) -> dict:
    for t in CAPE_TASKS:
        cron = t.get("ansible.builtin.cron")
        if cron and cron.get("name") == name:
            return t
    raise AssertionError(f"no cron task named {name!r}")


# ---------------------------------------------------------------------------
# The grant itself
# ---------------------------------------------------------------------------


def test_storage_traversal_is_granted_to_the_lamware_group():
    """Without this, nothing below storage/ is reachable by any service user."""
    grants = [t["ansible.posix.acl"] for t in _acl_tasks()
              if t["ansible.posix.acl"]["path"].endswith("/storage")]

    assert grants, "no ACL grant on the storage directory itself"
    for g in grants:
        assert g["entity"] == "lamware"
        assert g["etype"] == "group"
        assert g["state"] == "present"


def test_no_acl_grant_ever_includes_write():
    """Read-only is what makes detonation output usable as evidence.

    A pipeline process that could write into CAPE storage could plant a
    payload, and every conclusion drawn from "CAPE extracted this" would be
    forgeable. Asserted on the parsed permission string, not on prose.
    """
    for task in _acl_tasks():
        perms = task["ansible.posix.acl"]["permissions"]
        assert "w" not in perms, (
            f"{task.get('name')!r} grants {perms!r} on CAPE storage — "
            f"read-only is a security constraint, not a default"
        )


def test_grant_inherits_into_new_analysis_directories():
    """A default ACL, so new analyses are readable at creation."""
    defaults = [t["ansible.posix.acl"] for t in _acl_tasks()
                if t["ansible.posix.acl"].get("default")]

    assert defaults, "no default ACL — new analysis dirs will not inherit"
    assert any(d["path"].endswith("/storage/analyses") for d in defaults)


def test_existing_analyses_are_covered_too():
    """`default` only affects directories created afterwards."""
    recursive = [t["ansible.posix.acl"] for t in _acl_tasks()
                 if t["ansible.posix.acl"].get("recursive")]

    assert recursive, "default ACL alone leaves the existing corpus unreadable"


def test_grant_tasks_are_tagged_for_surgical_reapply():
    """The grant must be reappliable without re-running the whole cape role."""
    for task in _acl_tasks():
        assert "cape-storage-perms" in (task.get("tags") or []), task.get("name")


# The tag DEPLOYMENT.md tells operators to run. A task outside it does not
# exist as far as that command is concerned.
FEATURE_TAG = "cape-storage-perms"

# Every task this feature owns, by name fragment. Correct task content is
# worthless if the documented deploy cannot reach the task — which is exactly
# what happened: both cron tasks were written correctly, left untagged, and
# `make deploy TAGS=cape-storage-perms,...` skipped them. The duplicate cron
# kept running and the chgrp repair stayed in place, while every assertion
# about their YAML passed.
FEATURE_TASKS = (
    "Set CAPE storage directories to lamware group",
    "Install acl",
    "Grant the lamware group traversal",
    "Make the lamware grant inherit",
    "Apply the lamware grant to existing",
    "Verify a lamware-group service user",
    "Remove the superseded cape-memory-dump-cleanup",
    "Schedule CAPE storage maintenance",
)


def _reachable_under(tag: str) -> set[str]:
    """Task names Ansible would run for `--tags <tag>`."""
    return {t["name"] for t in CAPE_TASKS if tag in (t.get("tags") or [])}


def test_every_feature_task_is_reachable_by_the_documented_deploy():
    reachable = _reachable_under(FEATURE_TAG)
    missing = [
        frag for frag in FEATURE_TASKS
        if not any(frag.lower() in name.lower() for name in reachable)
    ]
    assert not missing, (
        f"tasks not reachable under --tags {FEATURE_TAG}: {missing}. "
        f"They will be silently skipped by the deploy the docs prescribe."
    )


def test_the_reachability_helper_discriminates():
    """Positive control: the helper must not report everything as reachable."""
    reachable = _reachable_under(FEATURE_TAG)
    all_names = {t["name"] for t in CAPE_TASKS}

    assert reachable, "helper found no tagged tasks at all"
    assert reachable < all_names, (
        "helper reports every task as reachable — it is not filtering on tags"
    )


def test_reachability_is_verified_as_a_group_member():
    """The verify step must exercise the grant, not re-read the mode it set.

    Re-reading the mode would have passed against exactly the broken state —
    the mode was 2750 throughout; only the group changed.
    """
    verify = [t for t in CAPE_TASKS
              if "reach a payload directory" in (t.get("name") or "")]
    assert verify, "no reachability verification task"
    task = verify[0]

    assert task.get("become_user") == "pipeline", (
        "verification must run as a real member of the lamware group"
    )
    body = task["ansible.builtin.shell"]
    assert "ls -1" in body, "must actually list a payload directory"


# ---------------------------------------------------------------------------
# Repair loop replaced by inheritance
# ---------------------------------------------------------------------------


def test_maintenance_cron_no_longer_repairs_permissions():
    """Inheritance replaced it. The cron was up to an hour late, every time.

    A sample detonated at 09:16 had unreadable payloads until 10:15, and the
    pipeline reads them minutes after detonation.
    """
    job = _cron("cape-storage-maintenance")["ansible.builtin.cron"]["job"]

    assert "chgrp" not in job, "permission repair should come from the default ACL"
    assert "chmod" not in job
    assert "memory.dmp" in job, "retention is genuinely periodic work; keep it"


def test_the_duplicate_cron_entry_is_removed():
    """cron keys on name, so the rename left the old entry running forever."""
    old = _cron("cape-memory-dump-cleanup")["ansible.builtin.cron"]
    assert old.get("state") == "absent", (
        f"the superseded entry is still being installed: {old!r}"
    )


def test_only_one_cron_still_deletes_memory_dumps():
    """Positive control for the above: no third copy of the same work."""
    active = [
        t for t in CAPE_TASKS
        if (c := t.get("ansible.builtin.cron"))
        and c.get("state") != "absent"
        and "memory.dmp" in (c.get("job") or "")
    ]
    assert len(active) == 1, [t.get("name") for t in active]


# ---------------------------------------------------------------------------
# The monitor check — the part that makes a revert visible
# ---------------------------------------------------------------------------


def _probe_block() -> str:
    body = MONITOR_T.split("CAPE storage reachability")[1]
    return body.split("Save baseline")[0]


def test_the_probe_block_locator_works():
    """Guards the guard: every assertion below is scoped by this split."""
    block = _probe_block()
    assert 'cape_storage_status="ok"' in block
    assert "api_process_status" not in block, "split leaked into the previous check"


def test_every_probe_command_drops_to_the_pipeline_user():
    """Root can always read it, so a root-run probe can never fail.

    Asserts on each command that reads CAPE storage, not on the presence of
    the string anywhere in the block — the first version of this test passed
    with the probe rewritten to run as root, because a *second* `su` further
    down still satisfied a substring check.
    """
    block = _probe_block()

    # The probe assignment itself must drop privileges. Scoped to the
    # assignment so a `su` anywhere else in the block cannot satisfy it.
    assignment = block.split("probe_dir=", 1)[1].split("\n\n", 1)[0]
    assert "su -s /bin/bash -c" in assignment and "pipeline" in assignment, (
        f"the probe must run as the pipeline user, got:\n{assignment}"
    )

    # The listing check is the second privileged read.
    listing = [ln for ln in block.splitlines() if "ls -1 '$probe_dir'" in ln]
    assert listing, "no listing check found"
    for ln in listing:
        assert "su -s /bin/bash -c" in ln and "pipeline" in ln, ln

    # Exactly one read is deliberately run as root: distinguishing "unreadable"
    # from "nothing detonated yet". More than one means a probe lost its `su`.
    assert block.count("su -s /bin/bash -c") == 2, (
        f"expected 2 unprivileged reads, found {block.count('su -s /bin/bash -c')}"
    )


def test_monitor_distinguishes_unreadable_from_never_detonated():
    """An empty corpus is not an alert; an unreadable one is."""
    probe = MONITOR_T.split("CAPE storage reachability")[1]
    assert 'cape_storage_status="empty"' in probe
    assert 'cape_storage_status="alert"' in probe


def test_monitor_queues_an_alert_rather_than_pushing_directly():
    """#378: direct pushes fire every 5 minutes. Queued alerts are edge-triggered."""
    probe = MONITOR_T.split("CAPE storage reachability")[1]
    assert "queue_alert cape_storage" in probe
    assert "curl" not in probe.split("Save baseline")[0]


def test_status_file_records_the_result():
    """The dashboard and any later audit need the state, not just a push."""
    assert "'cape_storage_status': '$cape_storage_status'" in MONITOR_T
    assert "'cape_storage_problem'" in MONITOR_T


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_monitor_script_is_syntactically_valid():
    """The probe uses su, globs and a nested $( ) — parse it, don't eyeball it."""
    # Substitute the Jinja away: every {{ ... }} becomes a literal token, so
    # what bash parses is the shape of the script rather than the template.
    rendered = re.sub(r"\{\{.*?\}\}", "PLACEHOLDER", MONITOR_T, flags=re.S)
    rendered = re.sub(r"\{%.*?%\}", "", rendered, flags=re.S)

    proc = subprocess.run(["bash", "-n"], input=rendered, text=True,
                          capture_output=True)
    assert proc.returncode == 0, proc.stderr
