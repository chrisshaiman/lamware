# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The qemu-patched role must be safe to run on a host where CAPE is installed.

Structural, on purpose: the thing guarded against is RUNNING this role on the
real host, which would reset CAPE or install a planted hypervisor, so these parse
the role and assert on task values instead. The host behaviour is the deploy
evidence in the PR.

1. It force-cloned CAPEv2 at a 2026-04 pin on every run. The live tree is
   upgraded by cape2.sh and carries local patches, one load-bearing (without it
   every detonation completes with zero processes). Any run of this role, or of
   `all`, would have reset it.
2. It installed /usr/bin/qemu-system-x86_64 from a fixed path in the shared /tmp,
   which no longer exists after the one-time build and which any local user can
   recreate.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "qemu-patched" / "tasks" / "main.yml").read_text())


def _flat(tasks):
    for t in tasks:
        if isinstance(t, dict):
            yield t
            for key in ("block", "rescue", "always"):
                if isinstance(t.get(key), list):
                    yield from _flat(t[key])


ALL = list(_flat(TASKS))


def _named(name: str) -> dict:
    return next(t for t in ALL if t.get("name") == name)


def test_the_cape_clone_never_touches_an_installed_tree():
    clone = next(t for t in ALL if "ansible.builtin.git" in t)
    assert "not qemu_patched_cape_tree.stat.exists" in str(clone.get("when")), (
        "a force:true clone at a pin resets the installed, upgraded, patched CAPE tree")
    check = _named("Check whether a CAPEv2 tree is already installed")
    assert check["ansible.builtin.stat"]["path"].endswith("/.git")
    assert ALL.index(check) < ALL.index(clone)


def test_git_is_only_installed_for_that_clone():
    git = _named("Install git")
    assert "not qemu_patched_cape_tree.stat.exists" in str(git.get("when"))


def test_no_task_installs_or_copies_anything_from_tmp():
    for t in ALL:
        for module in ("ansible.builtin.copy", "ansible.builtin.file"):
            body = t.get(module)
            if isinstance(body, dict) and str(body.get("src", "")).startswith("/tmp/"):
                raise AssertionError(f"{t.get('name')!r} reads {body['src']} from the shared /tmp")


def test_the_emulator_comes_from_the_checked_preserved_copy():
    install = next(t for t in ALL
                   if isinstance(t.get("ansible.builtin.copy"), dict)
                   and t["ansible.builtin.copy"].get("dest") == "/usr/bin/qemu-system-x86_64")
    assert install["ansible.builtin.copy"]["src"] == "{{ qemu_patched_preserved_path }}"
    assert install["ansible.builtin.copy"]["owner"] == "root"
    refuse = _named("Refuse a preserved emulator that is missing or not root's alone")
    that = " ".join(refuse["ansible.builtin.assert"]["that"])
    for cond in ("isreg", "not qemu_patched_preserved_bin.stat.islnk",
                 "pw_name == 'root'", "not qemu_patched_preserved_bin.stat.wgrp",
                 "not qemu_patched_preserved_bin.stat.woth"):
        assert cond in that, cond
    assert ALL.index(refuse) < ALL.index(install)
    assert "checksum" in str(install.get("when")), "copy only when the binaries differ"
