# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The MongoDB upgrade is pinned, dumped first, verified after, and single-instance (#528).

Structural: the role must pin every mongodb-org package to one version, dump
the cuckoo database before the package set changes version, mask the package's
mongod.service (CAPE's mongodb.service is the instance; a resurrected
mongod.service would serve an empty /var/lib/mongodb on the same port), start
only that unit, and read the version back from the running server after the
restart. Only a deploy observes the upgrade itself.
"""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROLE = Path(__file__).resolve().parents[1] / "ansible" / "roles" / "mongodb"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
NAMES = [t.get("name", "") for t in TASKS]


def _idx(fragment: str) -> int:
    return next(i for i, n in enumerate(NAMES) if fragment in n)


def test_every_mongodb_package_is_pinned_to_one_version():
    apt = TASKS[_idx("Install MongoDB at the pinned version")]["ansible.builtin.apt"]
    names = apt["name"]
    assert len(names) == 7
    assert all(n.endswith("={{ mongodb_version }}") for n in names), names
    assert apt.get("allow_downgrade") is True, "the rollback is the previous pin and a redeploy"
    assert DEFAULTS["mongodb_version"].startswith("8.0.")


def test_the_dump_precedes_the_install_and_only_runs_on_a_version_change():
    dump = TASKS[_idx("Dump the cuckoo database")]
    assert _idx("Dump the cuckoo database") < _idx("Install MongoDB at the pinned version")
    cmd = dump["ansible.builtin.shell"]["cmd"]
    assert "mongodump" in cmd and "--db cuckoo" in cmd and "--gzip" in cmd
    assert "mongodb_installed.stdout != mongodb_version" in " ".join(dump["when"])


def test_the_packages_own_unit_is_masked_and_only_capes_unit_is_started():
    mask = TASKS[_idx("Mask the package's mongod.service")]["ansible.builtin.systemd"]
    assert mask == {"name": "mongod", "masked": True}
    start = TASKS[_idx("Enable and start MongoDB")]["ansible.builtin.systemd"]
    assert start["name"] == "{{ mongodb_unit }}" and DEFAULTS["mongodb_unit"] == "mongodb"
    assert "loop" not in TASKS[_idx("Enable and start MongoDB")]


def test_the_version_is_read_from_the_running_server_after_the_restart():
    verify = TASKS[_idx("Verify the running server is the pinned version")]
    assert _idx("Flush handlers") < _idx("Verify the running server is the pinned version")
    assert "db.version()" in verify["ansible.builtin.command"]
    assert "mongodb_version" in verify["failed_when"]
