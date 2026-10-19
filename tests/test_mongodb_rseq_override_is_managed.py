# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""MongoDB's rseq drop-in is shipped by the role, not hand-made on the host (#528).

CAPE's installer writes its own mongodb.service with
`GLIBC_TUNABLES=glibc.pthread.rseq=0`; MongoDB 8.0.21's TCMalloc then refuses
kernels 6.19+ (SERVER-121912). The fix measured on 2026-09-02 was a drop-in
restoring rseq=1, and it lived only on the host for six weeks. Structural: the
role must ship exactly that drop-in and restart the unit when it changes. Only
a boot into a current kernel observes the property itself.
"""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROLE = Path(__file__).resolve().parents[1] / "ansible" / "roles" / "mongodb"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
HANDLERS = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))


def _dropin():
    for t in TASKS:
        c = t.get("ansible.builtin.copy")
        if isinstance(c, dict) and c.get("dest") == "/etc/systemd/system/mongodb.service.d/override.conf":
            return t
    raise AssertionError("the role does not ship the mongodb.service drop-in")


def test_the_dropin_restores_rseq():
    content = _dropin()["ansible.builtin.copy"]["content"]
    assert 'Environment="GLIBC_TUNABLES=glibc.pthread.rseq=1"' in content
    assert "[Service]" in content
    assert "rseq=0" not in content


def test_a_changed_dropin_restarts_the_unit_after_a_daemon_reload():
    task = _dropin()
    assert "Reload systemd and restart MongoDB" in task.get("notify", [])
    h = next(h for h in HANDLERS if h["name"] == "Reload systemd and restart MongoDB")
    unit = h["ansible.builtin.systemd"]
    assert unit["name"] == "mongodb" and unit["state"] == "restarted"
    assert unit.get("daemon_reload") is True, "a drop-in is not read until daemon-reload"


def test_the_dropin_directory_is_created_first():
    names = [t.get("name", "") for t in TASKS]
    mk = next(i for i, t in enumerate(TASKS)
              if isinstance(t.get("ansible.builtin.file"), dict)
              and t["ansible.builtin.file"].get("path") == "/etc/systemd/system/mongodb.service.d")
    assert mk < TASKS.index(_dropin()), names
