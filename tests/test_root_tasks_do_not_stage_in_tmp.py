# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Root-run tasks must not stage files they then act on in the shared /tmp (M14).

Structural: the property is about where a file lives between two root tasks.
The host /tmp is the shared sticky one (a per-user TMPDIR is only an
environment variable), so any local user can create names there first.
"""
from pathlib import Path

import yaml

ROLES = Path(__file__).resolve().parents[1] / "ansible" / "roles"


def _tasks(role: str):
    def walk(ts):
        for t in ts or []:
            if isinstance(t, dict):
                yield t
                for k in ("block", "rescue", "always"):
                    yield from walk(t.get(k))
    for f in (ROLES / role / "tasks").glob("*.yml"):
        yield from walk(yaml.safe_load(f.read_text()))


def test_the_detonation_network_xml_is_not_staged_in_tmp():
    for t in _tasks("networking"):
        for mod in ("ansible.builtin.template", "ansible.builtin.copy"):
            body = t.get(mod)
            if isinstance(body, dict) and "detonation-network" in str(body.get("src", "")):
                assert not str(body["dest"]).startswith("/tmp/"), body["dest"]
                assert body.get("owner") == "root" and body.get("mode") == "0600"
        cmd = t.get("ansible.builtin.command")
        if isinstance(cmd, str) and "net-define" in cmd:
            assert "/tmp/" not in cmd, cmd
