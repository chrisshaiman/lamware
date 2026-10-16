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


# Module arguments that name a file a task writes, reads or runs.
_PATH_KEYS = ("dest", "src", "path", "cmd", "chdir", "creates", "removes")


def _tmp_references(task: dict) -> list[str]:
    """Every fixed /tmp/... name a task stages through, read off its parsed args."""
    out = []
    for mod, body in task.items():
        if not isinstance(mod, str) or not mod.startswith("ansible."):
            continue
        if isinstance(body, str):          # command/shell given as a string
            if "/tmp/" in body:
                out.append(f"{mod}: {body.strip()[:80]}")
            continue
        if not isinstance(body, dict):
            continue
        if mod.endswith(".file") and body.get("state") == "absent":
            continue                       # removing a legacy name does not follow links
        for k in _PATH_KEYS:
            v = body.get(k)
            if isinstance(v, str) and "/tmp/" in v:
                out.append(f"{mod}.{k}: {v.strip()[:80]}")
    return out


def test_no_role_stages_a_file_under_a_fixed_tmp_name():
    """The class, not the networking instance: a fixed name in the shared /tmp can
    be created first by any local user, and root then reads, runs or defines
    their file (M14). Use ansible.builtin.tempfile (or mktemp -d) instead."""
    offenders = []
    for role_dir in sorted(p for p in ROLES.iterdir() if (p / "tasks").is_dir()):
        for t in _tasks(role_dir.name):
            for ref in _tmp_references(t):
                offenders.append(f"{role_dir.name}: {t.get('name', '?')}: {ref}")
    assert not offenders, "\n".join(offenders)
