# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Source tarballs are staged through private temp directories, not fixed /tmp names (#537).

Structural, by necessity: the property is about what Ansible does on the
deploy host, which no unit test can run. It is checked on the parsed task
files (yaml.safe_load), not by grepping text, so a comment that mentions /tmp
cannot satisfy or break it.

Why it matters: the pipeline and api roles used /tmp/lamware-pkg-src.tar.gz and
/tmp/api-src.tar.gz on both the controller and the host. On the host,
`ansible.builtin.copy` keeps the ownership of whatever already sits at dest
(module_utils.basic.atomic_move chowns the new file to the old one's uid), so a
local user who pre-created the name owned the uploaded archive and could
rewrite it before root unpacked it into the tree both venvs pip-install. On the
controller, `tar czf` followed a symlink planted there.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

# role -> (block name, tarball file name)
STAGING = {
    "pipeline": ("Stage the package source through private temp directories", "lamware-pkg-src.tar.gz"),
    "api": ("Stage the api source through private temp directories", "api-src.tar.gz"),
}


def _tasks(role: str) -> list[dict]:
    return yaml.safe_load((ROOT / "ansible" / "roles" / role / "tasks" / "main.yml").read_text())


def _walk(obj):
    """Every string value anywhere in a parsed task tree."""
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)
    elif isinstance(obj, str):
        yield obj


def _block(role: str) -> dict:
    name, _ = STAGING[role]
    matches = [t for t in _tasks(role) if t.get("name") == name]
    assert len(matches) == 1, f"{role}: staging block {name!r} not found"
    return matches[0]


@pytest.mark.parametrize("role", sorted(STAGING))
def test_no_task_in_the_role_names_a_fixed_tmp_path(role):
    bad = [s for s in _walk(_tasks(role)) if "/tmp/" in s or s.strip() == "/tmp"]
    assert bad == [], f"{role} writes or reads a fixed path in the shared /tmp: {bad}"


@pytest.mark.parametrize("role", sorted(STAGING))
def test_the_tarball_lives_in_a_registered_tempfile_directory(role):
    blk = _block(role)
    _, tarball = STAGING[role]
    by_module = {}
    for t in blk["block"]:
        for mod in ("ansible.builtin.tempfile", "ansible.builtin.command",
                    "ansible.builtin.copy", "ansible.builtin.unarchive"):
            if mod in t:
                by_module.setdefault(mod, []).append(t)
    temps = by_module["ansible.builtin.tempfile"]
    assert len(temps) == 2 and all(t[m]["state"] == "directory" for t in temps
                                   for m in ["ansible.builtin.tempfile"])
    local = next(t for t in temps if t.get("delegate_to") == "localhost")["register"]
    remote = next(t for t in temps if "delegate_to" not in t)["register"]

    tar = next(t for t in by_module["ansible.builtin.command"]
               if "tar czf" in t["ansible.builtin.command"]["cmd"])
    assert f"tar czf {{{{ {local}.path }}}}/{tarball}" in tar["ansible.builtin.command"]["cmd"]

    (copy,) = by_module["ansible.builtin.copy"]
    assert copy["ansible.builtin.copy"]["src"] == f"{{{{ {local}.path }}}}/{tarball}"
    assert copy["ansible.builtin.copy"]["dest"] == f"{{{{ {remote}.path }}}}/{tarball}"

    (unarchive,) = by_module["ansible.builtin.unarchive"]
    assert unarchive["ansible.builtin.unarchive"]["src"] == f"{{{{ {remote}.path }}}}/{tarball}"
    assert unarchive["ansible.builtin.unarchive"]["remote_src"] is True


@pytest.mark.parametrize("role", sorted(STAGING))
def test_both_temp_directories_are_removed_even_on_failure(role):
    blk = _block(role)
    removed = {}
    for t in blk.get("always", []):
        f = t.get("ansible.builtin.file", {})
        if f.get("state") == "absent":
            removed[f["path"]] = t.get("delegate_to")
    regs = {t["register"]: t.get("delegate_to") for t in blk["block"] if "ansible.builtin.tempfile" in t}
    for reg, where in regs.items():
        path = f"{{{{ {reg}.path }}}}"
        assert path in removed, f"{role}: {reg} is never removed"
        assert removed[path] == where, f"{role}: {reg} is removed on the wrong machine"
