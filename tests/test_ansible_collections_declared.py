# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A deploy died on a collection nobody had declared.

    [ERROR]: couldn't resolve module/action 'community.crypto.openssh_keypair'
    Origin: ~/.ansible/roles/konstruktoid.hardening/tasks/sshconfig.yml:143

`community.crypto` is a transitive dependency of the pinned hardening role. The
role does not declare its own collection requirements, and neither did we, so
nothing installed it. It went unnoticed because `ansible` (the bundle) ships that
collection while `ansible-core` does not — the original workstation satisfied it
by accident, and a second machine running core 2.21.2 did not.

The general test below parses every FQCN out of the ansible tree and requires its
collection to be declared, so a new module in our own code cannot reintroduce
this. The role's transitive dependency gets a named test, because that one is not
discoverable from our source at all.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REQ = yaml.safe_load((ROOT / "ansible" / "requirements.yml").read_text(encoding="utf-8"))
DECLARED = {c["name"] for c in REQ.get("collections", [])}

# Shipped inside ansible-core; never needs declaring.
BUILTIN = {"ansible.builtin", "ansible.legacy"}

FQCN = re.compile(r"\b((?:community|ansible|containers|kubernetes)\.[a-z_]+)\.[a-z_]+\b")


def _collections_used_in_repo() -> set[str]:
    used = set()
    for path in (ROOT / "ansible").rglob("*"):
        if path.suffix not in {".yml", ".yaml", ".j2"} or not path.is_file():
            continue
        # roles/ vendored under packer/ are a stale copy and not what deploys
        if "konstruktoid.hardening" in str(path):
            continue
        used |= set(FQCN.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return used - BUILTIN


def test_every_collection_the_repo_uses_is_declared():
    missing = _collections_used_in_repo() - DECLARED
    assert not missing, f"used but not in ansible/requirements.yml: {sorted(missing)}"


def test_the_scan_actually_finds_collections():
    """A regex that matched nothing would make the test above pass forever."""
    used = _collections_used_in_repo()
    assert len(used) >= 4, f"only found {used} — the FQCN scan is not working"
    assert "community.general" in used


def test_the_hardening_roles_transitive_dependency_is_declared():
    """Not discoverable from our source: no file in this repo mentions
    community.crypto except requirements.yml itself. It is required by
    konstruktoid.hardening/tasks/sshconfig.yml, which we do not vendor."""
    assert "community.crypto" in DECLARED, (
        "konstruktoid.hardening calls community.crypto.openssh_keypair; "
        "ansible-core does not ship it and the role does not declare it")


@pytest.mark.parametrize("name", sorted(DECLARED))
def test_every_declared_collection_is_pinned(name):
    """An unpinned collection is the same floating-input defect as the Packer
    version (#520) and the dotnet sdk:10.0 tag (#514)."""
    entry = next(c for c in REQ["collections"] if c["name"] == name)
    assert entry.get("version"), f"{name} has no version constraint"


def test_the_pinned_role_is_version_locked():
    """The transitive dependency set is a property of the role VERSION. If the
    role floats, requirements.yml can silently become incomplete again."""
    roles = REQ.get("roles", [])
    assert roles, "no roles declared"
    for r in roles:
        assert r.get("version"), f"{r['name']} is not pinned to a version"
