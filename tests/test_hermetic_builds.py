# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Image builds reach no network; package managers install only what was fetched (ADR-023).

Structural, and only because the property is not observable from here: whether
a build reached the network is decided on the host, at deploy time. The deploy
is the behavioural check (`podman build --network=none` fails on any fetch, and
the build-context label assert fails a build that kept an old image). These
tests are the record of which roles have been moved, and keep that list from
silently growing back.

The pdf-generation image stayed at 2026-05-17 for five months: its build ran
`pip install weasyprint` as pipeline, which has no DNS, failed, and the old image
kept serving PDFs.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"

# Roles that still build with network access, each to be moved by its own PR
# (ADR-023 Consequences). This list must only shrink: a role that is migrated
# and left here fails test_the_pending_list_only_shrinks.
PACKAGE_MIGRATION_PENDING = {
    "dotnet-analysis", "ghidra", "go-analysis", "interpret", "java-analysis",
    "office-macro-analysis", "pcap-analysis", "powershell-analysis",
    "pyinstaller-analysis", "python-sandbox", "screenshot-analysis", "triage",
    "volatility",
}
MIGRATED = {"pdf-generation"}

# A package manager reaching an index or mirror. `pip install --no-index` and
# `dpkg -i` of fetched files do not.
_NETWORK_INSTALL = re.compile(
    r"apt-get\s+(update|install)|apt\s+install|pip3?\s+install(?![^\n]*--no-index)"
    r"|dotnet\s+tool\s+install|npm\s+(install|ci)|go\s+(get|mod\s+download)|gem\s+install")
_DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}\Z")


def _build_tasks() -> dict[str, list[str]]:
    """role -> the command line of every task that runs `podman build`."""
    out: dict[str, list[str]] = {}
    for path in ROLES.glob("*/tasks/*.yml"):
        role = path.parts[-3]
        for task in yaml.safe_load(path.read_text()) or []:
            for t in task.get("block", [task]) + task.get("always", []):
                for mod in ("ansible.builtin.command", "ansible.builtin.shell",
                            "command", "shell"):
                    body = t.get(mod)
                    cmd = body.get("cmd") if isinstance(body, dict) else body
                    if isinstance(cmd, str) and re.search(r"\bpodman\s+build\b", cmd):
                        out.setdefault(role, []).append(" ".join(cmd.split()))
    return out


def _containerfile(role: str) -> str:
    return "\n".join(ln.split("#", 1)[0]
                     for ln in (ROLES / role / "templates" / "Containerfile.j2")
                     .read_text().splitlines())


BUILDS = _build_tasks()


def test_the_build_tasks_were_found():
    """Guards the guard: no tasks found would make every check below vacuous."""
    assert len(BUILDS) >= 14, sorted(BUILDS)
    assert set(BUILDS) == PACKAGE_MIGRATION_PENDING | MIGRATED, \
        "a role builds an image without being classified here"


def test_migrated_roles_build_with_no_network():
    for role in MIGRATED:
        for cmd in BUILDS[role]:
            assert "--network=none" in cmd, f"{role}: {cmd}"
            assert "--network=host" not in cmd, f"{role}: {cmd}"
            assert "--pull=never" in cmd, f"{role} could pull a base image at build time"


def test_migrated_containerfiles_install_nothing_from_the_network():
    for role in MIGRATED:
        hits = _NETWORK_INSTALL.findall(_containerfile(role))
        assert not hits, f"{role} still installs from an index or mirror: {hits}"


def test_the_pending_list_only_shrinks():
    """Each pending role must still be pending; a migrated one has to leave."""
    stale = [role for role in PACKAGE_MIGRATION_PENDING
             if all("--network=none" in c for c in BUILDS.get(role, []))
             and not _NETWORK_INSTALL.search(_containerfile(role))]
    assert not stale, f"migrated, so remove from PACKAGE_MIGRATION_PENDING: {stale}"


def test_pdf_generation_pins_its_base_image_by_digest():
    defaults = yaml.safe_load((ROLES / "pdf-generation/defaults/main.yml").read_text())
    assert _DIGEST_REF.search(defaults["pdf_generation_base_image"])
    first = next(ln for ln in _containerfile("pdf-generation").splitlines()
                 if ln.strip().startswith("FROM"))
    assert first.split() == ["FROM", "{{", "pdf_generation_base_image", "}}"], first


def test_every_locked_requirement_carries_a_hash():
    """pip refuses a --require-hashes install with any unhashed line, so a lock
    without hashes fails on the host mid-deploy. Fail here first."""
    blocks: dict[str, list[str]] = {}
    current = None
    for line in (ROLES / "pdf-generation/files/requirements.lock").read_text().splitlines():
        m = re.match(r"([A-Za-z0-9_.-]+)==\S+", line)
        if m:
            current = m.group(1)
            blocks[current] = []
        elif current and line.strip().startswith("--hash="):
            blocks[current].append(line)
    assert len(blocks) >= 12, sorted(blocks)
    unhashed = [name for name, hashes in blocks.items()
                if not any(re.search(r"--hash=sha256:[0-9a-f]{64}", h) for h in hashes)]
    assert not unhashed, f"locked without a hash: {unhashed}"


def test_pdf_generation_fails_a_deploy_that_kept_an_old_image():
    tasks = yaml.safe_load((ROLES / "pdf-generation/tasks/main.yml").read_text())
    build = next(t for t in tasks if "podman build" in str(t.get("ansible.builtin.command", "")))
    assert "--label lamware.build-context=" in build["ansible.builtin.command"]["cmd"]
    asserts = [t for t in tasks if "ansible.builtin.assert" in t]
    assert any("pdf_image_label" in str(t["ansible.builtin.assert"]["that"])
               and "pdf_context_hash" in str(t["ansible.builtin.assert"]["that"])
               for t in asserts), "nothing compares the image label with the context hash"


def test_inputs_are_fetched_by_the_fetch_user_not_pipeline():
    tasks = yaml.safe_load((ROLES / "pdf-generation/tasks/main.yml").read_text())
    fetches = [t for t in tasks if re.search(r"\b(pip\s+download|podman\b.*\bpull\b|apt-get\b)",
                                             str(t.get("ansible.builtin.shell", "")))]
    assert len(fetches) == 3, [t["name"] for t in fetches]
    for t in fetches:
        assert t.get("become_user") == "{{ build_fetch_user }}", t["name"]
    meta = yaml.safe_load((ROLES / "pdf-generation/meta/main.yml").read_text())
    assert {"role": "build-fetch"} in meta["dependencies"]
