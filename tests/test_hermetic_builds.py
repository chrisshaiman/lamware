# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Image builds reach no network; package managers install only what was fetched (ADR-023).

Structural, and only because the property is not observable from here: whether
a build reached the network is decided on the host, at deploy time. The deploy
is the behavioural check (`podman build --network=none` fails on any fetch, and
the build-context label assert fails a build that kept an old image). These
tests record which roles have moved to the one shared build
(`build-fetch/tasks/image.yml`), and keep that list from growing back.

The pdf-generation image stayed at 2026-05-17 for five months: its build ran
`pip install weasyprint` as pipeline, which has no DNS, failed, and the old image
kept serving PDFs.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"
SHARED = ROLES / "build-fetch" / "tasks"

# Roles that still build with network access, each to be moved by its own PR
# (ADR-023 Consequences). This list must only shrink.
PACKAGE_MIGRATION_PENDING = {
    "dotnet-analysis", "ghidra", "go-analysis", "interpret", "java-analysis",
    "office-macro-analysis", "pcap-analysis", "powershell-analysis",
    "pyinstaller-analysis", "python-sandbox", "screenshot-analysis", "triage",
    "volatility",
}

_NETWORK_INSTALL = re.compile(
    r"apt-get\s+(update|install)|apt\s+install|pip3?\s+install(?![^\n]*--no-index)"
    r"|dotnet\s+tool\s+install|npm\s+(install|ci)|go\s+(get|mod\s+download)|gem\s+install")
_DIGEST_REF = re.compile(r"@sha256:[0-9a-f]{64}\Z")


def _tasks(path: Path) -> list[dict]:
    """Every task in a file, blocks flattened."""
    out = []
    for task in yaml.safe_load(path.read_text()) or []:
        out.append(task)
        for key in ("block", "always", "rescue"):
            out.extend(task.get(key) or [])
    return out


def _cmd(task: dict) -> str:
    for mod in ("ansible.builtin.command", "ansible.builtin.shell", "command", "shell"):
        body = task.get(mod)
        cmd = body.get("cmd") if isinstance(body, dict) else body
        if isinstance(cmd, str):
            return " ".join(cmd.split())
    return ""


def _role_tasks(role: str) -> list[dict]:
    return [t for p in (ROLES / role / "tasks").glob("*.yml") for t in _tasks(p)]


def _own_builds(role: str) -> list[str]:
    return [c for t in _role_tasks(role) if re.search(r"\bpodman\s+build\b", c := _cmd(t))]


def _shared_build_use(role: str) -> dict | None:
    """The vars of this role's include of build-fetch's image tasks, or None."""
    for t in _role_tasks(role):
        inc = t.get("ansible.builtin.include_role") or t.get("include_role")
        if inc and inc.get("name") == "build-fetch" and inc.get("tasks_from") == "image":
            return t.get("vars") or {}
    return None


def _containerfile(role: str) -> str:
    return "\n".join(ln.split("#", 1)[0]
                     for ln in (ROLES / role / "templates" / "Containerfile.j2")
                     .read_text().splitlines())


IMAGE_ROLES = sorted(p.parts[-3] for p in ROLES.glob("*/templates/Containerfile.j2"))
MIGRATED = {r for r in IMAGE_ROLES if _shared_build_use(r) is not None}


def test_the_image_roles_were_found():
    """Guards the guard: no roles found would make every check below vacuous."""
    assert len(IMAGE_ROLES) >= 14, IMAGE_ROLES
    assert "pdf-generation" in MIGRATED


def test_every_image_role_is_classified():
    unclassified = set(IMAGE_ROLES) - PACKAGE_MIGRATION_PENDING - MIGRATED
    assert not unclassified, f"builds an image without being classified: {unclassified}"
    both = PACKAGE_MIGRATION_PENDING & MIGRATED
    assert not both, f"migrated, so remove from PACKAGE_MIGRATION_PENDING: {both}"


def test_migrated_roles_have_no_build_of_their_own():
    for role in MIGRATED:
        assert not _own_builds(role), f"{role} builds outside the shared, network-free build"


def test_the_shared_build_has_no_network_and_cannot_pull():
    builds = [c for t in _tasks(SHARED / "image.yml") if "podman build" in (c := _cmd(t))]
    assert len(builds) == 1, builds
    assert "--network=none" in builds[0] and "--pull=never" in builds[0]
    assert "--label lamware.build-context=" in builds[0]


def test_the_shared_build_fails_a_deploy_that_kept_an_old_image():
    asserts = [t for t in _tasks(SHARED / "image.yml") if "ansible.builtin.assert" in t]
    assert any("hb_image_label" in str(t["ansible.builtin.assert"]["that"])
               and "hb_context_hash" in str(t["ansible.builtin.assert"]["that"])
               for t in asserts), "nothing compares the image label with the context hash"


def test_every_shared_fetch_runs_as_the_fetch_user():
    fetches = [t for f in ("image.yml", "image_debs.yml") for t in _tasks(SHARED / f)
               if re.search(r"\bpip\s+download|\bpodman\b[^|]*\spull\s|\bapt-get\b", _cmd(t))]
    assert len(fetches) == 3, [t["name"] for t in fetches]
    for t in fetches:
        assert t.get("become_user") == "{{ build_fetch_user }}", t["name"]


def test_migrated_containerfiles_install_nothing_from_the_network():
    for role in MIGRATED:
        hits = _NETWORK_INSTALL.findall(_containerfile(role))
        assert not hits, f"{role} still installs from an index or mirror: {hits}"


def test_migrated_roles_pin_every_base_image_by_digest():
    for role in MIGRATED:
        defaults = yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text())
        froms = [ln.split()[1:] for ln in _containerfile(role).splitlines()
                 if ln.strip().startswith("FROM")]
        assert froms, role
        for parts in froms:
            assert parts[0] == "{{" and parts[2] == "}}", f"{role}: FROM {' '.join(parts)}"
            assert _DIGEST_REF.search(str(defaults[parts[1]])), f"{role}: {parts[1]}"
            assert "{{ " + parts[1] + " }}" in str(_shared_build_use(role)["hb_base_images"]), \
                f"{role}: {parts[1]} is a FROM but not handed to the shared build"


def test_every_locked_requirement_carries_a_hash():
    """pip refuses a --require-hashes install with any unhashed line, so a lock
    without hashes fails on the host mid-deploy. Fail here first."""
    for role in MIGRATED:
        lock = _shared_build_use(role).get("hb_lock")
        if not lock:
            continue
        blocks: dict[str, list[str]] = {}
        current = None
        for line in (ROLES / role / "files" / lock).read_text().splitlines():
            m = re.match(r"([A-Za-z0-9_.-]+)==\S+", line)
            if m:
                current = m.group(1)
                blocks[current] = []
            elif current and line.strip().startswith("--hash="):
                blocks[current].append(line)
        assert blocks, f"{role}: empty lock"
        unhashed = [n for n, h in blocks.items()
                    if not any(re.search(r"--hash=sha256:[0-9a-f]{64}", x) for x in h)]
        assert not unhashed, f"{role}: locked without a hash: {unhashed}"


def test_image_roles_depend_on_build_fetch():
    for role in MIGRATED:
        meta = yaml.safe_load((ROLES / role / "meta" / "main.yml").read_text())
        assert {"role": "build-fetch"} in meta["dependencies"], role
