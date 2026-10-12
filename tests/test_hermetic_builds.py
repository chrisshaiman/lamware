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
import hashlib
import re
import shlex
from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"
SHARED = ROLES / "build-fetch" / "tasks"

# Roles that still build with network access, each to be moved by its own PR
# (ADR-023 Consequences). This list must only shrink.
PACKAGE_MIGRATION_PENDING = {
    "dotnet-analysis", "pcap-analysis", "powershell-analysis",
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
        # A role's own default, or one build-fetch shares (python:3.12-slim).
        defaults = {**yaml.safe_load((ROLES / "build-fetch" / "defaults" / "main.yml").read_text()),
                    **(yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text()) or {})}
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


# --- The package fetch: what it trusts, and what re-runs it --------------------

_JINJA = jinja2.Environment(undefined=jinja2.StrictUndefined)
_JINJA.filters["hash"] = lambda s, alg: hashlib.new(alg, s.encode()).hexdigest()


def _resolve(value, ctx: dict):
    """A role variable as Ansible would hand it to the shared build: a bare
    "{{ var }}" is replaced by the variable's value (so lists stay lists), and
    strings are rendered until no template is left."""
    if isinstance(value, list):
        return [_resolve(v, ctx) for v in value]
    if not isinstance(value, str):
        return value
    bare = re.fullmatch(r"\{\{\s*(\w+)\s*\}\}", value)
    if bare:
        return _resolve(ctx[bare.group(1)], ctx)
    for _ in range(8):
        if "{{" not in value:
            break
        value = _JINJA.from_string(value).render(**ctx)
    return value


def _debs_task(fragment: str) -> dict:
    [task] = [t for t in _tasks(SHARED / "image_debs.yml") if fragment in t["name"]]
    return task


def _render_debs_fetch() -> list[str]:
    """The apt-get --download-only task, rendered, as the argv the shell sees."""
    raw = _debs_task("apt-get --download-only")["ansible.builtin.shell"]["cmd"]
    rendered = _JINJA.from_string(raw).render(
        build_fetch_home="/F", hb_name="r", build_fetch_ca_bundle="/host/ca.crt",
        hb_set={"name": "s", "image": "img@sha256:0", "packages": ["p1", "p2"]},
        hb_set_dir="/F/r/debs/s", hb_set_keydir="/F/r/keys/s", hb_set_key="k")
    return shlex.split(rendered.replace("\\\n", " "))


def test_the_package_fetch_mounts_keys_and_ca_read_only_and_writes_only_its_output():
    """The resolving container gets the set's signing keys and the host CA bundle,
    read-only; the only thing it can write on the host is its own output dir."""
    argv = _render_debs_fetch()
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert "/F/r/keys/s:/in/keys:ro" in mounts, mounts
    assert "/host/ca.crt:/in/ca-certificates.crt:ro" in mounts, mounts
    assert [m for m in mounts if not m.endswith(":ro")] == ["/F/r/debs/s:/out:rw"], mounts


def test_every_apt_call_in_the_fetch_uses_the_mounted_ca():
    """snapshot.ubuntu.com answers http with a 301 to https (measured 2026-10-11),
    and ubuntu:24.04 has no CA bundle: an apt call without CAInfo fails TLS there."""
    argv = _render_debs_fetch()
    script = argv[argv.index("-euc") + 1]
    opts = re.search(r'^\s*A="([^"]*)"', script, re.M)
    assert opts and "Acquire::https::CAInfo=/in/ca-certificates.crt" in opts.group(1).split()
    calls = [ln.split() for ln in script.splitlines() if ln.strip().startswith("apt-get")]
    assert len(calls) == 2, calls
    assert all(c[1] == "$A" for c in calls), calls


def test_the_fetch_is_redone_when_a_signing_key_changes_and_only_then():
    """A rotated key changes what apt accepts, so it must invalidate the .done
    marker. A set with no keys must keep the key it had before keys existed, or
    every already-fetched set (pdf-generation) is fetched again for nothing."""
    expr = _debs_task("key the fetch")["ansible.builtin.set_fact"]["hb_set_key"]
    s = {"name": "s", "image": "img", "sources": ["deb a", "deb b"], "packages": ["p", "q"]}

    def key(results: list[dict]) -> str:
        return _JINJA.from_string(expr).render(hb_set=s, hb_set_keys={"results": results}).strip()

    before = hashlib.sha256(b"imgdeb a|deb bp,q").hexdigest()
    assert key([]) == before
    assert key([{"checksum": "aa"}]) != key([{"checksum": "bb"}])
    assert key([{"checksum": "aa"}]) != before


def test_each_deb_set_is_copied_into_the_containerfile_and_nothing_else():
    """The set names in the role's tasks and the COPY lines in its Containerfile
    must agree: a set never COPYed is fetched for nothing, a COPY of a set that
    does not exist fails the build on the host."""
    for role in MIGRATED:
        sets = [s["name"] for s in _shared_build_use(role).get("hb_deb_sets", [])]
        assert len(sets) == len(set(sets)), f"{role}: duplicate set names {sets}"
        text = _containerfile(role)
        copied = re.findall(r"^\s*COPY\s+debs/([^/\s]+)/", text, re.M)
        assert sorted(copied) == sorted(sets), f"{role}: sets {sets}, COPYed {copied}"
        assert text.count("dpkg -i") >= len(sets), f"{role}: a COPYed set is never installed"


def test_every_package_source_is_signed_by_a_key_the_fetch_has():
    """Each source line names its signing key, and that key is either one the
    base image ships or one the set carries in signing_keys (mounted at /in/keys).
    A signed-by naming a file the container lacks fails `apt-get update` on the
    host. Rendered from the role defaults, as Ansible would."""
    for role in MIGRATED:
        defaults = yaml.safe_load((ROLES / role / "defaults" / "main.yml").read_text())
        for s in _shared_build_use(role).get("hb_deb_sets", []):
            keys = [Path(k).name for k in _resolve(s.get("signing_keys", []), defaults)]
            sources = _resolve(s["sources"], defaults)
            assert sources, f"{role}/{s['name']}: no sources"
            for line in sources:
                where = f"{role}/{s['name']}: {line}"
                assert "{{" not in line, where
                assert "http://snapshot.ubuntu.com" not in line, f"{where}: use https"
                m = re.search(r"\[[^\]]*signed-by=([^\s\]]+)", line)
                assert m, f"{where}: no signed-by"
                path = m.group(1)
                if path.startswith("/in/keys/"):
                    assert path.removeprefix("/in/keys/") in keys, f"{where}: key not carried"
                else:
                    assert path.startswith("/usr/share/keyrings/"), where
