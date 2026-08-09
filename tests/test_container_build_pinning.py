# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Third-party tools built into analysis images must be pinned.

A deploy on 2026-08-08 failed here:

    fatal: unable to access 'https://github.com/zrax/pycdc.git/':
           Could not resolve host: github.com

Transient DNS, but it exposed the real problem: `git clone --depth 1` takes
whatever HEAD happens to be. The decompiler and deobfuscator inside a
malware-analysis toolchain could change silently between deploys, with nothing
recording which build produced a given result — and two stored analyses of the
same sample could differ for reasons no artifact explains.

That is the same shape as the rest of this codebase's recurring bug: something
that looks fixed because the file did not change, while the thing it produces
does. The repo already knew better — the CAPEv2 clone in `roles/qemu-patched` is
pinned with a dated comment.

Still unpinned, and not covered here: `dotnet tool install -g ilspycmd` takes the
latest NuGet release, and `dotnet publish` restores from NuGet — the dotnet image is
not hermetic. This removes the GitHub dependency, not every one.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"

_SHA = re.compile(r"^[0-9a-f]{40}$")
# `git clone` of a remote URL, i.e. fetching third-party source at build time.
_CLONE = re.compile(r"git\s+clone\s+(?:--\S+\s+)*https?://\S+")


def _containerfiles() -> dict[str, str]:
    return {p.parts[-3]: p.read_text(encoding="utf-8")
            for p in ROLES.glob("*/templates/Containerfile.j2")}


CONTAINERFILES = _containerfiles()


def test_containerfiles_were_found():
    """Guards the guard: an empty set makes everything below vacuous."""
    assert len(CONTAINERFILES) >= 8, f"only found {sorted(CONTAINERFILES)}"
    assert "pyinstaller-analysis" in CONTAINERFILES
    assert "dotnet-analysis" in CONTAINERFILES


def test_no_containerfile_clones_an_unpinned_repo():
    """THE regression. `git clone --depth 1 <url>` cannot be pinned — depth-1
    always lands on HEAD — so its presence is itself the bug."""
    offenders = []
    for role, text in sorted(CONTAINERFILES.items()):
        for match in _CLONE.findall(text):
            offenders.append(f"{role}: {match.strip()}")
    assert not offenders, (
        "these Containerfiles clone a remote at whatever HEAD is, so the tool "
        "inside the image can change between deploys with nothing recording it: "
        + "; ".join(offenders) +
        " — use `git init` + `git fetch --depth 1 origin <sha>` + "
        "`git checkout FETCH_HEAD`, with the sha in the role's defaults")


def test_the_pinned_shas_are_real_and_resolvable_to_a_variable():
    """A pin that is a Jinja variable is only a pin if the variable exists and
    holds a full commit sha. A truncated or absent one fails the build late, on
    the host, mid-deploy."""
    expected = {
        "pyinstaller-analysis": "pycdc_commit",
        "dotnet-analysis": "de4dotex_commit",
    }
    for role, var in expected.items():
        text = CONTAINERFILES[role]
        assert f"{{{{ {var} }}}}" in text, f"{role} does not reference {var}"
        defaults = yaml.safe_load(
            (ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8"))
        sha = str(defaults.get(var, ""))
        assert _SHA.match(sha), (
            f"{role}: {var} is {sha!r} — must be a full 40-char commit sha, not a "
            f"tag or short sha, both of which can move or collide")


MIGRATION_PENDING = {
    "ghidra": "wget of a GitHub release — same failure mode, currently masked by a cached image",
    "pcap-analysis": "curl of an openSUSE repo key — not GitHub, but still build-time network",
}


def test_no_containerfile_reaches_the_network_for_source():
    """The build runs as `pipeline`, which cannot resolve DNS at all (#343) — its
    outbound is restricted to loopback:5432 and loopback:8000.

    Two deploys failed on `Could not resolve host: github.com` before that was
    understood. Sources are fetched by the ROLE, as root, where the network exists;
    the build only COPYs them. `apt` and NuGet still reach out, which is why this
    looks for source fetches specifically rather than all network use.
    """
    offenders = []
    for role, text in sorted(CONTAINERFILES.items()):
        if role in MIGRATION_PENDING:
            continue
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            if re.search(r"\b(git\s+(clone|fetch)|wget|curl)\b", code):
                offenders.append(f"{role}: {line.strip()[:70]}")
    assert not offenders, (
        "these Containerfiles fetch source at build time, from a user with no "
        "network: " + "; ".join(offenders) +
        " — fetch it in the role with get_url + checksum and COPY it in, or add a "
        "justified entry to MIGRATION_PENDING")


def test_the_migration_list_does_not_go_stale():
    """A role that no longer fetches must leave the list, or it starts hiding
    regressions instead of recording debt."""
    stale = []
    for role in MIGRATION_PENDING:
        if role not in CONTAINERFILES:
            stale.append(f"{role} has no Containerfile")
            continue
        fetches = any(
            re.search(r"\b(git\s+(clone|fetch)|wget|curl)\b", ln.split("#", 1)[0])
            for ln in CONTAINERFILES[role].splitlines())
        if not fetches:
            stale.append(f"{role} no longer fetches — remove it")
    assert not stale, f"MIGRATION_PENDING is stale: {stale}"


def test_the_migrated_roles_are_actually_migrated():
    """Guards the guard: if these slipped into MIGRATION_PENDING the suite would
    pass while the bug returned."""
    for role in ("pyinstaller-analysis", "dotnet-analysis", "java-analysis"):
        assert role not in MIGRATION_PENDING, (
            f"{role} is the whole point of this change and must not be exempted")


def test_every_fetched_source_is_checksum_verified():
    """A commit sha pins WHAT to fetch; only a checksum verifies WHAT ARRIVED, and
    it does so before the build starts rather than mid-build."""
    import yaml as _yaml
    for role, prefix in (("pyinstaller-analysis", "pycdc"),
                         ("pyinstaller-analysis", "pyinstxtractor"),
                         ("dotnet-analysis", "de4dotex"),
                         ("java-analysis", "cfr"),
                         ("java-analysis", "java_deobfuscator")):
        tasks = (ROLES / role / "tasks" / "main.yml").read_text(encoding="utf-8")
        assert "ansible.builtin.get_url" in tasks, f"{role} fetches nothing"
        defaults = _yaml.safe_load(
            (ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8"))
        sha = str(defaults.get(f"{prefix}_sha256", ""))
        assert re.match(r"^[0-9a-f]{64}$", sha), (
            f"{role}: {prefix}_sha256 is {sha!r} — must be a full sha256")
        assert f"{prefix}_sha256" in tasks, (
            f"{role} defines {prefix}_sha256 but never uses it — an unused "
            f"checksum verifies nothing")


def test_the_fetch_happens_before_the_build():
    """get_url after podman build leaves the build COPYing a file that is not there
    yet, or worse, last deploy's copy of it."""
    for role in ("pyinstaller-analysis", "dotnet-analysis", "java-analysis"):
        tasks = (ROLES / role / "tasks" / "main.yml").read_text(encoding="utf-8")
        assert tasks.index("ansible.builtin.get_url") < tasks.index("podman build"), (
            f"{role}: sources must be fetched before the image is built")


def test_the_pin_records_where_it_came_from():
    """A bare sha with no URL is unauditable — nobody can tell what it pins or
    whether the upstream still exists."""
    for role, var in (("pyinstaller-analysis", "pycdc_commit"),
                      ("dotnet-analysis", "de4dotex_commit")):
        defaults = (ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8")
        idx = defaults.index(var)
        preamble = defaults[max(0, idx - 400):idx]
        assert "http" in preamble, f"{role}: {var} has no upstream URL near it"
