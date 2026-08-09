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


# Empty as of 2026-08-09 (#344): ghidra and pcap-analysis were the last two, and
# both now fetch in the role. Keep the mechanism — the next role to need a
# build-time fetch records the debt here instead of quietly shipping it.
MIGRATION_PENDING: dict[str, str] = {}


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


MIGRATED = ("pyinstaller-analysis", "dotnet-analysis", "java-analysis",
            "ghidra", "pcap-analysis")


def test_the_migrated_roles_are_actually_migrated():
    """Guards the guard: if these slipped into MIGRATION_PENDING the suite would
    pass while the bug returned."""
    for role in MIGRATED:
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
                         ("java-analysis", "java_deobfuscator"),
                         # Not source, but the same contract: the version says
                         # what to ask for, the hash says which bytes are OK.
                         ("ghidra", "ghidra"),
                         # A repo signing key. Pinned so an upstream rotation
                         # fails the deploy instead of silently trusting new
                         # bytes that then decide what apt installs.
                         ("pcap-analysis", "zeek_repo_key")):
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
    for role in MIGRATED:
        tasks = (ROLES / role / "tasks" / "main.yml").read_text(encoding="utf-8")
        assert tasks.index("ansible.builtin.get_url") < tasks.index("podman build"), (
            f"{role}: sources must be fetched before the image is built")


def _get_url_dests(role: str) -> list[str]:
    """Basenames the role fetches INTO THE BUILD CONTEXT.

    Parsed from the task list rather than grepped: the dest is a Jinja path, so
    only its final component is comparable, and a substring search over the raw
    YAML would happily match the word inside a comment.

    Scoped to `/build/`, because not every get_url feeds an image. pcap-analysis
    also fetches the ET Open Suricata ruleset into `/rules/`, which is mounted at
    runtime — deliberately unpinned and unchecksummed, since freezing an IDS
    signature feed by hash would pin the detections themselves. Requiring a COPY
    for it would be a false alarm, and this test exists partly because the first
    version of it raised exactly that.
    """
    tasks = yaml.safe_load((ROLES / role / "tasks" / "main.yml").read_text(encoding="utf-8"))
    dests = [t["ansible.builtin.get_url"]["dest"]
             for t in tasks if "ansible.builtin.get_url" in t]
    return [Path(d).name for d in dests if "/build/" in d]


def _copy_sources(text: str) -> list[str]:
    """Build-context sources a Containerfile COPYs.

    `COPY --from=<stage>` reads from another STAGE, not the context, so it is
    excluded — counting it would let a missing fetch look satisfied.
    """
    sources = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0].upper() != "COPY":
            continue
        parts = parts[1:]
        if any(p.startswith("--from=") for p in parts):
            continue
        parts = [p for p in parts if not p.startswith("--")]
        sources.extend(Path(p).name for p in parts[:-1])  # last token is the dest
    return sources


def test_every_fetched_file_is_actually_copied_into_the_image():
    """The two halves must agree on a FILENAME, and nothing else checks that.

    get_url writing `ghidra.zip` while the Containerfile COPYs `ghidra-release.zip`
    passes every other test in this file: the fetch is pinned, checksummed, and
    ordered before the build. It fails on the host, mid-deploy, as a COPY error —
    the same late-and-expensive failure this whole file exists to move earlier.
    """
    for role in MIGRATED:
        fetched = _get_url_dests(role)
        assert fetched, f"{role} is listed as migrated but fetches nothing"
        copied = _copy_sources(CONTAINERFILES[role])
        missing = [f for f in fetched if f not in copied]
        assert not missing, (
            f"{role}: the role fetches {missing} but the Containerfile never COPYs "
            f"it — it copies {copied}. The build will fail on the host.")


def test_the_copy_parser_ignores_cross_stage_copies():
    """Guards the guard: ghidra's final stage pulls the unpacked tree with
    `COPY --from=`. If that counted as a build-context source, a role that stopped
    fetching entirely could still look satisfied."""
    assert "COPY --from=" in CONTAINERFILES["ghidra"], (
        "ghidra is no longer multi-stage — this control has nothing to guard")
    assert "ghidra" not in _copy_sources(CONTAINERFILES["ghidra"]), (
        "the --from= stage source leaked into the build-context source list")
    assert "ghidra.zip" in _copy_sources(CONTAINERFILES["ghidra"]), (
        "positive control: the real COPY of the fetched zip must still be seen")


def test_the_pin_records_where_it_came_from():
    """A bare sha with no URL is unauditable — nobody can tell what it pins or
    whether the upstream still exists."""
    for role, var in (("pyinstaller-analysis", "pycdc_commit"),
                      ("dotnet-analysis", "de4dotex_commit")):
        defaults = (ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8")
        idx = defaults.index(var)
        preamble = defaults[max(0, idx - 400):idx]
        assert "http" in preamble, f"{role}: {var} has no upstream URL near it"
