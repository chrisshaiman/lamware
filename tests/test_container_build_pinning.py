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

Not covered here: `dotnet tool install -g ilspycmd` in the dotnet Containerfile
takes the latest NuGet release and is unpinned for the same reason. Pinning it
needs a version this test cannot resolve offline; see the PR.
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


def test_the_fetch_checks_out_what_it_fetched():
    """`git fetch origin <sha>` leaves the working tree untouched. Without the
    checkout the build compiles whatever `git init` left behind — nothing — or
    silently the wrong ref. The pin would be decorative."""
    for role in ("pyinstaller-analysis", "dotnet-analysis"):
        text = CONTAINERFILES[role]
        assert "git fetch --depth 1 origin" in text, f"{role} missing pinned fetch"
        assert "git checkout FETCH_HEAD" in text, (
            f"{role} fetches a pinned commit but never checks it out")


def test_the_pin_records_where_it_came_from():
    """A bare sha with no URL is unauditable — nobody can tell what it pins or
    whether the upstream still exists."""
    for role, var in (("pyinstaller-analysis", "pycdc_commit"),
                      ("dotnet-analysis", "de4dotex_commit")):
        defaults = (ROLES / role / "defaults" / "main.yml").read_text(encoding="utf-8")
        idx = defaults.index(var)
        preamble = defaults[max(0, idx - 400):idx]
        assert "http" in preamble, f"{role}: {var} has no upstream URL near it"
