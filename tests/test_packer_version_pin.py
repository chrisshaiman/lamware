# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The builder version is an input to the image, and nothing recorded it.

Every template said `required_version = ">= 1.10"`, so any Packer from 1.10
onward could build the guests and no artifact said which one did. A different
builder can produce a different image — the same defect as the floating
`mcr.microsoft.com/dotnet/sdk:10.0` tag that left the dotnet-analysis image
unbuildable once the tag moved under a reusable cache (#514).

Pinned to `~> 1.16.0`: patch releases inside 1.16.x are allowed so a security fix
is not blocked, and a minor bump becomes a decision rather than a surprise.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = sorted((ROOT / "packer").glob("*.pkr.hcl"))
README = ROOT / "packer" / "README.md"
PIN = "~> 1.16.0"


def test_there_are_templates_to_check():
    """A glob that matches nothing would make every test below vacuous."""
    assert TEMPLATES, "no *.pkr.hcl found"


@pytest.mark.parametrize("tpl", TEMPLATES, ids=lambda p: p.name)
def test_every_template_pins_the_builder(tpl):
    m = re.search(r'required_version\s*=\s*"([^"]+)"', tpl.read_text(encoding="utf-8"))
    assert m, f"{tpl.name} declares no required_version"
    assert m.group(1) == PIN, f"{tpl.name} says {m.group(1)!r}, not {PIN!r}"


def test_the_templates_do_not_disagree():
    """Two templates on different builders is worse than one loose constraint:
    it looks pinned while the image depends on which file you built from."""
    seen = {re.search(r'required_version\s*=\s*"([^"]+)"',
                      t.read_text(encoding="utf-8")).group(1) for t in TEMPLATES}
    assert len(seen) == 1, seen


def test_the_readme_records_the_exact_release_and_its_checksum():
    """A constraint says which versions are ALLOWED. Reproducing the image needs
    the one that was used, and a checksum so it can be fetched again safely."""
    text = README.read_text(encoding="utf-8")
    assert "1.16.0" in text
    assert re.search(r"\b[0-9a-f]{64}\b", text), "no sha256 for the release"
    assert "sha256sum -c" in text, "no verification step shown"


def test_the_unpinned_plugin_is_named_rather_than_left_implicit():
    """`packer init` still fetches the qemu plugin over the network under a loose
    constraint. Saying so is not a fix, but an unrecorded gap is how the last one
    survived for months."""
    text = README.read_text(encoding="utf-8")
    assert "pkr.hcl.lock" in text
    assert "qemu" in text


def test_ci_installs_a_packer_the_templates_will_accept():
    """Two places declare a Packer version and nothing made them agree.

    CI pinned `~1.11` while the templates asked for `>= 1.10`, so it passed by
    luck. Raising the templates to `~> 1.16.0` without moving CI would have made
    every `packer validate` fail — caught here before pushing rather than by a
    red build.
    """
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    m = re.search(r"setup-packer@[^\n]*\n(?:\s*#[^\n]*\n)*\s*with:\s*\n\s*version:\s*\"([^\"]+)\"",
                  ci)
    assert m, "no setup-packer version found in CI"
    ci_series = m.group(1).lstrip("~^= ").split(".")[:2]
    tpl_series = PIN.lstrip("~> ").split(".")[:2]
    assert ci_series == tpl_series, (
        f"CI installs {m.group(1)!r} but the templates require {PIN!r}; "
        f"`packer validate` in CI would refuse every template")
