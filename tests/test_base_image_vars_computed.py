# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""win11-guest needed two variables nothing computed (#522).

`win11_base_image_path` and `win11_base_image_checksum` had to be hand-filled in
pkrvars after the base build. Two ways that goes wrong, both hit for real:

  - They are outputs of the base build, so the failure lands AFTER the 45-90
    minute step -- the longest one, and the one people walk away from.
  - The offline Defender fix (#550) rewrites the image's registry hives, so a
    checksum written by hand is stale the moment it is used. On 2026-09-02 the
    guest build rejected the image until the checksum was updated again, which
    reads as corruption rather than as a stale constant.

The Makefile now derives the path from the same pkrvars packer reads and hashes
the image at build time.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MK = (ROOT / "Makefile").read_text(encoding="utf-8")
EXAMPLE = (ROOT / "packer" / "packer.auto.pkrvars.hcl.example").read_text(encoding="utf-8")


def _target(name: str) -> str:
    # The boundary class MUST include digits. Without them "win11-office:" does
    # not look like a target start, the match runs past it, and every assertion
    # below is satisfied by the OTHER target's body -- verified: stripping
    # sha256sum from win11-guest alone still passed.
    m = re.search(rf"^{name}:.*?(?=\n[A-Za-z0-9_.-]+:|\Z)", MK, re.S | re.M)
    assert m, f"no {name} target"
    body = m.group(0)
    other = "win11-office" if name == "win11-guest" else "win11-guest"
    assert f"\n{other}:" not in body, f"{name} body leaked into {other}"
    return body


@pytest.mark.parametrize("target", ["win11-guest", "win11-office"])
def test_the_checksum_is_computed_at_build_time(target):
    """Not read from pkrvars, where it goes stale as soon as the image is
    touched -- and the image IS touched, by the offline Defender fix."""
    body = _target(target)
    assert "sha256sum" in body, f"{target} does not hash the base image"
    assert "-var win11_base_image_checksum=" in body


@pytest.mark.parametrize("target", ["win11-guest", "win11-office"])
def test_the_path_is_passed_too(target):
    assert "-var win11_base_image_path=" in _target(target)


@pytest.mark.parametrize("target", ["win11-guest", "win11-office"])
def test_a_missing_base_image_fails_before_packer_starts(target):
    """Otherwise packer fails partway through with a file-not-found that reads
    like a template problem."""
    body = _target(target)
    assert '[ -f "$(BASE_IMAGE)" ]' in body
    assert body.index('[ -f "$(BASE_IMAGE)"') < body.index("packer build")


def test_the_output_dir_comes_from_the_same_pkrvars_packer_reads():
    """Hardcoding a second copy of the path is how the two drift."""
    assert "packer.auto.pkrvars.hcl" in MK.split("BASE_OUTPUT_DIR")[1][:400]
    assert "output_directory" in MK.split("BASE_OUTPUT_DIR")[1][:400]


def test_base_image_is_overridable():
    """?= not :=, so BASE_IMAGE=<path> works for a one-off build."""
    assert re.search(r"^BASE_IMAGE\s*\?=", MK, re.M)


def test_the_example_tells_you_not_to_set_them_by_hand():
    """The example previously instructed exactly the thing that goes stale."""
    block = EXAMPLE.split("Windows 11 layered images")[1][:900]
    assert "COMPUTED BY THE MAKEFILE" in block
    assert "stale" in block.lower()
    # and they must stay commented out
    assert not re.search(r"^\s*win11_base_image_path\s*=", EXAMPLE, re.M)
