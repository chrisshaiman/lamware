# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A 37-minute build shipped an image with live antivirus and reported success (#548).

`disable-defender.ps1` was blocked in its entirety by Defender's own AMSI:

    At C:\\Windows\\Temp\\script-....ps1:1 char:1
    + <#
    This script contains malicious content and has been blocked by your antivirus
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent

PowerShell exited 0 anyway, Packer moved on, and printed `Builds finished`.
Booting the artifact afterwards showed WinDefend Running with Start=2 and
real-time protection on — a detonation guest that quarantines its samples.

Nothing checked. These tests are about the check that now does.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "packer" / "scripts" / "windows" / "verify-defender-disabled.ps1"
BODY = SCRIPT.read_text(encoding="utf-8")


@pytest.mark.parametrize("template", ["windows11-base.pkr.hcl", "windows11-guest.pkr.hcl"])
def test_the_check_runs_in_both_builds(template):
    """Base is where it must fail — 37 minutes earlier than the guest build.
    Guest keeps it too, because the guest is what CAPE actually boots."""
    t = (ROOT / "packer" / template).read_text(encoding="utf-8")
    assert "verify-defender-disabled.ps1" in t, f"{template} does not verify Defender"


@pytest.mark.parametrize("template", ["windows11-base.pkr.hcl", "windows11-guest.pkr.hcl"])
def test_it_runs_after_the_thing_it_verifies(template):
    """Checking before disable-defender.ps1 would report the pre-existing state
    and pass for the wrong reason."""
    t = (ROOT / "packer" / template).read_text(encoding="utf-8")
    verify = t.index("verify-defender-disabled.ps1")
    if "disable-defender.ps1" in t:
        assert t.index("disable-defender.ps1") < verify


def test_it_fails_the_build_rather_than_warning():
    """The whole defect was a non-zero condition reported through a zero exit."""
    assert re.search(r"^\s*exit 1\s*$", BODY, re.M), "nothing makes Packer stop"


def test_it_only_reads_state():
    """It must not itself trip AMSI — which is what killed the disable script.
    No Set-MpPreference, no service stops, no registry writes."""
    forbidden = ["Set-MpPreference", "Stop-Service", "Set-ItemProperty",
                 "New-ItemProperty", "reg add", "Remove-Item"]
    present = [f for f in forbidden if f.lower() in BODY.lower()]
    assert not present, f"the verifier mutates state and may be blocked itself: {present}"


@pytest.mark.parametrize("signal", [
    "WinDefend",                  # the service, Start=4
    "DisableAntiSpyware",         # the GP key the specialize pass should write
    "RealTimeProtectionEnabled",  # what the guest itself reports
])
def test_it_checks_each_thing_that_was_wrong(signal):
    """All three were wrong in the failing image. A verifier that checked only
    one would have passed on two of the three."""
    assert signal in BODY


def test_a_missing_cmdlet_is_treated_as_a_pass_not_a_crash():
    """When the engine really is off, Get-MpComputerStatus does not exist. If
    that were an error the check would fail on a correctly-built image — a guard
    that cannot ever pass gets deleted by the next person."""
    assert "SilentlyContinue" in BODY
    assert re.search(r"if \(\$mp\)", BODY), "no branch for the cmdlet being unavailable"
