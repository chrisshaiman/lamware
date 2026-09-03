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


def test_the_check_runs_in_the_guest_build():
    """The guest boots the image the OFFLINE hive edit has already corrected, so
    this is the first point at which the check can meaningfully pass."""
    t = (ROOT / "packer" / "windows11-guest.pkr.hcl").read_text(encoding="utf-8")
    assert "verify-defender-disabled.ps1" in t


def test_it_does_not_run_in_the_base_build():
    """The base build installs from the ISO with Defender live, so
    disable-defender.ps1 is blocked by AMSI and the check could never pass there.
    A gate that always fails gets bypassed rather than fixed -- and the base
    build must still produce the artifact the offline fix is applied to.

    The rationale has to stay in the template, or someone re-adds it."""
    t = (ROOT / "packer" / "windows11-base.pkr.hcl").read_text(encoding="utf-8")
    assert "verify-defender-disabled.ps1" in t, "the reason must be recorded here"
    assert 'script = "${path.root}/scripts/windows/verify-defender-disabled.ps1"' not in t, \
        "base cannot satisfy this check; it belongs to the guest build"
    assert "disable-defender-offline.sh" in t, "the working fix must be pointed at"


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


def test_it_asserts_on_the_engine_not_the_service_state():
    """Measured 2026-09-02 after the offline hive edit (#550): Windows resets
    WinDefend Start from 4 to 3 and runs the service, while reporting

        RealTimeProtectionEnabled = False
        AntivirusEnabled          = False

    The service running is not the thing that ruins an analysis; scanning is.
    Failing on the service state was asserting a proxy that disagrees with the
    property it stands for, so the check reported a usable image as broken."""
    svc_line = next(l for l in BODY.splitlines() if "WinDefend Start" in l)
    assert "informational" in svc_line.lower(), "service state must not fail the build"
    # and the engine assertions must still be failures
    assert '$problems += "real-time protection is ON"' in BODY
    assert '$problems += "antivirus engine is ON"' in BODY


def test_the_service_state_is_still_reported():
    """Downgrading it to informational must not mean hiding it -- it is the
    first thing to look at if a sample behaves oddly."""
    assert "WinDefend Start" in BODY
    assert "Get-Service -Name WinDefend" in BODY


def test_the_service_host_is_not_treated_as_scanning():
    """AMServiceEnabled says the antimalware service is loaded, not that it is
    scanning. Measured 2026-09-03: True on a guest reporting AntivirusEnabled
    False and RealTimeProtectionEnabled False. Asserting on it rejected a
    correctly-disabled image -- the same service-vs-engine confusion this file
    already fixed once for WinDefend."""
    line = next(l for l in BODY.splitlines() if "AMServiceEnabled" in l and "Write-Output" in l)
    assert "informational" in line.lower()
    assert '$problems += "antimalware service' not in BODY


def test_optional_engine_fields_are_probed_defensively():
    """AMServiceEnabled and OnAccessProtectionEnabled do not exist on every
    build. Referencing them blindly would throw and fail a good image."""
    for field in ("OnAccessProtectionEnabled",):
        assert f"contains '{field}'" in BODY, f"{field} accessed without a guard"
