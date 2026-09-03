# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The first 25H2 image booted with an expired Windows licence (#553).

The evaluation media (released 2025-09-15) carries a shelf life of about a year,
so an image built from it on 2026-09-02 was expired on day zero:

    Windows 11 Enterprise Evaluation
    Windows License is expired

Not cosmetic: once expired, the Windows License Manager Service shuts the guest
down every hour. Analyses would be truncated at unpredictable points and it would
read as sample behaviour -- the same class of confound the rebuild exists to
remove.

Nobody noticed until the guest was screenshotted, after the image had already
been staged on the sandbox. These tests are about the check that now catches it
during the build.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
W = ROOT / "packer" / "scripts" / "windows"
REARM = (W / "rearm-license.ps1").read_text(encoding="utf-8")
VERIFY = (W / "verify-license.ps1").read_text(encoding="utf-8")
BASE = (ROOT / "packer" / "windows11-base.pkr.hcl").read_text(encoding="utf-8")
GUEST = (ROOT / "packer" / "windows11-guest.pkr.hcl").read_text(encoding="utf-8")


def _order(t, *names):
    return [t.index(n) for n in names]


def test_the_rearm_is_followed_by_a_restart_before_anything_checks_it():
    """ReArmWindows does not take effect until reboot. Verifying first would
    read the OLD state and either pass wrongly or fail wrongly."""
    r = BASE.index("rearm-license.ps1")
    v = BASE.index("verify-license.ps1")
    # .index() would find the EARLIER restart (the hostname one), which sits
    # before rearm and would satisfy the ordering for the wrong reason.
    restart = BASE.index('provisioner "windows-restart"', r)
    assert r < restart < v, "rearm must be followed by a restart, then the check"


def test_the_restart_between_them_is_the_one_after_rearm():
    """There is an earlier windows-restart in this template for the hostname
    change. The ordering assertion above must not be satisfied by that one."""
    first = BASE.index('provisioner "windows-restart"')
    rearm = BASE.index("rearm-license.ps1")
    assert first < rearm, "expected an earlier restart to exist before rearm"
    after = BASE.index('provisioner "windows-restart"', rearm)
    assert after < BASE.index("verify-license.ps1")


@pytest.mark.parametrize("tpl,name", [("base", "BASE"), ("guest", "GUEST")])
def test_both_builds_check_the_licence(tpl, name):
    """The guest is what Cape boots; the base is where failing costs least."""
    assert "verify-license.ps1" in {"BASE": BASE, "GUEST": GUEST}[name]


def test_a_rearm_failure_is_not_fatal_by_itself():
    """A host that has exhausted its re-arms should fail on the resulting STATE,
    not on the attempt -- otherwise a still-valid licence with no re-arms left
    would fail the build for no reason."""
    assert "exit 1" not in REARM, "rearm must leave the verdict to verify-license"
    assert "C004D307" in REARM, "the exhausted-rearm code should be explained"


def test_the_verifier_fails_the_build():
    # indented inside if-blocks, so anchor on leading whitespace
    assert re.search(r"^\s*exit 1\s*$", VERIFY, re.M)


def test_grace_states_are_accepted_because_an_evaluation_is_one():
    """Requiring status 1 (Licensed) would fail every evaluation image, which is
    every image we build. A guard that can never pass gets deleted."""
    m = re.search(r"\$ok = @\(([^)]*)\)", VERIFY)
    assert m, "no accept-list found"
    ok = {int(x) for x in re.findall(r"\d+", m.group(1))}
    assert {2, 3} <= ok, "out-of-box / out-of-tolerance grace must be acceptable"
    assert 0 not in ok and 4 not in ok and 5 not in ok, "unlicensed states accepted"


def test_a_nearly_expired_grace_also_fails():
    """Passing on 3 days of grace would ship an image that expires mid-sweep --
    exactly the silent-truncation failure this is meant to prevent."""
    assert re.search(r"\$days\s*-lt\s*\d+", VERIFY), "no minimum-remaining check"


def test_the_verifier_only_reads_state():
    """Same rule as the Defender check: a verifier that mutates can be blocked
    or can mask the thing it is measuring."""
    for bad in ("ReArmWindows", "slmgr", "Set-CimInstance", "Invoke-CimMethod"):
        assert bad not in VERIFY, f"verify-license mutates state via {bad}"
