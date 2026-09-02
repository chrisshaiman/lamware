# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Defender has to be disabled offline, because every online hook is too late (#548).

The 25H2 base build proved the answer file cannot do it:

  windowsPE    RunSynchronousCommand runs BEFORE Setup applies the image, so the
               target hives do not exist. The commands already there write to
               HKLM\\SYSTEM\\Setup\\LabConfig -- WinPE's own in-memory registry.
  specialize   runs inside the booting OS. Its writes DID happen and Defender
               removed them; DisableAntiSpyware has been deprecated and actively
               deleted since Windows 10 2004, and Tamper Protection restores
               WinDefend\\Start.
  oobeSystem   later still.

So the edit happens on the host, against the qcow2, where nothing is defending
the hives.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "packer" / "scripts" / "host"
SH = (HOST / "disable-defender-offline.sh").read_text(encoding="utf-8")
SOFTWARE = (HOST / "defender-off-software.reg").read_text(encoding="utf-8")
SYSTEM = (HOST / "defender-off-system.reg").read_text(encoding="utf-8")

# .reg comments start with ";" -- strip them before asserting, or a test matches
# the prose explaining the rule instead of the rule.
SYSTEM_KEYS = "\n".join(ln for ln in SYSTEM.splitlines() if not ln.lstrip().startswith(";"))
SOFTWARE_KEYS = "\n".join(ln for ln in SOFTWARE.splitlines() if not ln.lstrip().startswith(";"))


def test_tamper_protection_is_disabled():
    """THE one that matters. Without it Windows reverts every other value on
    first boot, which is exactly what happened in #548."""
    assert re.search(r'"TamperProtection"\s*=\s*dword:0*0\b', SOFTWARE_KEYS), \
        "Tamper Protection is not being turned off; the rest will not stick"


def test_the_system_hive_uses_a_real_control_set():
    """`CurrentControlSet` is a runtime alias that does not exist offline. A
    merge against it succeeds and writes a key Windows never reads."""
    assert "ControlSet001" in SYSTEM_KEYS
    assert "CurrentControlSet" not in SYSTEM_KEYS


@pytest.mark.parametrize("value", ["DisableAntiSpyware", "DisableRealtimeMonitoring"])
def test_the_policy_values_are_still_set(value):
    """Kept as belt-and-braces. With Tamper Protection off they finally hold."""
    assert value in SOFTWARE_KEYS


def test_windefend_is_set_to_disabled_not_manual():
    """Start=3 is manual and Defender starts itself on demand. 4 is disabled."""
    m = re.search(r'\[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\WinDefend\]'
                  r'\s*\n"Start"\s*=\s*dword:0*(\d)', SYSTEM_KEYS)
    assert m and m.group(1) == "4", "WinDefend Start must be 4 (SERVICE_DISABLED)"


def test_the_script_picks_the_partition_by_size_not_number():
    """p1 is the ESP and p4 the recovery image. Guessing a number silently edits
    the recovery hive and reports success."""
    assert "blockdev --getsize64" in SH and "BEST" in SH
    assert not re.search(r'mount[^\n]*\$\{?NBD\}?p[0-9]', SH), "partition number is hardcoded"


def test_it_backs_up_the_hives_before_merging():
    assert "pre-defender-off" in SH
    assert SH.index("pre-defender-off") < SH.index("hivexregedit --merge")


def test_it_reads_the_values_back_after_writing():
    """Writing without verifying is how #548 shipped: a step that reported
    success and changed nothing."""
    assert "--export" in SH, "the script never confirms the merge took effect"
    assert SH.index("--merge") < SH.index("--export")


def test_it_refuses_to_run_unprivileged_rather_than_half_working():
    assert 'id -u' in SH and "exit 1" in SH


def test_it_disconnects_nbd_on_every_exit_path():
    """A left-behind /dev/nbd0 holding the qcow2 makes the next packer build
    fail with a confusing 'image in use'."""
    assert re.search(r"trap cleanup EXIT", SH)
    assert "qemu-nbd --disconnect" in SH.split("cleanup()")[1][:400]


def test_the_default_image_path_survives_sudo():
    """$HOME under sudo is /root. The first real run failed with

        ERROR: no image at /root/packer-output/windows11-base.qcow2

    so the default must resolve against the INVOKING user's home, not root's."""
    assert "SUDO_USER" in SH, "the default path will resolve to /root under sudo"
    assert "getent passwd" in SH
    # and the bare $HOME default must not be the primary source
    assert not re.search(r'IMG="\$\{1:-\$HOME/', SH)
