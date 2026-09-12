# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Capture the guest's event logs — and ONLY those (#518 failed detonations).

quasarrat scored 55, 17, 45 on identical images. In the low run its API trace
stops mid-CLR-work with no NtTerminateProcess, where the healthy runs end with a
clean NtClose sequence and NtTerminateProcess ExitCode=0. The process was ended
rather than exiting, and the trace cannot say whether that was a crash, an
external kill, or the monitor dropping out.

The evtx/ and sysmon/ directories were empty in every analysis because both
modules were off, so no Windows-side evidence existed and none can be recovered
retrospectively.

The restraint matters as much as the capture. sysmon_windows and procmon sit
beside evtx in the same config section and run an AGENT inside the guest —
a well-known analyst artefact that evasive malware checks for. Turning those on
to investigate variance would perturb the very measurements being stabilised.
evtx exports logs Windows already keeps.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape" / "defaults" / "main.yml").read_text(encoding="utf-8"))
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape" / "tasks" / "main.yml").read_text(encoding="utf-8"))

#: Guest-resident agents. Enabling any of these changes what the sample can see.
IN_GUEST_AGENTS = ("sysmon_windows", "sysmon_linux", "procmon", "curtain", "tracee_linux")


def _evtx_task():
    for t in TASKS:
        ini = t.get("community.general.ini_file") or {}
        if ini.get("option") == "evtx":
            return t
    raise AssertionError("no task enables evtx")


def test_evtx_is_enabled_in_the_guest_module_list():
    task = _evtx_task()
    ini = task["community.general.ini_file"]
    assert ini["section"] == "auxiliary_modules", \
        "evtx is set in the wrong section; the analyzer reads config.evtx from auxiliary_modules"
    assert "cape_capture_evtx" in str(ini["value"]), \
        "evtx is hardcoded rather than driven by the role variable"
    assert DEFAULTS["cape_capture_evtx"] is True


def test_changing_it_restarts_cape():
    """auxiliary.conf is read at startup; without the handler the running daemon
    keeps the old module list while the deploy reports success."""
    assert "Restart Cape services" in str(_evtx_task().get("notify", ""))


def test_no_in_guest_agent_is_switched_on_alongside_it():
    """The restraint IS the requirement. Enabling sysmon or procmon to chase a
    measurement problem would add an artefact evasive malware looks for, and
    change the thing being measured."""
    enabled = []
    for t in TASKS:
        ini = t.get("community.general.ini_file") or {}
        if ini.get("option") in IN_GUEST_AGENTS:
            val = str(ini.get("value", "")).lower()
            if "yes" in val or "true" in val:
                enabled.append(f"{ini['option']}={ini.get('value')}")
    assert not enabled, (
        f"these run an agent inside the guest and were switched on: {enabled}. "
        f"They are visible to the sample; evtx was chosen precisely because it "
        f"is not")
