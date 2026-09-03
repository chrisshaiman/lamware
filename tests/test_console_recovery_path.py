# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The only documented recovery path was blocked by our own hardening (#524).

konstruktoid sets `ImplicitPolicyTarget=block` and `AuthorizedDefault=none` but
never writes `rules.conf`, so nothing is authorised. On a remote server the only
USB device that ever appears is the BMC's virtual keyboard, presented when an
operator opens the KVM console — and it was refused:

    usb 1-9: Device is not authorized for usage

`docs/DEPLOYMENT.md` named that console as *the* answer to "SSH locked out", so
the runbook's single entry did not work. On 2026-09-01 a passphrase-encrypted key
and an emptied ssh-agent — entirely operator-side — escalated to a rescue-mode
boot partly for this reason.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "hardening"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
DOC = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")


def _usbguard_task():
    for t in TASKS:
        if "usbguard" in str(t.get("name", "")).lower():
            return t
    return None


# --- the rule itself ---


def test_a_usbguard_rule_is_written_at_all():
    """konstruktoid points RuleFile at a file it never creates. Configuring the
    daemon to block everything and then writing no allow rules is what took the
    console out."""
    t = _usbguard_task()
    assert t, "nothing authorises the console keyboard"
    assert "ansible.builtin.blockinfile" in t
    assert t["ansible.builtin.blockinfile"].get("create") is True, (
        "rules.conf does not exist until something creates it")


def test_the_hub_carrying_the_keyboard_is_allowed():
    """Allowing HID alone left the console dead. The BMC presents the keyboard
    behind 046b:ff01 "Virtual Hub" (class 09), and a blocked hub means the HID
    never enumerates:

        7: block id 046b:ff01 name "Virtual Hub" via-port "1-9" with-interface 09:00:00

    A hub carries no data of its own and anything behind it still has to match
    the HID rule, so this does not widen the exposure the HID rule already
    accepted."""
    block = _usbguard_task()["ansible.builtin.blockinfile"]["block"]
    classes = set(re.findall(r"\b(\d{2}):\d{2}:\d{2}\b", block))
    assert "09" in classes, "the BMC virtual hub is blocked; the keyboard cannot appear"


def test_mass_storage_stays_blocked_even_with_the_hub_allowed():
    """Verified on the host after the change: 046b:ff20 "Virtual Cdrom Device"
    (08:06:50) and 046b:ffb0 "Virtual Ethernet" remained blocked. Allowing the
    hub must not become allowing everything plugged into it."""
    block = _usbguard_task()["ansible.builtin.blockinfile"]["block"]
    classes = set(re.findall(r"\b(\w{2}):\w{2}:\w{2}\b", block))
    assert "08" not in classes, "virtual media / mass storage would be authorised"
    assert "02" not in classes and "0a" not in classes, "virtual ethernet would be authorised"


def test_the_rule_allows_input_devices_only():
    """Parsed from the rendered block, not grepped from the file: the comments
    above it name both the classes we allow and the one we refuse, so a text
    search would match whether or not the rule survived."""
    block = _usbguard_task()["ansible.builtin.blockinfile"]["block"]
    classes = set(re.findall(r"\b(\d{2}):\d{2}:\d{2}\b", block))
    assert classes <= {"03", "09"}, f"expected HID and hubs only, got {classes}"
    assert block.strip().startswith("allow ")


# 09 (hubs) was in this list until the console was actually tested. The BMC
# hangs its keyboard off a virtual hub, so forbidding hubs forbade the keyboard.
# Changed on evidence, not to make a test pass: mass storage and wireless stay
# forbidden, and both were confirmed still blocked on the host afterwards.
@pytest.mark.parametrize("forbidden,why", [
    ("08", "mass storage - the exfiltration case USBGuard mainly exists for"),
    ("e0", "wireless controllers"),
])
def test_no_other_device_class_is_allowed(forbidden, why):
    block = _usbguard_task()["ansible.builtin.blockinfile"]["block"]
    assert forbidden not in re.findall(r"\b(\w{2}):\w{2}:\w{2}\b", block), why


def test_the_wildcard_form_is_not_used():
    """`03:*:*` would cover HID devices that are not input peripherals. The
    enumerated form is deliberate."""
    block = _usbguard_task()["ansible.builtin.blockinfile"]["block"]
    assert "*" not in block, "a wildcard interface match is broader than intended"


def test_it_is_switchable_and_defaults_on():
    """A recovery path that has to be remembered is not a recovery path, but the
    trade-off is real, so it stays a variable someone can turn off."""
    assert DEFAULTS["hardening_usbguard_allow_console_hid"] is True
    assert _usbguard_task()["when"] == "hardening_usbguard_allow_console_hid"


def test_usbguard_is_reloaded_so_the_rule_takes_effect():
    """A rule file the daemon has not re-read changes nothing — and the failure
    mode is silent until the next time somebody needs the console."""
    assert _usbguard_task().get("notify") == "Restart usbguard"
    handlers = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    assert any(h["name"] == "Restart usbguard" for h in handlers)


def test_it_runs_after_the_baseline_that_blocks_it():
    """Ordering is the whole point: konstruktoid installs USBGuard, so allowing
    the keyboard before the include would be undone by it."""
    names = [str(t.get("name", "")) for t in TASKS]
    assert names.index("Apply konstruktoid.hardening baseline (production settings)") \
        < next(i for i, n in enumerate(names) if "usbguard" in n.lower())


# --- the runbook ---


def test_the_runbook_checks_the_client_before_the_server():
    """The actual 2026-09-01 cause was operator-side. The old entry sent you
    straight to the KVM console."""
    section = DOC.split("### SSH stopped accepting a key that used to work")[1]
    section = section.split("### Recovery ladder")[0]
    assert "ssh-add -l" in section
    assert "[preauth]" in section
    for rung in ("Serial over LAN", "KVM / IPMI", "init=/bin/bash", "rescue"):
        assert rung in DOC, f"the ladder lost its {rung} rung"


def test_the_runbook_documents_the_console_account():
    """This assertion used to be the opposite -- it required the guide to WARN
    that no console password existed, which was true and important until #552
    created one. Updated rather than deleted: rungs 1 and 2 hand you a login
    prompt, and the guide has to say what to type at it, or they read as working
    recovery paths when they are not."""
    assert "console-recovery" in DOC, "the console account is undocumented"
    assert "console_recovery_password_hash" in DOC or "vault" in DOC.lower()
    # and it must still record WHY it exists, or someone removes it as clutter
    assert "rescue-mode boot" in DOC or "rescue mode" in DOC.lower()


def test_the_old_single_line_answer_is_gone():
    assert "### SSH locked out of OVH server" not in DOC
