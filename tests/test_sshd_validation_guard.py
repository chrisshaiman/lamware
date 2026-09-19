# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A rollback guard must not delete a control it has no evidence against.

On 2026-09-19 `make deploy TAGS=pipeline,hardening` failed like this:

    Verify the merged sshd config still parses
    rc=255  "Missing privilege separation directory: /run/sshd"

    Remove the drop-in that broke sshd            -> changed
    Fail loudly, with sshd left working           -> "sshd rejected
                                                     20-lamware-console-user.conf"

Nothing rejected anything. `sshd -t` refuses to start without /run/sshd and
exits 255 before reading a single config line. The host uses socket activation
(ssh.socket enabled, ssh.service disabled), so /run/sshd is created per sshd
instance and can be absent between connections -- making the check racy, and
its failure path destructive: it deleted `DenyUsers console-recovery`, one of
the two independent reasons that account cannot log in remotely, and reported a
cause that was false.

Verified afterwards: with /run/sshd present and the identical file restored,
`sshd -t` passes. The config was never the problem.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "hardening" / "tasks" / "main.yml").read_text())


def _console_block():
    for t in TASKS:
        if isinstance(t, dict) and "block" in t and "rescue" in t:
            names = [b.get("name", "") for b in t["block"] if isinstance(b, dict)]
            if any("sshd config still parses" in n for n in names):
                return t
    return None


def test_the_guarded_block_exists():
    assert _console_block() is not None, "the validate/rollback block is gone"


def test_the_privsep_directory_is_created_before_validating():
    """sshd -t exits 255 without /run/sshd, before reading any config."""
    block = _console_block()["block"]
    mkdir_at = next((i for i, t in enumerate(block)
                     if isinstance(t.get("ansible.builtin.file"), dict)
                     and t["ansible.builtin.file"].get("path") == "/run/sshd"
                     and t["ansible.builtin.file"].get("state") == "directory"), None)
    validate_at = next((i for i, t in enumerate(block)
                        if "sshd -t" in str(t.get("ansible.builtin.command", ""))), None)
    assert validate_at is not None, "nothing validates the merged config"
    assert mkdir_at is not None, (
        "/run/sshd is never created; `sshd -t` is racy on a socket-activated host")
    assert mkdir_at < validate_at, "the privsep directory is created too late"


def test_the_validation_result_is_captured():
    """The rescue cannot tell an environment fault from a rejection without it."""
    block = _console_block()["block"]
    validate = next(t for t in block if "sshd -t" in str(t.get("ansible.builtin.command", "")))
    assert validate.get("register"), "the sshd -t result is not registered"


def test_deletion_is_gated_on_an_actual_config_rejection():
    """The gate must come FIRST in the rescue.

    A failed task aborts the rescue, so an assert ahead of the removal means a
    non-rejection failure leaves the drop-in in place. Ordering is the whole
    mechanism -- the same assert after the removal would be decorative.
    """
    rescue = _console_block()["rescue"]
    gate_at = next((i for i, t in enumerate(rescue) if "ansible.builtin.assert" in t), None)
    remove_at = next((i for i, t in enumerate(rescue)
                      if isinstance(t.get("ansible.builtin.file"), dict)
                      and t["ansible.builtin.file"].get("state") == "absent"), None)
    assert remove_at is not None, "the rollback no longer removes the fragment"
    assert gate_at is not None, (
        "the rescue deletes the drop-in unconditionally; `sshd -t` failing to "
        "RUN is not evidence the drop-in is bad")
    assert gate_at < remove_at, (
        f"the gate is at rescue[{gate_at}] but the removal at rescue[{remove_at}] "
        f"-- a gate after the deletion prevents nothing")


def test_the_gate_checks_for_the_privsep_failure_specifically():
    rescue = _console_block()["rescue"]
    gate = next(t for t in rescue if "ansible.builtin.assert" in t)
    conditions = " ".join(gate["ansible.builtin.assert"].get("that", []))
    assert "Missing privilege separation directory" in conditions, (
        "the gate does not recognise the failure that actually occurred")


def test_the_failure_message_does_not_blame_the_config():
    """The original message asserted a cause that was false, which sent the
    operator to check `DenyUsers` against a file that was fine."""
    rescue = _console_block()["rescue"]
    gate = next(t for t in rescue if "ansible.builtin.assert" in t)
    msg = gate["ansible.builtin.assert"].get("fail_msg", "")
    assert "LEFT IN PLACE" in msg, "the message must say the drop-in survived"
    assert "environment" in msg.lower(), "the message must name the real cause"
