# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A console account that can log in locally and cannot log in over SSH (#552).

There was no console credential at all: ovh/main.tf provisions key-only and
nothing set a password, so Serial-over-LAN and the KVM console both reached a
`login:` prompt nobody could satisfy. On 2026-09-01 an operator-laptop key
problem -- a passphrase-protected key whose ssh-agent had been wiped by a
`wsl --shutdown` -- became an OVH rescue-mode boot, because neither out-of-band
path could be used.

The SSH refusal is STRUCTURAL: sshd carries `AllowGroups sudo`, so an account
outside that group is refused before anything else is considered. The trap is
that the account needs root powers, and granting them the obvious way -- adding
it to `sudo` -- is exactly what would let it in remotely. These tests exist
mostly to keep that from being "simplified" later.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "hardening"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
TEXT = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
USER = DEFAULTS["hardening_console_user"]


def _user_task():
    for t in TASKS:
        u = t.get("ansible.builtin.user")
        if isinstance(u, dict) and "console_user" in str(u.get("name", "")):
            return u
    return None


def _copy_to(fragment):
    for t in TASKS:
        for sub in ([t] + list(t.get("block") or [])):
            c = sub.get("ansible.builtin.copy") if isinstance(sub, dict) else None
            if isinstance(c, dict) and fragment in str(c.get("dest", "")):
                return c
    return None


def test_the_account_is_not_in_the_sudo_group():
    """THE assertion. Group membership is what sshd's AllowGroups refuses on;
    putting this account in `sudo` would silently make it remotely usable."""
    u = _user_task()
    assert u, "no console account is created"
    assert u.get("groups") in ([], None), f"groups={u.get('groups')!r} must be empty"
    assert u.get("append") is not True, "append:true could add it to sudo elsewhere"


def test_sudo_is_granted_by_username_instead():
    """The account still needs root powers; this is how it gets them without
    touching group membership."""
    c = _copy_to("sudoers.d")
    assert c, "no sudoers entry"
    assert "ALL=(ALL)" in c["content"]
    assert c.get("validate") == "visudo -cf %s", "an invalid sudoers file locks out sudo"
    assert c.get("mode") == "0440"


def test_ssh_is_denied_redundantly():
    """Redundant with AllowGroups on purpose: two independent reasons, so one
    edit cannot quietly open remote access to a password account."""
    c = _copy_to("sshd_config.d")
    assert c, "no sshd drop-in"
    assert "DenyUsers" in c["content"]


def test_a_broken_sshd_config_is_rolled_back_not_left():
    """This change exists to preserve a way back in. Leaving a host whose sshd
    cannot start would be the worst possible way to fail at that."""
    blk = next((t for t in TASKS if "rescue" in t and "block" in t), None)
    assert blk, "the sshd edit is not guarded by a rescue"
    assert any("sshd -t" in str(s) for s in blk["block"]), "merged config never validated"
    # assert on the parsed structure, not on str() of it -- the YAML text
    # "state: absent" never appears in a Python dict repr, so a text check here
    # fails for the wrong reason (and would pass if the rescue were emptied).
    removes = [s for s in blk["rescue"]
               if isinstance(s.get("ansible.builtin.file"), dict)
               and s["ansible.builtin.file"].get("state") == "absent"
               and "sshd_config.d" in str(s["ansible.builtin.file"].get("path"))]
    assert removes, "a bad drop-in would be left in place"
    assert any("ansible.builtin.fail" in s for s in blk["rescue"]), \
        "failure would pass silently"


def test_the_password_hash_comes_from_a_variable_and_is_mandatory():
    """A default would ship a known password to every host."""
    u = _user_task()
    assert "console_recovery_password_hash" in str(u.get("password"))
    assert "mandatory" in str(u.get("password")), "a missing hash must fail the play"
    assert "console_recovery_password_hash" not in yaml.dump(DEFAULTS), \
        "the hash must not have a role default"


def test_the_user_task_does_not_log_the_hash():
    for t in TASKS:
        u = t.get("ansible.builtin.user")
        if isinstance(u, dict) and "console_user" in str(u.get("name", "")):
            assert t.get("no_log") is True, "the password hash would appear in output"


def test_the_runbook_says_to_verify_by_trying_it():
    """Checking the config asserts the proxy. The property is whether SSH
    actually refuses -- the distinction that cost the most time on 2026-09-01."""
    doc = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert f"ssh {USER}@" in doc
    assert "must be refused" in doc
