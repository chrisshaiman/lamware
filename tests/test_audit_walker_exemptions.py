# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The scheduled filesystem walkers are exempt from the /home audit rule (#797).

Structural, because only a booted host observes the property (auditd runs
with its rules locked, so the exemptions load at the next boot): this parses
the rules file the hardening role ships and the task that ships it, and keeps
three things from drifting. The file must sort before konstruktoid's
`hardening.rules` (augenrules merges rules.d in name order and the kernel stops
at the first matching rule, so a `never` rule placed after the `always` rule
it exempts does nothing). Every rule in it must be a `never` rule: this file
exists to subtract from the audit, never to add to it. And each exemption must
name a binary by absolute path with `-F exe=`, not a comm name a process could
set for itself.
"""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
HARDENING = ROOT / "ansible" / "roles" / "hardening"
RULES_NAME = "00-lamware-audit-exclusions.rules"
RULES = HARDENING / "files" / RULES_NAME
TASKS = yaml.safe_load((HARDENING / "tasks" / "main.yml").read_text(encoding="utf-8"))

WALKERS = {"/usr/bin/aide", "/usr/sbin/updatedb.plocate"}


def _rules() -> list[str]:
    lines = RULES.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def test_the_file_sorts_before_konstruktoids_rules():
    assert RULES_NAME < "audit.rules", RULES_NAME
    assert RULES_NAME < "hardening.rules", RULES_NAME


def test_every_rule_is_a_never_rule_on_the_exit_list():
    rules = _rules()
    assert rules, "no rules in the exemption file"
    for rule in rules:
        assert rule.startswith("-a never,exit "), rule


def test_exemptions_name_the_walkers_by_absolute_path():
    exes = set()
    for rule in _rules():
        m = re.search(r"-F exe=(\S+)", rule)
        assert m, f"exemption without an exe filter: {rule}"
        assert m.group(1).startswith("/"), m.group(1)
        assert "comm=" not in rule, rule
        exes.add(m.group(1))
    assert exes == WALKERS, exes


def _task(name_fragment: str) -> dict:
    for task in TASKS:
        if name_fragment in task.get("name", ""):
            return task
    raise AssertionError(f"no task named like {name_fragment!r}")


def test_the_role_ships_the_file_into_rules_d_and_merges():
    task = _task("Exempt the scheduled filesystem walkers")
    copy = task.get("ansible.builtin.copy") or task.get("copy")
    assert copy["src"] == RULES_NAME
    assert copy["dest"] == f"/etc/audit/rules.d/{RULES_NAME}"
    assert copy["mode"] == "0600"
    assert "Merge audit rules" in task.get("notify", [])


def test_the_distribution_aide_timer_is_masked_not_just_disabled():
    """A package upgrade re-enables a disabled unit; it cannot re-enable a masked one."""
    task = _task("duplicate AIDE timer")
    unit = task.get("ansible.builtin.systemd_service") or task.get("systemd_service")
    assert unit["name"] == "dailyaidecheck.timer"
    assert unit["masked"] is True
    assert unit["enabled"] is False
