# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every service the host must reach, or be reached on, needs an explicit rule.

ufw sets DEFAULT_INPUT_POLICY=DROP and DEFAULT_OUTPUT_POLICY=DROP. For weeks
that was invisible, because /etc/iptables/rules.v4 carries `:INPUT ACCEPT` and
`:OUTPUT ACCEPT` and iptables-persistent kept restoring them. ufw declares
`Breaks: iptables-persistent`, so whichever role ran last decided whether the
default policy was permissive. Dropping the netfilter-persistent dependency
ended that coin-flip and two things stopped working at once:

  host -> guest agent   CAPE drives analyses over http://<guest>:8000. Nothing
                        accepted NEW outbound to virbr-det, so task 1250 hit
                        "guest initialization hit the critical timeout" and
                        produced 0 processes and 0 API calls.

  CAPE web UI inbound   listening on 10.200.0.1:8000 with no ufw rule at all.

Neither was new breakage. Both were gaps a permissive policy had been papering
over, and nothing detected them because nothing asserted that a listener has a
matching allow.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
HARDENING_DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "hardening" / "defaults" / "main.yml").read_text())
HARDENING_TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "hardening" / "tasks" / "main.yml").read_text())
NETWORKING_TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "networking" / "tasks" / "main.yml").read_text())

INBOUND = HARDENING_DEFAULTS["hardening_ufw_inbound"]


def _by_port(port):
    return next((e for e in INBOUND if str(e["port"]) == str(port)), None)


# --- inbound ---------------------------------------------------------------

def test_the_cape_ui_is_allowed_inbound():
    assert _by_port(8000) is not None, (
        "CAPE's web UI listens on 10.200.0.1:8000 with no ufw rule; ufw's "
        "default-deny makes it unreachable")


def test_the_cape_ui_is_wireguard_only():
    """An unauthenticated admin interface over plain HTTP onto a live-malware
    host must never be reachable from the public address."""
    e = _by_port(8000)
    assert e.get("interface") == "wg0", (
        f"CAPE UI is scoped to {e.get('interface')!r}, not wg0 -- omitting the "
        f"interface exposes it on the public address")


def test_the_public_ports_stay_public():
    """The inverse: scoping 80/443 to an interface would break ACME and the SPA."""
    for port in ("80", "443"):
        assert _by_port(port).get("interface") is None, (
            f"{port} must stay reachable from anywhere")


def test_the_inbound_task_honours_the_interface_field():
    """A field nothing reads is decoration, and the rule would silently be
    world-reachable."""
    task = next(t for t in HARDENING_TASKS
                if isinstance(t, dict)
                and "inbound ports" in str(t.get("name", "")))
    ufw = task["community.general.ufw"]
    assert "interface" in ufw, "the task ignores the interface field"
    assert "default(omit)" in str(ufw["interface"]), (
        "interface must be omitted when unset, or every rule gets bound to a NIC")


# --- outbound: host -> guest agent -----------------------------------------

def _guest_agent_block():
    for t in NETWORKING_TASKS:
        if not isinstance(t, dict):
            continue
        b = t.get("ansible.builtin.blockinfile")
        if isinstance(b, dict) and "guest agent" in str(b.get("marker", "")):
            return b
    return None


def test_cape_can_reach_the_guest_agent():
    b = _guest_agent_block()
    assert b is not None, (
        "nothing permits host -> guest:8000; CAPE cannot start an analysis and "
        "every detonation times out with 0 processes")
    assert "--dport 8000" in b["block"]
    assert "ufw-before-output" in b["block"]


def test_the_guest_rule_is_scoped_to_the_detonation_bridge():
    """A blanket outbound ACCEPT would also permit the host to reach anything
    else it can route to."""
    b = _guest_agent_block()
    assert "-o " in b["block"], "the rule is not scoped to an interface"
    assert "virbr-det" in b["block"]


def test_the_guest_rule_is_one_port_not_a_blanket():
    """Measured: a blanket `-o virbr-det -j ACCEPT` logged ~165 packets to
    ephemeral ports, all replies already accepted by ufw's conntrack rule. Task
    1252 detonated with tcp/8000 alone."""
    b = _guest_agent_block()
    assert b["block"].count("-A ufw-before-output") == 1, "more than one rule"
    assert "-j ACCEPT" in b["block"] and "--dport" in b["block"], (
        "the rule is not port-scoped")


def test_the_guest_rule_is_validated_before_it_lands():
    assert "restore --test" in _guest_agent_block().get("validate", "")


def test_nothing_calls_netfilter_persistent_any_more():
    """ufw declares Breaks: iptables-persistent, so on any host where the
    hardening role has run the binary does not exist and the task fails the
    whole play. That is what broke the 2026-09-19 deploy."""
    for role in ("networking", "pipeline"):
        text = (ROOT / "ansible" / "roles" / role / "tasks" / "main.yml").read_text()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "netfilter-persistent save" not in stripped, (
                f"{role} still calls netfilter-persistent, which ufw evicts")
