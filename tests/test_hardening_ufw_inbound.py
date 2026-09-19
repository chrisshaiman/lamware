# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""ufw is not installed on this host, and that is a decision with a cost.

THE ORIGINAL FINDING (2026-09-02, #529 follow-on) still matters and is kept
here because it is why this file exists. konstruktoid's UFW handling sets
`default deny (incoming)` and re-adds exactly one inbound rule -- sshd. Every
`TAGS=hardening` run deleted everything else the host serves:

    curl https://lamware.shaiman.net/   ->  000  (from the operator laptop)
    curl https://<public>/docs          ->  403  (ON the host, nginx fine)

nginx was healthy and answering locally; the packets never arrived. WireGuard
(51820/udp) was not allowed either and kept working only because conntrack held
the flow open -- it would have dropped on the next idle gap. SSH stayed up
because 22/tcp is the one rule the baseline does add, which is the only reason
that was an outage and not a lockout. The same window reopened on 2026-09-19.

WHY UFW IS GONE. ufw and iptables-persistent declare `Breaks:` against each
other, so installing one removes the other and every deploy picked a winner by
role order -- `hardening` installed ufw, `networking` then installed
iptables-persistent and evicted it. With ufw present, three controls failed at
once:

    pipeline egress   the DROP sat below ufw's chains and never fired; uid 997
                      reached 1.1.1.1:443 with the rule present and 0 packets
    guest agent       nothing accepted NEW outbound to virbr-det, so CAPE could
                      not reach the guest and detonations timed out at 0 procs
    CAPE web UI       listening on 10.200.0.1:8000 with no inbound rule at all

None of those exist without ufw: the raw rules sit at the top of INPUT, OUTPUT
and FORWARD with nothing in front of them. That ordering is what the air-gap
depends on and what ufw could only have offered below LIBVIRT_FWO -- config
libvirt rewrites on every network restart.

WHAT THIS GIVES UP. ufw provided default-deny inbound. `/etc/iptables/rules.v4`
carries `:INPUT ACCEPT`, so any service that listens is reachable by whatever
can route to it -- which is exactly how the CAPE UI was exposed without a rule.
That is NOT solved here and must not be read as solved.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "hardening"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
NETWORKING = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "networking" / "tasks" / "main.yml").read_text())


def _hardening_vars():
    for t in TASKS:
        if isinstance(t, dict) and "ansible.builtin.include_role" in t:
            return t.get("vars") or {}
    return {}


def test_konstruktoid_does_not_manage_ufw():
    """The knob that stops the baseline installing it in the first place."""
    assert _hardening_vars().get("manage_ufw") is False, (
        "konstruktoid will install ufw, which evicts iptables-persistent and "
        "puts its own chains in front of every raw rule on this host")


def test_ufw_is_purged_not_merely_absent():
    """A config-only (`rc`) package is one `apt install` from coming back and
    evicting iptables-persistent again."""
    task = next((t for t in TASKS
                 if isinstance(t, dict)
                 and isinstance(t.get("ansible.builtin.apt"), dict)
                 and t["ansible.builtin.apt"].get("name") == "ufw"), None)
    assert task is not None, "nothing removes ufw"
    apt = task["ansible.builtin.apt"]
    assert apt.get("state") == "absent"
    assert apt.get("purge") is True, "ufw left in rc state can be reinstalled"


def test_the_dead_inbound_list_is_gone():
    """It managed ufw rules. With no ufw it would be silently inert, which is
    worse than absent -- it reads as though inbound is handled."""
    assert "hardening_ufw_inbound" not in DEFAULTS


def test_iptables_persistent_is_the_persistence_mechanism():
    """Something must survive a reboot, and with ufw gone it is this."""
    installs = [t for t in NETWORKING
                if isinstance(t, dict)
                and "iptables-persistent" in str(t.get("ansible.builtin.apt", ""))]
    assert installs, "nothing installs iptables-persistent"

    saves = [t for t in NETWORKING
             if isinstance(t, dict)
             and "netfilter-persistent save" in str(t.get("ansible.builtin.command", ""))]
    assert saves, (
        "the raw INPUT/OUTPUT/FORWARD rules are never saved, so the air-gap "
        "does not survive a reboot")


def test_nothing_reloads_a_firewall_that_is_not_installed():
    """`ufw reload` in a handler failed the whole play once ufw was evicted."""
    for role in ("pipeline", "networking", "hardening"):
        h = ROOT / "ansible" / "roles" / role / "handlers" / "main.yml"
        if not h.exists():
            continue
        assert "ufw reload" not in h.read_text(), (
            f"{role} reloads ufw, which is not installed on this host")
