# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A hardening deploy took the public web tier offline (#529 follow-on).

konstruktoid's UFW handling sets `default deny (incoming)` and adds exactly one
inbound rule — sshd from `sshd_admin_net`. It exposes `ufw_outgoing_traffic` but
nothing for inbound, so every `TAGS=hardening` run deletes anything else the
host needs to serve.

Observed 2026-09-02: `/etc/ufw/user.rules` rewritten at 00:08, and

    curl https://lamware.shaiman.net/   ->  000  (from the operator laptop)
    curl https://<public>/docs          ->  403  (ON the host, nginx fine)

nginx was healthy and answering locally; the packets never arrived. The
Playwright smoke gate failed with 14 `Page.goto` timeouts, which reads as an
application fault and is not one.

WireGuard (51820/udp) was not allowed either. It kept working only because
conntrack held the flow open — it would have dropped on the next idle gap. SSH
stayed up throughout because 22/tcp is the one rule the baseline does add, which
is the only reason this was an outage and not a lockout.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "hardening"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
INBOUND = DEFAULTS["hardening_ufw_inbound"]


def _ufw_task():
    for t in TASKS:
        if "community.general.ufw" in t:
            return t
    return None


@pytest.mark.parametrize("port,proto", [("443", "tcp"), ("80", "tcp"), ("51820", "udp")])
def test_the_ports_the_host_must_serve_are_reopened(port, proto):
    """443 is the SPA and /api. 80 carries the ACME challenge, so losing it
    breaks certificate renewal silently and weeks later. 51820 is WireGuard,
    which is the ONLY path to Cape's UI and the admin surfaces (#529)."""
    assert any(str(r["port"]) == port and r["proto"] == proto for r in INBOUND), \
        f"{port}/{proto} would be removed by the next hardening deploy"


def test_the_rule_is_applied_inbound():
    """`direction: out` would be silently useless — the baseline's outbound
    policy already permits these, so the task would report changed and fix
    nothing."""
    t = _ufw_task()
    assert t, "nothing re-adds the inbound rules"
    assert t["community.general.ufw"]["direction"] == "in"
    assert t["community.general.ufw"]["rule"] == "allow"


def test_it_runs_after_the_baseline_that_deletes_them():
    """Ordering is the whole point: konstruktoid rewrites user.rules, so
    allowing the ports first would be undone in the same play."""
    names = [str(t.get("name", "")) for t in TASKS]
    baseline = names.index("Apply konstruktoid.hardening baseline (production settings)")
    ufw = next(i for i, t in enumerate(TASKS) if "community.general.ufw" in t)
    assert baseline < ufw


def test_every_entry_carries_a_comment():
    """`ufw status` is the only place these are visible. An uncommented rule is
    indistinguishable from one someone added by hand at 2am."""
    for r in INBOUND:
        assert r.get("comment", "").startswith("lamware:"), r


def test_ssh_is_not_duplicated_here():
    """22/tcp is the baseline's own rule and the reason this was recoverable.
    Re-adding it would fight the role over sshd_admin_net scoping."""
    assert not any(str(r["port"]) == "22" for r in INBOUND)


def test_the_collection_used_is_declared():
    """community.general.ufw — the same class of gap that broke a deploy in
    #545, one module over."""
    req = yaml.safe_load((ROOT / "ansible" / "requirements.yml").read_text(encoding="utf-8"))
    assert "community.general" in {c["name"] for c in req["collections"]}
