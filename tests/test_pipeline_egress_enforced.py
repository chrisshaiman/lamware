# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pipeline egress allowlist has to be ORDERED to work, not merely present.

Measured on the live host 2026-09-19, with every existing check green:

    OUTPUT rule 10  DROP  owner UID match 997  "block all other outbound"
                    pkts: 0                    <- never reached

    sudo -u pipeline bash -c 'echo > /dev/tcp/1.1.1.1/443'   -> CONNECTED
    sudo -u pipeline bash -c 'echo > /dev/tcp/1.1.1.1/53'    -> CONNECTED
    sudo -u pipeline bash -c 'echo > /dev/tcp/127.0.0.1/27017' -> CONNECTED

ufw's OUTPUT jumps run first: `-o lo -j ACCEPT` takes all loopback, then
`ufw-user-output` accepts 22/53/80/123/443/853/4460 to ANY destination (from
konstruktoid's ufw_outgoing_traffic default, which we do not override). Anything
appended to OUTPUT below those is unreachable.

So the rules must live in `ufw-before-output`, ahead of both. These tests assert
the property that was missing -- position relative to ufw -- rather than the one
that was already true.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text())
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2").read_text()

ALLOWED_PORTS = {"5432", "8000"}
DENIED_PORTS = {"53", "27017", "4000", "443", "80"}


def _egress_blocks():
    out = []
    for t in TASKS:
        if not isinstance(t, dict):
            continue
        b = t.get("ansible.builtin.blockinfile")
        if isinstance(b, dict) and "pipeline egress" in str(b.get("marker", "")):
            out.append(b)
    return out


def test_both_families_are_configured():
    """#343 was filed because the allowlist existed only in IPv4."""
    paths = {b["path"] for b in _egress_blocks()}
    assert paths == {"/etc/ufw/before.rules", "/etc/ufw/before6.rules"}, paths


def test_rules_target_ufws_before_output_chain():
    """In OUTPUT they are unreachable. The chain is the entire fix."""
    for b in _egress_blocks():
        chain = "ufw6-before-output" if "before6" in b["path"] else "ufw-before-output"
        for line in b["block"].strip().splitlines():
            assert line.startswith(f"-A {chain} "), (
                f"{b['path']}: rule targets the wrong chain: {line}")


def test_the_block_is_inserted_before_ufw_accepts_loopback():
    """ufw's `-o lo -j ACCEPT` is the first rule in the file body. Anchoring on
    the last chain declaration puts our block above it."""
    for b in _egress_blocks():
        anchor = b.get("insertafter", "")
        assert anchor.startswith("^:"), (
            f"{b['path']}: anchor {anchor!r} is not a chain declaration, so the "
            f"block may land after ufw's loopback ACCEPT")


def test_there_is_exactly_one_drop_and_it_is_last():
    """An allow below the DROP is dead -- the failure mode the role's own
    comment has warned about since #343.

    Asserting only that the LAST drop is last is not enough: a second DROP
    inserted ABOVE the allows kills every one of them and leaves the trailing
    DROP exactly where it was. A mutation proved that gap.
    """
    for b in _egress_blocks():
        lines = [ln for ln in b["block"].strip().splitlines() if ln.strip()]
        drops = [i for i, ln in enumerate(lines) if " -j DROP" in ln]
        accepts = [i for i, ln in enumerate(lines) if " -j ACCEPT" in ln]
        assert drops, f"{b['path']}: no DROP-all"
        assert len(drops) == 1, (
            f"{b['path']}: {len(drops)} DROP rules; one above the allows would "
            f"silently kill them")
        assert drops[0] == len(lines) - 1, f"{b['path']}: the DROP-all is not last"
        assert all(a < drops[0] for a in accepts), (
            f"{b['path']}: an ACCEPT sits below the DROP-all")


def test_only_postgres_and_cape_are_allowed():
    for b in _egress_blocks():
        ports = set(re.findall(r"--dport (\d+)", b["block"]))
        assert ports == ALLOWED_PORTS, f"{b['path']}: allowlist is {ports}"


def test_dns_is_not_allowed():
    """No pipeline-uid code resolves a hostname (cape_api_url and db_host are IP
    literals), and direct DNS egress from this uid is an exfil channel."""
    for b in _egress_blocks():
        assert "--dport 53 " not in b["block"], f"{b['path']}: DNS is allowed"


def test_previously_revoked_ports_are_not_reintroduced():
    for b in _egress_blocks():
        ports = set(re.findall(r"--dport (\d+)", b["block"]))
        assert not (ports & DENIED_PORTS), f"{b['path']}: denied ports present"


def test_the_uid_is_numeric_not_a_name():
    """iptables-restore resolves a NAME at restore time; a boot-ordering fault
    would fail open on a rule that must never fail open."""
    for b in _egress_blocks():
        assert "--uid-owner pipeline" not in b["block"], (
            f"{b['path']}: uid-owner uses a name, which can fail to resolve")
        assert "pipeline_uid" in b["block"], (
            f"{b['path']}: uid is not resolved at deploy time")


def test_the_write_is_validated_before_it_lands():
    """A malformed block must be rejected before the file is written, not
    discovered when ufw reloads and the host answers nothing."""
    for b in _egress_blocks():
        v = b.get("validate", "")
        assert "restore --test" in v, f"{b['path']}: no validate: {v!r}"


def test_comment_strings_match_what_the_monitor_greps_for():
    for b in _egress_blocks():
        assert b["block"].count('--comment "pipeline: ') == 3


# --- the monitor has to detect the failure it slept through -----------------

def test_the_monitor_surveys_the_chain_the_rules_are_in():
    assert 'EGRESS_CHAIN_V4="ufw-before-output"' in MONITOR
    assert 'EGRESS_CHAIN_V6="ufw6-before-output"' in MONITOR


def test_the_monitor_detects_a_preempting_accept():
    """The rules were defeated by an ACCEPT ABOVE them, which the old survey --
    scoped to rules commented `pipeline:` -- could not see."""
    assert "PREEMPTED" in MONITOR
    # Defined AND called. A rename that touches only one of the two leaves the
    # string present while breaking the script -- which a substring check reads
    # as healthy.
    assert MONITOR.count("egress_preempted_by") >= 2, (
        "egress_preempted_by is defined or called, but not both")


def test_the_monitor_probes_effectiveness_not_just_presence():
    """A rule that EXISTS satisfied the old check throughout the period it did
    nothing."""
    assert "probe_egress" in MONITOR
    assert "INEFFECTIVE" in MONITOR
    assert MONITOR.count("probe_egress") >= 3, "probe defined but never called"


def test_the_probe_targets_a_local_port_so_it_generates_no_egress():
    """A monitor that reaches the internet every 5 minutes to prove it cannot
    reach the internet would be its own finding."""
    probe = MONITOR[MONITOR.index("probe_egress() {"):]
    probe = probe[:probe.index("\n}")]
    # Assert the CONNECTION TARGET, not merely that the address appears
    # somewhere -- the failure message names 127.0.0.1 too, so a body-wide
    # substring check passes even when the probe dials a public address.
    targets = re.findall(r"/dev/tcp/([0-9.]+)/(\d+)", probe)
    assert targets, "the probe no longer opens a connection"
    for host, _port in targets:
        assert host.startswith("127."), (
            f"the probe dials {host}, which leaves the host; a monitor that "
            f"reaches the internet to prove it cannot would be its own finding")


# --- the fact the rules depend on must actually be defined ------------------

def _set_fact_tasks():
    return [t["ansible.builtin.set_fact"] for t in TASKS
            if isinstance(t, dict) and isinstance(t.get("ansible.builtin.set_fact"), dict)]


def test_the_uid_fact_is_defined_from_getent_not_from_itself():
    """`pipeline_uid: "{{ pipeline_uid }}"` is undefined at resolution time and
    fails the whole role.

    It got there by a blind global replace of the getent expression, which also
    rewrote the set_fact that was supposed to DEFINE it. The existing tests
    checked only the blockinfile blocks, so nothing covered the definition and
    the deploy was where it surfaced.
    """
    facts = [f for f in _set_fact_tasks() if "pipeline_uid" in f]
    assert facts, "pipeline_uid is never defined, but the rules reference it"
    for f in facts:
        value = str(f["pipeline_uid"])
        assert "pipeline_uid" not in value, (
            f"pipeline_uid is defined from itself: {value!r}")
        assert "getent_passwd" in value, (
            f"pipeline_uid is not resolved from getent: {value!r}")


def test_the_getent_lookup_runs_before_the_fact_is_pinned():
    names = [t.get("name", "") for t in TASKS if isinstance(t, dict)]
    getent_at = next((i for i, t in enumerate(TASKS)
                      if isinstance(t, dict) and "ansible.builtin.getent" in t), None)
    fact_at = next((i for i, t in enumerate(TASKS)
                    if isinstance(t, dict)
                    and isinstance(t.get("ansible.builtin.set_fact"), dict)
                    and "pipeline_uid" in t["ansible.builtin.set_fact"]), None)
    assert getent_at is not None, "nothing resolves the pipeline uid"
    assert fact_at is not None and getent_at < fact_at, (
        f"the fact is pinned at task {fact_at} before getent runs at {getent_at}: {names[:0]}")


def test_every_variable_the_rules_use_is_defined_somewhere():
    """Catches the general shape: a rule referencing a variable no task sets."""
    defined = {k for f in _set_fact_tasks() for k in f}
    for b in _egress_blocks():
        for var in re.findall(r"\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}", b["block"]):
            assert var in defined, (
                f"{b['path']}: rules use {{{{ {var} }}}} but no set_fact defines it")
