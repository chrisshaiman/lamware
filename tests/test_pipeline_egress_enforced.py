# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pipeline user's egress allowlist, and why its CHAIN is load-bearing.

The rules live in OUTPUT and work there — because nothing precedes them. That
was not true for one day. On 2026-09-19, with ufw installed, measured live:

    OUTPUT rule 10  DROP  owner UID match 997  "block all other outbound"
                    pkts: 0                    <- never reached

    sudo -u pipeline bash -c 'echo > /dev/tcp/1.1.1.1/443'     -> CONNECTED
    sudo -u pipeline bash -c 'echo > /dev/tcp/127.0.0.1/27017' -> CONNECTED

ufw's OUTPUT jumps ran first: `-o lo -j ACCEPT` took all loopback, then
`ufw-user-output` accepted 22/53/80/123/443/853/4460 to ANY destination. The
rules were moved into `ufw-before-output` to get ahead of that, and then ufw was
removed from the host entirely — it and iptables-persistent evict each other,
and every deploy picked a winner by role order. With ufw gone the rules are back
in OUTPUT with nothing in front of them, which is where they belong.

So the property worth asserting is not "a DROP exists" — it did, for a whole day
while uid 997 browsed the internet. It is that nothing terminating precedes it.
`test_air_gap_rule_checks.py` exercises that at runtime against fake tables;
this file asserts the shape of what Ansible installs.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text())
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2").read_text()

ALLOWED_PORTS = {"5432", "8000"}
REVOKED_PORTS = {"4000", "27017"}


def _egress_rules():
    """Every iptables task touching the pipeline user's OUTPUT chain."""
    out = []
    for t in TASKS:
        if not isinstance(t, dict):
            continue
        r = t.get("ansible.builtin.iptables")
        if isinstance(r, dict) and r.get("chain") == "OUTPUT" and r.get("uid_owner"):
            out.append(r)
    return out


def _present(rules):
    return [r for r in rules if r.get("state") != "absent"]


def test_rules_exist_in_both_families():
    """#343 was filed because the allowlist existed only in IPv4."""
    fams = {r.get("ip_version", "ipv4") for r in _present(_egress_rules())}
    assert fams == {"ipv4", "ipv6"}, f"families configured: {fams}"


def test_the_drop_all_exists_in_both_families():
    drops = [r for r in _present(_egress_rules()) if r.get("jump") == "DROP"]
    fams = {r.get("ip_version", "ipv4") for r in drops}
    assert fams == {"ipv4", "ipv6"}, f"DROP-all present for: {fams}"


def test_allows_are_declared_before_the_drop():
    """ansible.builtin.iptables APPENDS, so an allow declared after the DROP-all
    lands below it and is dead — present, matching `-C`, permitting nothing."""
    rules = _present(_egress_rules())
    for fam in ("ipv4", "ipv6"):
        fam_rules = [r for r in rules if r.get("ip_version", "ipv4") == fam]
        drop_at = next(i for i, r in enumerate(fam_rules) if r.get("jump") == "DROP")
        accepts = [i for i, r in enumerate(fam_rules) if r.get("jump") == "ACCEPT"]
        assert all(a < drop_at for a in accepts), (
            f"{fam}: an ACCEPT is declared after the DROP-all and will be dead")


def test_only_postgres_and_cape_are_allowed():
    ports = {str(r["destination_port"]) for r in _present(_egress_rules())
             if r.get("jump") == "ACCEPT"}
    assert ports == ALLOWED_PORTS, f"allowlist is {ports}"


def test_dns_is_not_allowed():
    """No pipeline-uid code resolves a hostname — cape_api_url and db_host are
    IP literals — and direct DNS egress from this uid is an exfil channel."""
    ports = {str(r.get("destination_port")) for r in _present(_egress_rules())}
    assert "53" not in ports


def test_the_revoked_ports_stay_revoked():
    """LiteLLM (4000) and Mongo (27017) are explicitly removed: no pipeline-uid
    process reaches them. interpret runs as a rootless subuid with
    --network=none and a bind-mounted LiteLLM Unix socket."""
    for r in _egress_rules():
        if str(r.get("destination_port")) in REVOKED_PORTS:
            assert r.get("state") == "absent", (
                f"port {r['destination_port']} is allowed again")


def test_the_rules_are_persisted():
    """Without this the allowlist survives only until the next reboot, and a
    reboot is precisely when nobody is watching the rule set."""
    saves = [t for t in TASKS
             if isinstance(t, dict)
             and "netfilter-persistent save" in str(t.get("ansible.builtin.command", ""))]
    assert saves, "nothing persists the pipeline egress rules"


def test_no_ufw_chain_is_referenced_anywhere():
    """ufw is not installed. A rule targeting one of its chains would be written
    into a file nothing reads, and the allowlist would silently not exist."""
    text = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()
    for line in text.splitlines():
        if line.strip().startswith("#"):
            continue
        assert "ufw-before-output" not in line and "before.rules" not in line, (
            f"pipeline role targets a ufw chain: {line.strip()[:80]}")


# --- the monitor has to watch the chain the rules are actually in -----------

def test_the_monitor_surveys_output():
    assert 'EGRESS_CHAIN_V4="OUTPUT"' in MONITOR
    assert 'EGRESS_CHAIN_V6="OUTPUT"' in MONITOR


def test_the_monitor_can_still_explain_a_preempting_accept():
    """Structural preemption is no longer an alarm -- it produced two false
    urgent pages in one day, on an empty ufw shell and on LIBVIRT_OUT's
    DHCP/DNS accepts, both while the DROP was firing at 42+ packets.

    It survives as the EXPLANATION attached to a failed probe, so the operator
    still learns what accepted first. Defined AND called, because a rename
    touching only one leaves the name present while breaking the script."""
    assert "egress_failure_detail" in MONITOR
    assert MONITOR.count("egress_preempted_by") >= 2, (
        "egress_preempted_by is defined or called, but not both")


def test_structural_preemption_does_not_alarm_on_its_own():
    """The alarm is the probe. Re-promoting the heuristic brings back both
    false pages, and it touches the PAUSE file."""
    body = MONITOR[MONITOR.index("check_egress() {"):]
    body = body[:body.index("\n}")]
    assert "egress_preempted_by" not in body, (
        "check_egress calls the structural heuristic again; it answers 'does a "
        "chain above contain an ACCEPT', not 'does anything accept THIS traffic'")


def test_the_monitor_probes_effectiveness_not_just_presence():
    """A rule that EXISTS satisfied every check for the whole day it did
    nothing."""
    assert "INEFFECTIVE" in MONITOR
    assert MONITOR.count("probe_egress") >= 3, "probe defined but never called"


def test_the_probe_targets_a_local_port_so_it_generates_no_egress():
    probe = MONITOR[MONITOR.index("probe_egress() {"):]
    probe = probe[:probe.index("\n}")]
    targets = re.findall(r"/dev/tcp/([0-9.]+)/(\d+)", probe)
    assert targets, "the probe no longer opens a connection"
    for host, _port in targets:
        assert host.startswith("127."), f"the probe dials {host}, leaving the host"
