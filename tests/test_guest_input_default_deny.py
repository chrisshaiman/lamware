# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""ADR-020, amended 2026-10-05: what a guest on virbr-det can reach on the HOST.

The air-gap is two FORWARD rules. A guest packet addressed to one of the host's own
addresses is delivered locally through INPUT, which the air-gap never sees, and INPUT's
policy is ACCEPT. Measured 2026-10-05: 45,481 guest SYNs to a gateway port on no
allowlist, every one answered by a host RST -- i.e. every one had passed INPUT.

Three layers, in the order CLAUDE.md §3 ranks them:

1. **Behavioural, in a network namespace.** `fixtures/guest_input_netns.py` builds the
   bridge, the host addresses and a guest under `unshare -rn`, seeds INPUT with the
   pre-ADR shape the host had, runs the role's own `guest_input.yml` with
   ansible-playbook (twice), and probes from the guest. Needs unprivileged user
   namespaces, `iptables` and `ansible-playbook`; skipped with the reason otherwise
   (the CI test job has neither). Set LAMWARE_XTABLES_BIN to a directory holding
   iptables/ip6tables(-restore) if they are not on PATH.
2. **`iptables-restore --test`** on the templates rendered here, under `unshare -rn`.
3. **Parsed structure** of the rendered chain. Structural, and labelled so: it runs where
   (1) cannot, and it pins the exhaustive allow list the ADR states, so widening what a
   guest can reach is a reviewed diff to this file rather than a one-line template edit.

None of this observes the host. The host probes are in the PR's Not verified section.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "networking"
HARNESS = ROOT / "tests" / "fixtures" / "guest_input_netns.py"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
GUEST_TASKS = yaml.safe_load((ROLE / "tasks" / "guest_input.yml").read_text())
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
INETSIM_CONF = (ROOT / "ansible" / "roles" / "inetsim" / "templates"
                / "inetsim.conf.j2").read_text()


def _vars() -> dict:
    """The values the role renders with: vars/main.yml.example, the cape and
    networking role defaults. The same sources a deploy reads."""
    example = yaml.safe_load((ROOT / "ansible" / "vars" / "main.yml.example").read_text())
    cape = yaml.safe_load((ROOT / "ansible" / "roles" / "cape" / "defaults"
                           / "main.yml").read_text())
    v = {k: example[k] for k in ("detonation_bridge", "detonation_gateway",
                                 "inetsim_dns_port")}
    v["cape_resultserver_port"] = cape["cape_resultserver_port"]
    v.update(DEFAULTS)
    return v


VARS = _vars()
GW = VARS["detonation_gateway"]
CHAIN = VARS["networking_guest_input_chain"]


def _render(suffix: str) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)
    src = (ROLE / "templates" / f"guest-input.rules.{suffix}.j2").read_text()
    return env.from_string(src).render(**VARS)


def _chain_rules(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.startswith(f"-A {CHAIN} ")]


def _opt(rule: str, flag: str) -> str | None:
    m = re.search(rf"(?:^|\s){re.escape(flag)} (\S+)", rule)
    return m.group(1) if m else None


def _accepts(rules: list[str]) -> set[tuple]:
    """(proto, port-or-icmp-type, destination) for every ACCEPT except conntrack."""
    out = set()
    for r in rules:
        if not r.endswith("-j ACCEPT") or "--ctstate" in r:
            continue
        port = _opt(r, "--dport") or _opt(r, "--icmp-type") or _opt(r, "--icmpv6-type")
        out.add((_opt(r, "-p"), port, _opt(r, "-d")))
    return out


# --- layer 3: parsed structure of the rendered chain ------------------------

def test_v4_chain_is_exactly_the_adr_allowlist():
    """Structural. The ADR's exhaustive list of what a guest can open on the host.
    Widening it is a decision, so it is a diff here, not only a template edit."""
    gw = f"{GW}/32"
    dns = str(VARS["inetsim_dns_port"])
    expected = {("udp", "67", None),
                ("udp", "53", gw), ("tcp", "53", gw),
                ("udp", dns, gw), ("tcp", dns, gw),
                ("tcp", "80", gw), ("tcp", "443", gw), ("tcp", "25", gw), ("tcp", "21", gw),
                ("tcp", str(VARS["cape_resultserver_port"]), gw),
                ("icmp", "8", gw)}
    assert _accepts(_chain_rules(_render("v4"))) == expected


def test_v4_chain_order_established_first_reject_last():
    """Structural. ESTABLISHED first or every detonation dies at guest init (#620's
    shape); the two REJECTs last and nothing after them; never DROP, because a closed
    port must answer exactly as the kernel did (RST / port-unreachable)."""
    rules = _chain_rules(_render("v4"))
    assert "--ctstate RELATED,ESTABLISHED" in rules[0] and rules[0].endswith("-j ACCEPT")
    assert rules[-2].endswith("-j REJECT --reject-with tcp-reset") and "-p tcp" in rules[-2]
    assert rules[-1].endswith("-j REJECT --reject-with icmp-port-unreachable")
    assert _opt(rules[-1], "-p") is None, "the last rule must match everything"
    assert not any(r.endswith("-j DROP") for r in rules)


def test_every_v4_service_allow_is_scoped_to_the_gateway():
    """Structural. A port-only match accepts the same port on ANY host address -- the
    WireGuard address, the public address. Only DHCP (broadcast) is exempt."""
    for proto, port, dest in _accepts(_chain_rules(_render("v4"))):
        if (proto, port) == ("udp", "67"):
            continue
        assert dest == f"{GW}/32", f"{proto}/{port} is not scoped to the gateway"


def test_v6_chain_mirrors_the_structure_and_opens_no_service():
    """Structural (#343: both families). IPv6 is disabled on the host; the chain exists
    so that enabling it does not open the guest path."""
    rules = _chain_rules(_render("v6"))
    assert "--ctstate RELATED,ESTABLISHED" in rules[0]
    assert rules[-2].endswith("-j REJECT --reject-with tcp-reset")
    assert rules[-1].endswith("-j REJECT --reject-with icmp6-port-unreachable")
    assert _accepts(rules) == {("ipv6-icmp", "135", None), ("ipv6-icmp", "136", None),
                               ("ipv6-icmp", "128", None)}


def test_inetsim_ports_are_the_ones_inetsim_binds():
    """Structural. inetsim.conf.j2 binds its TCP services on literal ports; the chain's
    list is a copy. Parsed from both so the copies cannot drift apart silently."""
    bound = {int(p) for p in re.findall(r"^\w+_bind_port\s+(\d+)\s*$", INETSIM_CONF, re.M)}
    started = set(re.findall(r"^start_service\s+(\w+)", INETSIM_CONF, re.M))
    assert bound, "parsed no literal bind ports from inetsim.conf.j2 -- fix the parser"
    assert started == {"dns", "http", "https", "smtp", "ftp"}, (
        f"INetSim starts {started}; a new service needs a port in the guest chain")
    assert bound == set(VARS["networking_inetsim_tcp_ports"])


def test_main_imports_the_chain_and_inserts_no_input_accepts():
    """Structural. import_tasks (static) so `TAGS=networking` runs it; and no task in
    main.yml inserts an INPUT ACCEPT again -- one would sit above or below the jump and
    either be dead or bypass the chain."""
    imports = [t for t in TASKS if isinstance(t, dict)
               and t.get("ansible.builtin.import_tasks") == "guest_input.yml"]
    assert len(imports) == 1
    for t in TASKS + GUEST_TASKS:
        ipt = t.get("ansible.builtin.iptables") if isinstance(t, dict) else None
        if isinstance(ipt, dict) and ipt.get("chain") == "INPUT":
            assert ipt.get("state") == "absent", f"INPUT rule inserted by {t.get('name')}"


def test_retirement_covers_every_old_per_port_accept():
    """Structural. The nine specs main.yml inserted before the ADR-020 amendment
    (as of da717da). `iptables -D` only deletes an exact match, so a misspelt comment
    leaves the old rule on the host."""
    retire = next(t for t in GUEST_TASKS if "Retire" in t.get("name", ""))
    specs = {(i["proto"], str(i["port"]), i["comment"]) for i in retire["loop"]}
    dns = "{{ inetsim_dns_port }}"
    rs = "{{ cape_resultserver_port }}"
    assert specs == {
        ("udp", "53", "INetSim: guest DNS (UDP)"), ("tcp", "53", "INetSim: guest DNS (TCP)"),
        ("udp", dns, "INetSim: guest DNS (UDP, post-redirect)"),
        ("tcp", dns, "INetSim: guest DNS (TCP, post-redirect)"),
        ("tcp", "80", "INetSim: guest HTTP"), ("tcp", "443", "INetSim: guest HTTPS"),
        ("tcp", "25", "INetSim: guest SMTP"), ("tcp", "21", "INetSim: guest FTP"),
        ("tcp", rs, "Cape: guest resultserver")}


# --- shared: can this machine run the namespace layers? ---------------------

def _env() -> dict:
    env = dict(os.environ)
    extra = env.get("LAMWARE_XTABLES_BIN")
    if extra:
        env["PATH"] = f"{extra}{os.pathsep}{env['PATH']}"
    return env


def _netns_unavailable() -> str | None:
    env = _env()
    if shutil.which("unshare") is None:
        return "unshare not installed"
    if shutil.which("iptables", path=env["PATH"]) is None:
        return "iptables not on PATH (set LAMWARE_XTABLES_BIN)"
    r = subprocess.run(["unshare", "-rn", "iptables", "-w", "-S"], capture_output=True,
                       text=True, env=env, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        return f"no unprivileged user+net namespace with iptables: {r.stderr.strip()[:200]}"
    return None


_NETNS_SKIP = _netns_unavailable()
needs_netns = pytest.mark.skipif(_NETNS_SKIP is not None, reason=_NETNS_SKIP or "")
needs_ansible = pytest.mark.skipif(shutil.which("ansible-playbook") is None,
                                   reason="ansible-playbook not installed")


# --- layer 2: the kernel's parser accepts what the role renders -------------

@needs_netns
@pytest.mark.parametrize("family,suffix", [("iptables", "v4"), ("ip6tables", "v6")])
def test_rendered_chain_passes_iptables_restore_test(tmp_path, family, suffix):
    f = tmp_path / f"rules.{suffix}"
    f.write_text(_render(suffix))
    r = subprocess.run(["unshare", "-rn", f"{family}-restore", "--test", "--noflush", str(f)],
                       capture_output=True, text=True, env=_env(), stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr


# --- layer 1: run the role in a namespace and probe from a guest ------------

# What a guest sees AFTER the role has run. Closed ports answer as they always did;
# open ports that are not on the ADR's list are refused; the allowlist works; the
# host can still reach the guest agent (ESTABLISHED), in both families.
EXPECTED_AFTER = {
    "closed_tcp_gw_5201": "refused", "closed_udp_gw_9999": "refused",
    "open_tcp_gw_22": "refused", "open_tcp_wg_22": "refused",
    "open_tcp_wg_8000": "refused", "open_tcp_wg_443": "refused",
    "open_tcp_wg_80": "refused", "open_tcp_public_22": "refused",
    "open_udp_gw_5353": "refused",
    "inetsim_tcp_gw_80": "open", "inetsim_tcp_gw_443": "open",
    "inetsim_tcp_gw_25": "open", "inetsim_tcp_gw_21": "open",
    "resultserver_tcp_gw_2042": "open",
    "dns_udp_gw_53": "answer", "dns_tcp_gw_53": "open", "dns_udp_gw_5300": "answer",
    "ping_gw": "reply", "ping_wg": "none",
    "open_tcp6_gw_2222": "refused", "closed_tcp6_gw_5201": "refused", "ping6_gw": "reply",
    "host_to_guest_agent": "open", "host_to_guest_agent_v6": "open",
}

# Pre-ADR, the same probes reach every listener. If these stop being "open" the
# harness has stopped measuring, and EXPECTED_AFTER would pass vacuously.
OPEN_BEFORE = ["open_tcp_gw_22", "open_tcp_wg_22", "open_tcp_wg_8000", "open_tcp_wg_443",
               "open_tcp_wg_80", "open_tcp_public_22", "open_tcp6_gw_2222"]


def _run_harness(tmp_path: Path, roles: Path, runs: int) -> dict:
    vars_file = tmp_path / "vars.yml"
    vars_file.write_text(yaml.safe_dump({
        "detonation_bridge": VARS["detonation_bridge"],
        "detonation_gateway": VARS["detonation_gateway"],
        "inetsim_dns_port": VARS["inetsim_dns_port"],
        "cape_resultserver_port": VARS["cape_resultserver_port"],
        "networking_guest_input_dir": str(tmp_path),
    }))
    r = subprocess.run(
        ["unshare", "-rn", sys.executable, str(HARNESS), "--roles-path", str(roles),
         "--vars", str(vars_file), "--workdir", str(tmp_path), "--runs", str(runs)],
        capture_output=True, text=True, env=_env(), stdin=subprocess.DEVNULL, timeout=600)
    assert r.returncode == 0, r.stderr[-3000:]
    return json.loads(r.stdout)


@pytest.fixture(scope="module")
def clean_run(tmp_path_factory):
    if _NETNS_SKIP is not None:
        pytest.skip(_NETNS_SKIP)
    if shutil.which("ansible-playbook") is None:
        pytest.skip("ansible-playbook not installed")
    return _run_harness(tmp_path_factory.mktemp("guest-in"), ROLE.parent, runs=2)


@needs_netns
@needs_ansible
def test_the_harness_reproduces_the_hole_before_the_role_runs(clean_run):
    before = clean_run["before"]
    assert {k: before[k] for k in OPEN_BEFORE} == {k: "open" for k in OPEN_BEFORE}


@needs_netns
@needs_ansible
def test_after_the_role_a_guest_reaches_exactly_the_allowlist(clean_run):
    assert clean_run["runs"][0]["rc"] == 0, clean_run["runs"][0]["tail"]
    assert clean_run["after"] == EXPECTED_AFTER


@needs_netns
@needs_ansible
def test_closed_ports_answer_exactly_as_before(clean_run):
    """REJECT, not DROP: a sample probing a closed gateway port must see the same
    refusal, not a timeout."""
    for k in ("closed_tcp_gw_5201", "closed_udp_gw_9999", "closed_tcp6_gw_5201"):
        assert clean_run["after"][k] == clean_run["before"][k] == "refused"


@needs_netns
@needs_ansible
def test_second_run_changes_nothing(clean_run):
    assert clean_run["runs"][1]["rc"] == 0, clean_run["runs"][1]["tail"]
    assert clean_run["runs"][1]["changed"] == []


@needs_netns
@needs_ansible
def test_live_state_is_migrated(clean_run):
    """The host already carries the nine per-port ACCEPTs and a fail2ban jump at the
    top. Afterwards: the jump is rule 1 in both families, the old ACCEPTs are gone."""
    for fam in ("iptables_S", "ip6tables_S"):
        rules = [ln for ln in clean_run[fam].splitlines() if ln.startswith("-A INPUT ")]
        assert rules[0] == f"-A INPUT -i virbr-det -j {CHAIN}", fam
        assert rules.count(rules[0]) == 1, fam
    assert "INetSim: guest" not in clean_run["iptables_S"]
    assert "Cape: guest resultserver" not in clean_run["iptables_S"]


# --- mutations: each property above must be one that a broken role fails -----

V4 = "templates/guest-input.rules.v4.j2"
V6 = "templates/guest-input.rules.v6.j2"
SCRIPT = "files/apply-guest-input.sh"
TASKFILE = "tasks/guest_input.yml"

MUTATIONS = {
    # name: (file, regex to delete-or-replace, replacement, probe, value-that-proves-it)
    "no_established": (V4, r"^-A .*--ctstate RELATED,ESTABLISHED.*\n", "",
                       "host_to_guest_agent", "timeout"),
    "no_established_v6": (V6, r"^-A .*--ctstate RELATED,ESTABLISHED.*\n", "",
                          "host_to_guest_agent_v6", "timeout"),
    "no_reject": (V4, r"^-A .*-j REJECT.*\n", "", "open_tcp_wg_8000", "open"),
    "jump_appended_not_first": (SCRIPT, r'-I INPUT 1 -i', "-A INPUT -i",
                                "open_tcp_gw_22", "open"),
    "no_resultserver": (V4, r"^-A .*CAPE resultserver.*\n", "",
                        "resultserver_tcp_gw_2042", "refused"),
    "inetsim_unscoped": (V4, r"(-A \{\{ networking_guest_input_chain \}\}) -d "
                             r"\{\{ detonation_gateway \}\}/32 (-p tcp -m tcp --dport "
                             r"\{\{ port \}\})", r"\1 \2", "open_tcp_wg_443", "open"),
}


@needs_netns
@needs_ansible
@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_mutation_is_caught(tmp_path, name):
    rel, pattern, repl, probe, proof = MUTATIONS[name]
    roles = tmp_path / "roles"
    shutil.copytree(ROLE, roles / "networking")
    target = roles / "networking" / rel
    src = target.read_text()
    mutated, n = re.subn(pattern, repl, src, flags=re.M)
    assert n > 0, f"mutation {name} matched nothing -- it tests nothing"
    target.write_text(mutated)
    result = _run_harness(tmp_path, roles, runs=1)
    assert result["after"][probe] == proof, (
        f"{name}: expected {probe}={proof}, got {result['after'][probe]}; "
        f"deploy rc={result['runs'][0]['rc']}")
    assert result["after"] != EXPECTED_AFTER


@needs_netns
@needs_ansible
def test_mutation_without_retirement_leaves_the_old_rules(tmp_path):
    """The old ACCEPTs are dead once the chain terminates, so no probe can see them;
    this one is read off the ruleset the role leaves behind."""
    roles = tmp_path / "roles"
    shutil.copytree(ROLE, roles / "networking")
    tf = roles / "networking" / TASKFILE
    tasks = yaml.safe_load(tf.read_text())
    tf.write_text(yaml.safe_dump([t for t in tasks if "Retire" not in t.get("name", "")]))
    result = _run_harness(tmp_path, roles, runs=1)
    assert "INetSim: guest HTTP" in result["iptables_S"]
