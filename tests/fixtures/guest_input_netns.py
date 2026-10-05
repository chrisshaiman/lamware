# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Run roles/networking's guest_input.yml in a throwaway network namespace and probe it.

Invoked by tests/test_guest_input_default_deny.py as

    unshare -rn python3 guest_input_netns.py --roles-path R --vars V --workdir W

so this process is root in a new user + network namespace and nothing it does touches
the machine running the tests. It builds a small copy of the host's topology:

    host netns   virbr-det 192.168.100.1/24 (+ fd00:100::1/64)   the bridge
                 wg0       10.200.0.1/24    (dummy)                the WireGuard address
                 mgmt0     203.0.113.8/24   (dummy)                a public address (TEST-NET-3)
    guest netns  veth      192.168.100.20/24, default via the gateway, enslaved to virbr-det

seeds INPUT with the shape the host had on 2026-10-05, before the amendment (fail2ban jump, the
nine per-port guest ACCEPTs with their exact comments, LIBVIRT_INP, the DNS redirect)
plus one interface-agnostic `--dport 22 ACCEPT` standing in for an allow someone adds to
INPUT later, opens listeners where the host has them, probes from the guest, runs the
role's tasks with ansible-playbook (twice, for idempotency), and probes again.

Prints one JSON object on stdout. It asserts nothing: the test decides what is right.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

BRIDGE = "virbr-det"
GW = "192.168.100.1"
GW6 = "fd00:100::1"
GUEST = "192.168.100.20"
GUEST6 = "fd00:100::20"
WG = "10.200.0.1"
PUBLIC = "203.0.113.8"
CHAIN = "LAMWARE-GUEST-IN"

# Where the host has listeners (2026-10-05): sshd on the wildcard, nginx and the CAPE
# UI on the WireGuard address, INetSim and the resultserver on the gateway. 5201 and
# 9999 have nothing listening: they are the closed-port controls.
TCP_LISTENERS = [("0.0.0.0", 22), (WG, 8000), (WG, 443), (WG, 80),
                 (GW, 80), (GW, 443), (GW, 25), (GW, 21), (GW, 2042), (GW, 5300)]
TCP6_LISTENERS = [("::", 2222)]
UDP_LISTENERS = [(GW, 5300), ("0.0.0.0", 5353)]

PROBES = [
    # (name, kind, address, port)
    ("closed_tcp_gw_5201", "tcp", GW, 5201),
    ("closed_udp_gw_9999", "udp", GW, 9999),
    ("open_tcp_gw_22", "tcp", GW, 22),
    ("open_tcp_wg_22", "tcp", WG, 22),
    ("open_tcp_wg_8000", "tcp", WG, 8000),
    ("open_tcp_wg_443", "tcp", WG, 443),
    ("open_tcp_wg_80", "tcp", WG, 80),
    ("open_tcp_public_22", "tcp", PUBLIC, 22),
    ("open_udp_gw_5353", "udp", GW, 5353),
    ("inetsim_tcp_gw_80", "tcp", GW, 80),
    ("inetsim_tcp_gw_443", "tcp", GW, 443),
    ("inetsim_tcp_gw_25", "tcp", GW, 25),
    ("inetsim_tcp_gw_21", "tcp", GW, 21),
    ("resultserver_tcp_gw_2042", "tcp", GW, 2042),
    ("dns_udp_gw_53", "udp", GW, 53),        # redirected to 5300 in PREROUTING
    ("dns_tcp_gw_53", "tcp", GW, 53),
    ("dns_udp_gw_5300", "udp", GW, 5300),
    ("ping_gw", "ping", GW, 0),
    ("ping_wg", "ping", WG, 0),
    ("open_tcp6_gw_2222", "tcp6", GW6, 2222),
    ("closed_tcp6_gw_5201", "tcp6", GW6, 5201),
    ("ping6_gw", "ping6", GW6, 0),
]

PROBE_SCRIPT = r"""
import json, socket, subprocess, sys
out = {}
for name, kind, addr, port in json.loads(sys.argv[1]):
    if kind in ("tcp", "tcp6"):
        fam = socket.AF_INET6 if kind == "tcp6" else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(1.5)
        try:
            s.connect((addr, port)); out[name] = "open"
        except ConnectionRefusedError:
            out[name] = "refused"
        except OSError as e:
            out[name] = "timeout" if isinstance(e, TimeoutError) else type(e).__name__
        finally:
            s.close()
    elif kind == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5)
        try:
            s.connect((addr, port)); s.send(b"q"); s.recv(64); out[name] = "answer"
        except ConnectionRefusedError:
            out[name] = "refused"
        except TimeoutError:
            out[name] = "timeout"
        finally:
            s.close()
    else:
        args = ["ping", "-6" if kind == "ping6" else "-4", "-c1", "-W1", addr]
        r = subprocess.run(args, capture_output=True)
        out[name] = "reply" if r.returncode == 0 else "none"
print(json.dumps(out))
"""


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, check=check,
                          stdin=subprocess.DEVNULL)


def tcp_server(addr: str, port: int, fam: int = socket.AF_INET) -> None:
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, port))
    s.listen(16)

    def loop() -> None:
        while True:
            c, _ = s.accept()
            try:
                c.sendall(b"ok")
            finally:
                c.close()
    threading.Thread(target=loop, daemon=True).start()


def udp_server(addr: str, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))

    def loop() -> None:
        while True:
            data, peer = s.recvfrom(64)
            s.sendto(b"a" + data, peer)
    threading.Thread(target=loop, daemon=True).start()


def topology() -> int:
    """Build the bridge, the host addresses and a guest netns; return the guest pid."""
    sh("ip", "link", "set", "lo", "up")
    sh("ip", "link", "add", BRIDGE, "type", "bridge")
    sh("ip", "addr", "add", f"{GW}/24", "dev", BRIDGE)
    sh("ip", "-6", "addr", "add", f"{GW6}/64", "dev", BRIDGE, "nodad")
    sh("ip", "link", "set", BRIDGE, "up")
    for dev, addr in (("wg0", WG), ("mgmt0", PUBLIC)):
        sh("ip", "link", "add", dev, "type", "dummy")
        sh("ip", "addr", "add", f"{addr}/24", "dev", dev)
        sh("ip", "link", "set", dev, "up")
    # Its own stdout, not ours: an inherited pipe would hold the caller's read open
    # for as long as the sleep lives, and the test would wait the full 600 s.
    guest = subprocess.Popen(["unshare", "-n", "sleep", "600"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    pid = str(guest.pid)
    sh("ip", "link", "add", "veth-h", "type", "veth", "peer", "name", "veth-g")
    sh("ip", "link", "set", "veth-h", "master", BRIDGE)
    sh("ip", "link", "set", "veth-h", "up")
    sh("ip", "link", "set", "veth-g", "netns", pid)
    g = ("nsenter", "-t", pid, "-n")
    sh(*g, "ip", "link", "set", "lo", "up")
    sh(*g, "ip", "addr", "add", f"{GUEST}/24", "dev", "veth-g")
    sh(*g, "ip", "-6", "addr", "add", f"{GUEST6}/64", "dev", "veth-g", "nodad")
    sh(*g, "ip", "link", "set", "veth-g", "up")
    sh(*g, "ip", "route", "add", "default", "via", GW)
    return guest.pid


def seed_pre_adr_state() -> None:
    """INPUT as the host had it before the ADR-020 amendment, read live on 2026-10-05."""
    ipt = ("iptables", "-w")
    sh(*ipt, "-t", "nat", "-A", "PREROUTING", "-i", BRIDGE, "-p", "udp", "--dport", "53",
       "-j", "REDIRECT", "--to-ports", "5300")
    sh(*ipt, "-t", "nat", "-A", "PREROUTING", "-i", BRIDGE, "-p", "tcp", "--dport", "53",
       "-j", "REDIRECT", "--to-ports", "5300")
    # The nine per-port ACCEPTs, spelled exactly as the old insert tasks spelled them.
    old = [("udp", "53", "INetSim: guest DNS (UDP)"), ("tcp", "53", "INetSim: guest DNS (TCP)"),
           ("udp", "5300", "INetSim: guest DNS (UDP, post-redirect)"),
           ("tcp", "5300", "INetSim: guest DNS (TCP, post-redirect)"),
           ("tcp", "80", "INetSim: guest HTTP"), ("tcp", "443", "INetSim: guest HTTPS"),
           ("tcp", "25", "INetSim: guest SMTP"), ("tcp", "21", "INetSim: guest FTP"),
           ("tcp", "2042", "Cape: guest resultserver")]
    for proto, port, comment in old:
        sh(*ipt, "-A", "INPUT", "-i", BRIDGE, "-p", proto, "--dport", port,
           "-m", "comment", "--comment", comment, "-j", "ACCEPT")
    sh(*ipt, "-N", "LIBVIRT_INP")
    for proto, port in (("udp", "53"), ("tcp", "53"), ("udp", "67"), ("tcp", "67")):
        sh(*ipt, "-A", "LIBVIRT_INP", "-i", BRIDGE, "-p", proto, "--dport", port, "-j", "ACCEPT")
    sh(*ipt, "-A", "INPUT", "-j", "LIBVIRT_INP")
    sh(*ipt, "-N", "ufw-before-input")
    sh(*ipt, "-A", "INPUT", "-j", "ufw-before-input")
    # An allow that is not about guests at all, of the kind a later change adds. Below
    # the guest jump it must not apply to guests; above it, it would.
    sh(*ipt, "-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "comment",
       "--comment", "simulated later allow", "-j", "ACCEPT")
    # fail2ban inserts its jump at the top when it starts.
    sh(*ipt, "-N", "f2b-sshd")
    sh(*ipt, "-A", "f2b-sshd", "-j", "RETURN")
    sh(*ipt, "-I", "INPUT", "1", "-p", "tcp", "-m", "multiport", "--dports", "22",
       "-j", "f2b-sshd")


def probe_from_guest(pid: int) -> dict:
    r = sh("nsenter", "-t", str(pid), "-n", sys.executable, "-c", PROBE_SCRIPT,
           json.dumps(PROBES), check=False)
    if r.returncode != 0:
        return {"error": r.stderr[-2000:]}
    return json.loads(r.stdout)


def probe_host_to_guest(pid: int) -> dict:
    """CAPE drives the guest agent host -> guest; the replies come back through INPUT."""
    agent = subprocess.Popen(
        ["nsenter", "-t", str(pid), "-n", sys.executable, "-c",
         "import socket\n"
         "s = socket.socket(socket.AF_INET6)\n"
         "s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n"
         "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
         "s.bind(('::', 8000)); s.listen(4)\n"
         "while True:\n"
         "    c, _ = s.accept(); c.sendall(b'agent'); c.close()\n"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.4)
    out = {}
    for name, fam, addr in (("host_to_guest_agent", socket.AF_INET, GUEST),
                            ("host_to_guest_agent_v6", socket.AF_INET6, GUEST6)):
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((addr, 8000))
            out[name] = "open" if s.recv(16) == b"agent" else "no-data"
        except ConnectionRefusedError:
            out[name] = "refused"
        except OSError as e:
            out[name] = "timeout" if isinstance(e, TimeoutError) else type(e).__name__
        finally:
            s.close()
    agent.kill()
    agent.wait()
    return out


def run_role(roles_path: str, vars_file: str, workdir: Path) -> dict:
    pb = workdir / "play.yml"
    pb.write_text(
        "- hosts: localhost\n"
        "  connection: local\n"
        "  gather_facts: false\n"
        "  tasks:\n"
        "    - ansible.builtin.include_role:\n"
        "        name: networking\n"
        "        tasks_from: guest_input\n")
    env = dict(os.environ, ANSIBLE_ROLES_PATH=roles_path, ANSIBLE_NOCOLOR="1",
               ANSIBLE_LOCAL_TEMP=str(workdir / "ansible-local"),
               ANSIBLE_REMOTE_TEMP=str(workdir / "ansible-remote"),
               ANSIBLE_PYTHON_INTERPRETER=sys.executable,
               ANSIBLE_STDOUT_CALLBACK="default")
    r = subprocess.run(["ansible-playbook", "-i", "localhost,", "-e", f"@{vars_file}", str(pb)],
                       capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    recap = [ln for ln in r.stdout.splitlines() if ln.startswith("localhost")]
    changed, task = [], ""
    for ln in r.stdout.splitlines():
        if ln.startswith("TASK ["):
            task = ln[6:ln.index("]")]
        elif ln.startswith("changed:") and task not in changed:
            changed.append(task)
    return {"rc": r.returncode, "recap": recap[-1] if recap else "", "changed": changed,
            "tail": "" if r.returncode == 0 else r.stdout[-3000:] + r.stderr[-1500:]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roles-path", required=True)
    ap.add_argument("--vars", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--runs", type=int, default=2)
    a = ap.parse_args()
    work = Path(a.workdir)

    pid = topology()
    seed_pre_adr_state()
    for addr, port in TCP_LISTENERS:
        tcp_server(addr, port)
    for addr, port in TCP6_LISTENERS:
        tcp_server(addr, port, socket.AF_INET6)
    for addr, port in UDP_LISTENERS:
        udp_server(addr, port)
    time.sleep(0.2)

    result = {"before": {**probe_from_guest(pid), **probe_host_to_guest(pid)}}
    result["runs"] = [run_role(a.roles_path, a.vars, work) for _ in range(a.runs)]
    result["after"] = {**probe_from_guest(pid), **probe_host_to_guest(pid)}
    result["iptables_S"] = sh("iptables", "-w", "-S", check=False).stdout
    result["ip6tables_S"] = sh("ip6tables", "-w", "-S", check=False).stdout
    print(json.dumps(result), flush=True)
    os.kill(pid, 9)


if __name__ == "__main__":
    main()
