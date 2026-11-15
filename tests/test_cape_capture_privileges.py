# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE's sniffer captures through a root helper, on the detonation bridge only (ADR-029).

The helper is rendered and its own code is run here: the argument check against
exactly what CAPE's sniffer sends and against what it must refuse, the file open
(as cape, never through a link), and the tcpdump command it executes. The task
file is checked for ORDER (capture is proven before the old rights go), which
cannot be observed without the host; the host evidence is in the PR.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "cape"
TASKS = yaml.safe_load((ROLE / "tasks" / "capture-privileges.yml").read_text())
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
ANALYSES = "/opt/CAPEv2/storage/analyses"


def _helper() -> dict:
    src = jinja2.Template((ROLE / "templates" / "lamware-capture.j2").read_text()).render(
        cape_capture_helper="/usr/local/sbin/lamware-capture", cape_capture_interface="virbr-det",
        cape_user="cape", cape_vm_dump_analyses_dir=ANALYSES)
    ns: dict = {"__name__": "lamware_capture"}
    exec(compile(src, "lamware-capture", "exec"), ns)  # noqa: S102
    return ns


H = _helper()


def _cape_argv(iface="virbr-det", user="cape", path=f"{ANALYSES}/1318/dump.pcap", bpf="not arp"):
    """What modules/auxiliary/sniffer.py passes after the tcpdump path (CAPE 2026-11)."""
    host, rs, rport, gport = "192.168.100.10", "192.168.100.1", "2042", "8000"
    return (["-U", "-q", "-s", "0", "-i", iface, "-n", "-Z", user, "-w", path, "host", host,
             "and", "not", "(", "dst", "host", host, "and", "dst", "port", gport, ")",
             "and", "not", "(", "src", "host", host, "and", "src", "port", gport, ")",
             "and", "not", "(", "dst", "host", rs, "and", "dst", "port", rport, ")",
             "and", "not", "(", "src", "host", rs, "and", "src", "port", rport, ")"]
            + (["and", "(", bpf, ")"] if bpf else []))


# --- the argument check ------------------------------------------------------------

def test_capes_own_arguments_are_accepted():
    path, filt = H["parse"](_cape_argv())
    assert path == f"{ANALYSES}/1318/dump.pcap"
    assert filt[:2] == ["host", "192.168.100.10"] and filt[-2:] == ["not arp", ")"]


@pytest.mark.parametrize("argv, why", [
    (_cape_argv(iface="lo"), "interface"),
    (_cape_argv(iface="wg0"), "interface"),
    (_cape_argv(user="root"), "-Z"),
    (_cape_argv(path="/etc/shadow"), "-w"),
    (_cape_argv(path=f"{ANALYSES}/1/../../../../etc/cron.d/x"), "-w"),
    (_cape_argv(path=f"{ANALYSES}/1/dump.pcap.sh"), "-w"),
    (_cape_argv(path=f"{ANALYSES}/latest/dump.pcap"), "-w"),
    (_cape_argv(bpf="-z /tmp/x"), "filter"),
    (_cape_argv(bpf="not arp; id"), "filter"),
    (_cape_argv(bpf="$(id)"), "filter"),
    (_cape_argv()[:10], "arguments"),
    (["-r", "/etc/shadow"] + _cape_argv()[2:], "argument 1"),
    (_cape_argv()[:4] + ["-z", "x"] + _cape_argv()[6:], "argument 5"),
])
def test_anything_else_is_refused(argv, why):
    with pytest.raises(H["Refused"], match=why):
        H["parse"](argv)


def test_main_refuses_with_status_2_before_opening_anything(monkeypatch, capsys):
    monkeypatch.setattr(H["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(H["os"], "open", lambda *a, **k: pytest.fail("opened a file"))
    assert H["main"](_cape_argv(iface="lo")) == 2
    assert "refused: interface 'lo'" in capsys.readouterr().err


def test_main_refuses_without_root(monkeypatch):
    monkeypatch.setattr(H["os"], "geteuid", lambda: 1001)
    assert H["main"](_cape_argv()) == 2


def test_tcpdump_gets_the_fixed_interface_stdout_and_the_filter_after_double_dash(monkeypatch, tmp_path):
    os_ = H["os"]
    seen = {}
    monkeypatch.setattr(os_, "geteuid", lambda: 0)
    monkeypatch.setitem(H, "open_as", lambda user, path: os_.open(tmp_path / "f", os_.O_WRONLY | os_.O_CREAT))
    monkeypatch.setattr(os_, "dup2", lambda fd, to: seen.setdefault("dup2", to))
    monkeypatch.setattr(os_, "execve", lambda prog, argv, env: seen.update(prog=prog, argv=argv, env=env))
    H["main"](_cape_argv())
    argv = seen["argv"]
    assert seen["prog"] == "/usr/bin/tcpdump" and seen["dup2"] == 1
    assert argv[argv.index("-i") + 1] == "virbr-det"
    assert argv[argv.index("-Z") + 1] == "cape"
    assert argv[argv.index("-w") + 1] == "-"
    dd = argv.index("--")
    assert argv[dd + 1:] == _cape_argv()[11:]
    assert all(not a.startswith("-") for a in argv[dd + 1:])
    assert seen["env"]["PATH"].startswith("/usr/sbin")


# --- the file open ------------------------------------------------------------------

@pytest.fixture
def as_me(monkeypatch):
    """open_as without privilege changes: record them instead."""
    os_ = H["os"]
    calls = []
    for name in ("setgroups", "setegid", "seteuid"):
        monkeypatch.setattr(os_, name, lambda v, _n=name: calls.append((_n, v)))
    monkeypatch.setattr(os_, "fchown", lambda fd, u, g: calls.append(("fchown", g)))
    return calls


def test_the_file_is_opened_after_becoming_cape_and_root_is_restored(as_me, tmp_path):
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name
    fd = H["open_as"](me, str(tmp_path / "dump.pcap"))
    os.close(fd)
    names = [c[0] for c in as_me]
    assert names == ["setgroups", "setegid", "seteuid", "fchown", "seteuid", "setegid", "setgroups"]
    assert as_me[2] == ("seteuid", os.getuid()) and as_me[4] == ("seteuid", 0)
    assert oct((tmp_path / "dump.pcap").stat().st_mode & 0o777) == "0o640"


def test_a_link_at_the_pcap_path_is_not_followed(as_me, tmp_path):
    import pwd
    target = tmp_path / "victim"
    target.write_text("keep")
    os.symlink(target, tmp_path / "dump.pcap")
    with pytest.raises(OSError):
        H["open_as"](pwd.getpwuid(os.getuid()).pw_name, str(tmp_path / "dump.pcap"))
    assert target.read_text() == "keep"
    assert ("seteuid", 0) in as_me, "privileges were not restored after a failed open"


# --- the role -------------------------------------------------------------------------

def _names():
    return [t.get("name") for t in TASKS]


def _task(name):
    return next(t for t in TASKS if t.get("name") == name)


def test_capture_through_the_helper_is_proven_before_the_old_rights_go():
    n = _names()
    probe = n.index("Check cape can capture on the detonation bridge through the helper")
    for before in ("Install the capture helper (root-owned; ADR-029)",
                   "Let cape run the capture helper through sudo",
                   "Point CAPE's sniffer at the capture helper"):
        assert n.index(before) < probe, before
    for after in ("Remove tcpdump's capture capabilities", "Take cape out of the pcap group",
                  "Remove the pcap group"):
        assert probe < n.index(after), after


def test_the_probe_runs_as_cape_through_sudo_and_checks_the_file():
    t = _task("Check cape can capture on the detonation bridge through the helper")
    cmd = t["ansible.builtin.shell"]["cmd"]
    assert "sudo -u {{ cape_user }} timeout 3 sudo -n {{ cape_capture_helper }}" in cmd
    assert "-i {{ cape_capture_interface }}" in cmd
    fw = t["failed_when"]
    assert "rc=124" in fw and "magic=d4c3b2a1" in fw and "owner=" in fw


def test_sudo_runs_the_helper_without_a_pty_so_cape_can_stop_it():
    c = _task("Let cape run the capture helper through sudo")["ansible.builtin.copy"]
    lines = [ln for ln in c["content"].splitlines() if ln and not ln.startswith("#")]
    assert lines == ["Defaults!{{ cape_capture_helper }} !use_pty",
                     "{{ cape_user }} ALL=(root) NOPASSWD: {{ cape_capture_helper }}"]
    assert c["validate"] == "visudo -cf %s" and c["mode"] == "0440"


def test_the_sniffer_runs_the_helper():
    t = _task("Point CAPE's sniffer at the capture helper")["community.general.ini_file"]
    assert (t["section"], t["option"], t["value"]) == ("sniffer", "tcpdump", "{{ cape_capture_helper }}")


def test_capabilities_group_and_reapply_hook_are_removed():
    assert _task("Remove tcpdump's capture capabilities")["ansible.builtin.command"] == "setcap -r /usr/bin/tcpdump"
    hook = _task("Remove the apt hook and script that re-applied them")
    assert hook["ansible.builtin.file"]["state"] == "absent"
    assert "/etc/apt/apt.conf.d/80-lamware-tcpdump-caps" in hook["loop"]
    assert _task("Remove the pcap group")["ansible.builtin.group"]["state"] == "absent"
    mode = _task("Give tcpdump the package's owner and mode back")["ansible.builtin.file"]
    assert (mode["owner"], mode["group"], mode["mode"]) == ("root", "root", "0755")


def test_both_old_root_paths_are_removed_and_the_helper_is_the_only_grant():
    rm = _task("Remove the sudo rules that made cape root-equivalent")
    assert set(rm["loop"]) == {"tcpdump", "ip_netns"}
    that = _task("Refuse if a capture or netns rule other than the helper is granted")["ansible.builtin.assert"]["that"]
    assert "'tcpdump' not in cape_sudo_list.stdout" in that
    assert "cape_capture_helper in cape_sudo_list.stdout" in that


def test_the_helper_path_does_not_name_tcpdump():
    """The assert above greps sudo -l for 'tcpdump'; the helper's own path must not match."""
    assert "tcpdump" not in DEFAULTS["cape_capture_helper"]


def test_the_role_includes_the_file():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert any(t.get("ansible.builtin.import_tasks") == "capture-privileges.yml" for t in tasks)


def _mitmdump_guard(tmp_path, conf: str) -> int:
    """Run the role's own awk guard against a config; rc 0 means 'Mitmdump enabled'."""
    task = TASKS[0]
    assert task["name"] == "Refuse to drop the netns rule while Mitmdump is configured"
    cmd = task["ansible.builtin.command"].replace("{{ cape_install_dir }}", str(tmp_path))
    (tmp_path / "conf").mkdir(exist_ok=True)
    (tmp_path / "conf" / "auxiliary.conf").write_text(conf)
    return subprocess.run(["bash", "-c", cmd]).returncode


def test_the_mitmdump_guard_passes_the_shipped_disabled_section(tmp_path):
    shipped = "[auxiliary_modules]\nsniffer = yes\n\n[Mitmdump]\n# Enable [yes/no].\nenabled = no\n\n[PolarProxy]\nenabled = yes\n"
    assert _mitmdump_guard(tmp_path, shipped) == 1


def test_the_mitmdump_guard_refuses_an_enabled_section(tmp_path):
    assert _mitmdump_guard(tmp_path, "[Mitmdump]\nenabled = yes\n") == 0
    assert _mitmdump_guard(tmp_path, "[mitmdump]\n  enabled=True\n") == 0


def test_sudoers_is_validated_after_every_sudoers_change():
    n = _names()
    v = n.index("Validate sudoers after the removal")
    assert n.index("Remove the sudo rules that made cape root-equivalent") < v
    assert n.index("Give CAPE's remaining sudoers file the standard mode") < v


# --- check 23 -----------------------------------------------------------------------

def test_check_23_has_a_control_and_probes_every_service_user():
    smoke = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()
    block = smoke[smoke.index('echo "[23/23]'):smoke.index("# Summary + ntfy alert on failure")]
    assert 'timeout 3 /usr/bin/tcpdump -i lo -n -c 1 -w /dev/null >/dev/null 2>&1; CAP_CTRL=$?' in block
    assert 'fail "capture probe is blind' in block
    for u in ("pipeline", "lamware-api", "auto-feeder", "lamware-notify", "lamware-web-build"):
        assert u in block
    assert '[ "$CAP_LO" != 2 ]' in block and '[ "$CAP_BRIDGE" != 124 ]' in block
