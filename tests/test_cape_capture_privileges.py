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


def test_tcpdump_runs_as_cape_with_only_the_capture_capabilities():
    argv = H["capture_argv"](_cape_argv()[11:])
    assert argv[0] == "/usr/bin/setpriv"
    sp = argv[:argv.index("--")]
    assert "--reuid=cape" in sp and "--regid=cape" in sp and "--init-groups" in sp
    for flag in ("--inh-caps", "--ambient-caps", "--bounding-set"):
        assert f"{flag}=-all,+net_raw,+net_admin" in sp, flag
    td = argv[argv.index("--") + 1:]
    assert td[0] == "/usr/bin/tcpdump"
    assert td[td.index("-i") + 1] == "virbr-det"
    assert td[td.index("-w") + 1] == "-"
    assert "-Z" not in td, "tcpdump is already cape; -Z would need root"
    dd = td.index("--")
    assert td[dd + 1:] == _cape_argv()[11:]


def test_signals_are_forwarded_and_handlers_exist_before_the_fork(monkeypatch, tmp_path):
    """The parent path of main(): handlers, fork, drop to cape, forward, wait."""
    os_, sig = H["os"], H["signal"]
    events = []
    handlers = {}
    monkeypatch.setattr(os_, "geteuid", lambda: 0)
    monkeypatch.setitem(H, "open_as", lambda u, p: os_.open(tmp_path / "f", os_.O_WRONLY | os_.O_CREAT))
    monkeypatch.setattr(sig, "signal", lambda s, h: (events.append(("handler", s)), handlers.__setitem__(s, h)))

    def fake_fork():
        events.append(("fork",))
        return 4242

    def fake_become(user, gid):
        events.append(("become", user, gid))
        handlers[sig.SIGTERM](sig.SIGTERM, None)   # CAPE's stop arrives while we wait

    monkeypatch.setattr(os_, "fork", fake_fork)
    monkeypatch.setitem(H, "become", fake_become)
    monkeypatch.setitem(H, "caller_gid", lambda user, env: 986)
    monkeypatch.setattr(os_, "kill", lambda pid, s: events.append(("kill", pid, s)))
    monkeypatch.setattr(os_, "waitpid", lambda pid, f: (pid, 0))
    assert H["main"](_cape_argv()) == 0
    fork_at = events.index(("fork",))
    assert {e[1] for e in events[:fork_at] if e[0] == "handler"} >= {sig.SIGTERM, sig.SIGINT}
    assert ("become", "cape", 986) in events[fork_at:], "the parent must take the caller's gid"
    assert ("kill", 4242, sig.SIGTERM) in events


def test_a_signal_before_the_child_exists_is_sent_once_it_does(monkeypatch, tmp_path):
    os_, sig = H["os"], H["signal"]
    handlers, kills = {}, []
    monkeypatch.setattr(os_, "geteuid", lambda: 0)
    monkeypatch.setitem(H, "open_as", lambda u, p: os_.open(tmp_path / "f", os_.O_WRONLY | os_.O_CREAT))
    monkeypatch.setattr(sig, "signal", lambda s, h: handlers.__setitem__(s, h))

    def fork_after_a_signal():
        handlers[sig.SIGTERM](sig.SIGTERM, None)
        return 4242

    monkeypatch.setattr(os_, "fork", fork_after_a_signal)
    monkeypatch.setitem(H, "become", lambda u, g: None)
    monkeypatch.setitem(H, "caller_gid", lambda user, env: 986)
    monkeypatch.setattr(os_, "kill", lambda pid, s: kills.append((pid, s)))
    monkeypatch.setattr(os_, "waitpid", lambda pid, f: (pid, 0))
    H["main"](_cape_argv())
    assert kills == [(4242, sig.SIGTERM)]


def test_the_parent_drops_to_cape_for_good_and_stays_visible(monkeypatch):
    os_ = H["os"]
    calls = []
    monkeypatch.setattr(os_, "setgroups", lambda g: calls.append("setgroups"))
    monkeypatch.setattr(os_, "setresgid", lambda *a: calls.append(("setresgid", len(set(a)))))
    monkeypatch.setattr(os_, "setresuid", lambda *a: calls.append(("setresuid", len(set(a)))))

    class Libc:
        def prctl(self, opt, val, *rest):
            calls.append(("prctl", opt, val))
            return 0

    monkeypatch.setattr(H["ctypes"], "CDLL", lambda *a, **k: Libc())
    import getpass
    H["become"](getpass.getuser(), os.getgid())
    assert calls == ["setgroups", ("setresgid", 1), ("setresuid", 1), ("prctl", 4, 1)], calls


def test_the_parent_keeps_the_callers_gid_when_it_is_one_of_capes_groups():
    """hidepid compares gid as well as uid: CAPE runs with Group=lamware, and a
    helper with cape's primary gid was invisible to it (detonation 1320)."""
    import getpass
    import pwd
    me = getpass.getuser()
    primary = pwd.getpwnam(me).pw_gid
    mine = [g for g in os.getgrouplist(me, primary) if g != primary]
    if mine:
        assert H["caller_gid"](me, {"SUDO_GID": str(mine[0])}) == mine[0]
    assert H["caller_gid"](me, {"SUDO_GID": str(primary)}) == primary


@pytest.mark.parametrize("env", [{}, {"SUDO_GID": ""}, {"SUDO_GID": "x"}, {"SUDO_GID": "0"}, {"SUDO_GID": "65533"}])
def test_any_other_caller_gid_falls_back_to_capes_own(env):
    import getpass
    import pwd
    me = getpass.getuser()
    primary = pwd.getpwnam(me).pw_gid
    raw = env.get("SUDO_GID", "")
    if raw.isdigit() and int(raw) in os.getgrouplist(me, primary):
        pytest.skip("this machine's user is in that group")
    assert H["caller_gid"](me, env) == primary


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
    probe = n.index(PROBE)
    for before in ("Install the capture helper (root-owned; ADR-029)",
                   "Let cape run the capture helper through sudo",
                   "Point CAPE's sniffer at the capture helper"):
        assert n.index(before) < probe, before
    for after in ("Remove tcpdump's capture capabilities", "Take cape out of the pcap group",
                  "Remove the pcap group"):
        assert probe < n.index(after), after


PROBE = "Check cape can capture on the detonation bridge through the helper, and stop it"


def test_the_probe_stops_the_capture_the_way_cape_does():
    t = _task(PROBE)
    cmd = t["ansible.builtin.shell"]["cmd"]
    assert 'setpriv --reuid={{ cape_user }} --regid="$g" --init-groups bash -c' in cmd
    assert "systemctl show -p Group --value cape.service" in cmd
    assert 'sudo -n "$1"' in cmd
    assert 'ps --ppid "$s" -o pid=' in cmd and 'kill -TERM "$c"' in cmd
    fw = t["failed_when"]
    for want in ("stop=stopped", "left=", "magic=d4c3b2a1", "owner="):
        assert want in fw, want


def test_the_leftover_match_cannot_hit_a_real_capes_capture():
    """The probe kills what it leaves; CAPE's filter always starts with `host <ip>`."""
    import re
    cmd = _task(PROBE)["ansible.builtin.shell"]["cmd"]
    pat = re.search(r'pgrep -u .+? -f -- "([^"]+)"', cmd).group(1).replace("{{ cape_capture_interface }}", "virbr-det")
    probe = "/usr/bin/tcpdump -U -q -s 0 -i virbr-det -n -w - -- not arp"
    real = "/usr/bin/tcpdump -U -q -s 0 -i virbr-det -n -w - -- " + " ".join(_cape_argv()[11:])
    assert re.search(pat, probe) and not re.search(pat, real)


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
    block = smoke[smoke.index('echo "[23/25]'):smoke.index("# Summary + ntfy alert on failure")]
    assert 'timeout 3 /usr/bin/tcpdump -i lo -n -c 1 -w /dev/null >/dev/null 2>&1; CAP_CTRL=$?' in block
    assert 'fail "capture probe is blind' in block
    for u in ("pipeline", "lamware-api", "auto-feeder", "lamware-notify", "lamware-web-build"):
        assert u in block
    assert '[ "$CAP_LO" != 2 ]' in block
    assert 'ps --ppid "$s" -o pid=' in block and '[ "$CAP_STOP" != stopped ]' in block
    assert 'setpriv --reuid="$CAP_USER" --regid="$CAP_GROUP" --init-groups' in block
