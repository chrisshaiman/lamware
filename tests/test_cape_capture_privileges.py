"""The cape user captures without sudo, and the sudo rules that made it root are gone.

The re-apply script is tested behaviourally (fake getcap/setcap/logger on PATH):
it is the piece that must work unattended after a tcpdump upgrade, when nobody
is watching and a failure means every pcap is silently empty. The task file is
checked structurally: the ORDER (prove capture without sudo before removing
sudo) cannot be observed without the host. The host evidence is in the PR.
"""

import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "cape"
SCRIPT = ROLE / "files" / "lamware-tcpdump-caps"
TASKS = yaml.safe_load((ROLE / "tasks" / "capture-privileges.yml").read_text())


def _run(tmp_path, getcap_out: str, setcap_rc: int = 0, binary: bool = True):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls"
    for name, body in {
        "getcap": f'echo "{getcap_out}"',
        "setcap": f'echo "setcap $*" >> {log}; exit {setcap_rc}',
        "logger": f'echo "logger $*" >> {log}',
    }.items():
        (bindir / name).write_text(f"#!/bin/sh\n{body}\n")
        (bindir / name).chmod(0o755)
    tcpdump = tmp_path / "tcpdump"
    if binary:
        tcpdump.write_text("#!/bin/sh\n")
        tcpdump.chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "LAMWARE_TCPDUMP": str(tcpdump)}
    r = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True)
    return r.returncode, (log.read_text() if log.exists() else "")


def test_missing_capabilities_are_granted(tmp_path):
    rc, calls = _run(tmp_path, getcap_out="")
    assert rc == 0
    assert "setcap cap_net_raw,cap_net_admin=eip" in calls


def test_present_capabilities_are_left_alone(tmp_path):
    rc, calls = _run(tmp_path, getcap_out="/usr/bin/tcpdump cap_net_admin,cap_net_raw=eip")
    assert rc == 0 and "setcap" not in calls


def test_a_failed_setcap_is_logged_and_never_fails_apt(tmp_path):
    rc, calls = _run(tmp_path, getcap_out="", setcap_rc=1)
    assert rc == 0
    assert "logger" in calls and "capture will fail" in calls


def test_no_tcpdump_is_not_an_error(tmp_path):
    rc, calls = _run(tmp_path, getcap_out="", binary=False)
    assert rc == 0 and calls == ""


def _names():
    return [t.get("name") for t in TASKS]


def test_capture_is_proven_before_sudo_is_removed():
    n = _names()
    removal = n.index("Remove the sudo rules that made cape root-equivalent")
    for before in ("Put the cape user in the pcap group",
                   "Make tcpdump executable by root and the pcap group only",
                   "Grant tcpdump capture capabilities",
                   "Check the cape user can capture without sudo"):
        assert n.index(before) < removal, before


def test_both_root_paths_are_removed_and_verified():
    rm = next(t for t in TASKS if t.get("name") == "Remove the sudo rules that made cape root-equivalent")
    assert rm["ansible.builtin.file"]["state"] == "absent"
    assert set(rm["loop"]) == {"tcpdump", "ip_netns"}
    check = next(t for t in TASKS if t.get("name") == "Refuse if a capture or netns rule is still granted")
    assert "'tcpdump' not in cape_sudo_list.stdout" in check["ansible.builtin.assert"]["that"]
    assert "'netns' not in cape_sudo_list.stdout" in check["ansible.builtin.assert"]["that"]


def test_the_apt_hook_runs_the_reapply_script():
    hook = next(t for t in TASKS if t.get("name") == "Re-apply the capabilities after every dpkg run")
    content = hook["ansible.builtin.copy"]["content"]
    assert "DPkg::Post-Invoke" in content and "/usr/local/sbin/lamware-tcpdump-caps" in content
    assert hook["ansible.builtin.copy"]["dest"].startswith("/etc/apt/apt.conf.d/")


def test_the_capture_probe_runs_as_cape_without_sudo_rights():
    probe = next(t for t in TASKS if t.get("name") == "Check the cape user can capture without sudo")
    cmd = probe["ansible.builtin.command"]
    assert cmd.startswith("sudo -u {{ cape_user }} timeout")
    assert "sudo -n" not in cmd and "--non-interactive" not in cmd
    assert probe["failed_when"] == "cape_capture_probe.rc not in [0, 124]"


def test_the_role_includes_the_file():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert any(t.get("ansible.builtin.import_tasks") == "capture-privileges.yml" for t in tasks)


def test_the_script_is_executable_in_the_repo():
    assert os.access(SCRIPT, os.X_OK)


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


def test_another_sections_enabled_does_not_count(tmp_path):
    assert _mitmdump_guard(tmp_path, "[Mitmdump]\nenabled = no\n[PolarProxy]\nenabled = yes\n") == 1


def test_sudoers_is_validated_after_every_sudoers_change():
    n = _names()
    v = n.index("Validate sudoers after the removal")
    assert n.index("Remove the sudo rules that made cape root-equivalent") < v
    assert n.index("Give CAPE's remaining sudoers file the standard mode") < v
