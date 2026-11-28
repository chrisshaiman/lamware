# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""cape holds only its allowlisted groups (ADR-031; phase 1 removed lamware).

The cape role removes cape from every group outside cape_supplementary_groups
BEFORE CAPE restarts (systemd gives a
service its user's groups at start), its units run Group=cape, and no other role
adds it back. Security-test check 27's shell block is run against stub `ps`,
`getent` and `sudo` and fake /proc status files: membership, a running process
that still carries the group, a blind probe, and the pipeline's read path each
decide the result.
"""
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible/roles"
CAPE_TASKS = yaml.safe_load((ROLES / "cape/tasks/main.yml").read_text())
SMOKE = (ROLES / "security-test/templates/security-smoke-test.sh.j2").read_text()


def _names(tasks):
    return [t.get("name") for t in tasks if isinstance(t, dict)]


def _task(name):
    return next(t for t in CAPE_TASKS if isinstance(t, dict) and t.get("name") == name)


def test_the_cape_role_removes_the_membership_before_the_restarting_drop_ins():
    names = _names(CAPE_TASKS)
    rm = _task("Remove cape from every group outside its allowlist")
    assert rm["ansible.builtin.command"] == "gpasswd -d {{ cape_user }} {{ item }}"
    assert rm["loop"] == ("{{ cape_groups_now.stdout.split() | difference([cape_user] + "
                          "cape_supplementary_groups) }}")
    defaults = yaml.safe_load((ROLES / "cape/defaults/main.yml").read_text())
    assert defaults["cape_supplementary_groups"] == ["libvirt"]
    assert rm["notify"] == ["Restart Cape services", "Restart cape's user manager"]
    assert names.index("Read cape's groups") < names.index("Remove cape from every group outside its allowlist")
    for dropin in ("Deploy CAPE service drop-in (cape group + umask)",
                   "Deploy CAPE processor drop-in (cape group + umask)"):
        assert names.index("Remove cape from every group outside its allowlist") < names.index(dropin)


def test_cape_restarts_with_its_new_groups_before_the_capture_probe():
    """The first phase-1 deploy probed in the window between the membership removal
    and the end-of-play restart: CAPE still carried lamware, and the probe saw no
    capture child under hidepid ("nochild")."""
    names = _names(CAPE_TASKS)
    flush = names.index("Restart CAPE with its new groups before anything probes it")
    assert CAPE_TASKS[flush]["ansible.builtin.meta"] == "flush_handlers"
    assert names.index("Deploy CAPE processor drop-in (cape group + umask)") < flush
    assert names.index("Remove cape from every group outside its allowlist") < flush
    assert flush < names.index("Give CAPE's sniffer capture rights without sudo")
    stale = _task("Find CAPE processes carrying a group outside its allowlist")
    # cape lingers: its user manager keeps the groups it started with (check 27 found it).
    assert stale["notify"] == ["Restart Cape services", "Restart cape's user manager"]
    handlers = yaml.safe_load((ROLES / "cape/handlers/main.yml").read_text())
    um = next(h for h in handlers if h["name"] == "Restart cape's user manager")
    assert um["ansible.builtin.shell"]["cmd"] == 'systemctl restart "user@$(id -u {{ cape_user }}).service"'
    assert stale["changed_when"] == "cape_stale_groups.stdout | length > 0"
    assert names.index("Find CAPE processes carrying a group outside its allowlist") < flush


def test_the_stale_group_finder_names_exactly_the_processes_outside_the_allowlist(tmp_path):
    """Run the task's own shell against fake /proc status files and a stub ps."""
    cmd = _task("Find CAPE processes carrying a group outside its allowlist")["ansible.builtin.shell"]["cmd"]
    cmd = jinja2.Environment().from_string(cmd).render(  # noqa: S701 - shell
        cape_user="cape", cape_supplementary_groups=["libvirt"])
    proc, bindir = tmp_path / "proc", tmp_path / "bin"
    proc.mkdir()
    bindir.mkdir()
    for pid, gid, groups in (("10", "986", "1002"),          # Group=lamware
                             ("11", "1002", "1002 986"),      # lamware kept
                             ("12", "1002", "1002 999"),      # systemd-journal kept
                             ("13", "1002", "1002 1003"),     # cape + libvirt: fine
                             ("14", "1002", "")):             # (sd-pam): no groups
        (proc / pid).mkdir()
        (proc / pid / "status").write_text(f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\nGroups:\t{groups}\n")
    (bindir / "ps").write_text("#!/bin/bash\nprintf '10\\n11\\n12\\n13\\n14\\n'\n")
    (bindir / "getent").write_text("#!/bin/bash\ncase $2 in cape) echo cape:x:1002: ;; libvirt) echo libvirt:x:1003:cape ;; esac\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    out = subprocess.run(["bash", "-c", cmd.replace('"/proc/$p/status"', f'"{proc}/$p/status"')],
                         capture_output=True, text=True, env={"PATH": f"{bindir}:/usr/bin:/bin"})
    assert out.returncode == 0 and out.stdout.split() == ["10", "11", "12"], out


@pytest.mark.parametrize("name", ["Deploy CAPE service drop-in (cape group + umask)",
                                  "Deploy CAPE processor drop-in (cape group + umask)"])
def test_the_cape_units_run_as_group_cape(name):
    content = _task(name)["ansible.builtin.copy"]["content"]
    lines = [ln.strip() for ln in content.splitlines()]
    assert "Group=cape" in lines and "UMask=0027" in lines
    assert not any(ln.startswith("Group=lamware") for ln in lines)


def test_no_role_adds_cape_to_lamware():
    hits = []
    for f in ROLES.glob("*/tasks/*.yml"):
        for t in yaml.safe_load(f.read_text()) or []:
            u = t.get("ansible.builtin.user") if isinstance(t, dict) else None
            if isinstance(u, dict) and "cape" in str(u.get("name")) and "lamware" in str(u.get("groups", "")):
                hits.append(f"{f.relative_to(ROOT)}: {t.get('name')}")
    assert hits == []


def test_no_unit_template_gives_cape_the_lamware_group():
    for f in list(ROLES.glob("cape*/templates/*.j2")) + list(ROLES.glob("cape*/files/*")):
        if f.is_file():
            text = f.read_text(errors="replace")
            assert "Group=lamware" not in text, f


# --- check 27, run for real ---------------------------------------------------------

def _check27() -> str:
    env = jinja2.Environment()  # noqa: S701 - shell, not HTML
    env.filters["bool"] = bool
    out = env.from_string(SMOKE).render()
    return out[out.index('echo "[27/29]'):out.index('echo "[28/29]')]


def _run27(tmp, *, member_of="cape libvirt", procs=(("1002", "1002 1003"),),
           readable=True, analyses=("1322",), libvirt=True):
    """procs: (primary gid, supplementary gids) per running cape process."""
    bindir, proc, store = tmp / "bin", tmp / "proc", tmp / "analyses"
    for d in (bindir, proc, store):
        d.mkdir()
    for a in analyses:
        (store / a).mkdir()
    pids = []
    for i, (gid, groups) in enumerate(procs):
        pid = str(100 + i)
        pids.append(pid)
        (proc / pid).mkdir()
        (proc / pid / "status").write_text(
            f"Name:\tpython\nUid:\t1001\t1001\t1001\t1001\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nGroups:\t{groups}\n")
        (proc / pid / "comm").write_text("python\n")
    libvirt_line = "libvirt) echo libvirt:x:1003:cape ;;" if libvirt else ""
    stubs = {
        "getent": f"#!/bin/bash\ncase $2 in cape) echo cape:x:1002: ;; {libvirt_line} esac\n",
        "id": f"#!/bin/bash\necho {member_of}\n",
        "ps": "#!/bin/bash\n" + "".join(f"echo {p}\n" for p in pids),
        "sudo": f"#!/bin/bash\nexit {0 if readable else 1}\n",
    }
    for name, body in stubs.items():
        (bindir / name).write_text(body)
        (bindir / name).chmod(0o755)
    body = (_check27().replace('"/proc/$pid/status"', f'"{proc}/$pid/status"')
            .replace("/proc/$pid/comm", f"{proc}/$pid/comm")
            .replace("/opt/CAPEv2/storage/analyses", str(store)))
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": f"{bindir}:/usr/bin:/bin"}).stdout


def test_check27_passes_when_cape_holds_only_its_allowlist(tmp_path):
    out = _run27(tmp_path, procs=(("1002", "1002 1003"), ("1002", "1002"), ("1002", "")))
    assert "PASS: cape: only cape + libvirt, on 3 processes too; the pipeline reads 1322" in out, out


@pytest.mark.parametrize("kw, want", [
    ({"member_of": "cape lamware libvirt"}, "outside its allowlist (libvirt): lamware"),
    ({"member_of": "cape systemd-journal libvirt"}, "outside its allowlist (libvirt): systemd-journal"),
    ({"procs": (("986", "1002"),)}, "carry a group outside its allowlist: 100(python:986)"),   # Group=lamware
    ({"procs": (("1002", "1002"), ("1002", "1002 999 1003"))}, "101(python:999)"),            # journal kept
    ({"procs": ()}, "no running cape process"),
    ({"libvirt": False}, "allowlisted groups do not resolve: libvirt"),
    ({"readable": False}, "the pipeline cannot read the newest CAPE analysis"),
    ({"analyses": ()}, "none found"),
])
def test_check27_fails_each_way_it_should(tmp_path, kw, want):
    out = _run27(tmp_path, **kw)
    assert "FAIL" in out and want in out, out
