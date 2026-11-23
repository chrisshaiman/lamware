# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""cape is in no group it doesn't write for (ADR-031 phase 1).

The cape role removes cape from lamware BEFORE CAPE restarts (systemd gives a
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
    rm = _task("Remove cape from the lamware group")
    assert rm["ansible.builtin.command"] == "gpasswd -d {{ cape_user }} lamware"
    assert rm["when"] == "'lamware' in cape_groups_now.stdout.split()"
    assert rm["notify"] == "Restart Cape services"
    assert names.index("Read cape's groups") < names.index("Remove cape from the lamware group")
    for dropin in ("Deploy CAPE service drop-in (cape group + umask)",
                   "Deploy CAPE processor drop-in (cape group + umask)"):
        assert names.index("Remove cape from the lamware group") < names.index(dropin)


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
    return out[out.index('echo "[27/27]'):out.index("# Summary + ntfy alert on failure")]


def _run27(tmp, *, members="pipeline,lamware-api,auto-feeder", procs=(("1002", "1002 1003"),),
           readable=True, analyses=("1322",), lamware=True):
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
    stubs = {
        "getent": f"#!/bin/bash\n{'echo lamware:x:986:' + members if lamware else 'exit 2'}\n",
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


def test_check27_passes_when_cape_is_out_and_the_pipeline_still_reads(tmp_path):
    out = _run27(tmp_path, procs=(("1002", "1002 999 1003"), ("1002", "1002")))
    assert "PASS: cape: not in lamware, 2 processes without it; the pipeline reads 1322" in out, out


@pytest.mark.parametrize("kw, want", [
    ({"members": "pipeline,cape,auto-feeder"}, "cape is a member of lamware"),
    ({"procs": (("986", "1002"),)}, "carry the lamware group: 100(python)"),            # Group=lamware
    ({"procs": (("1002", "1002"), ("1002", "1002 986 1003"))}, "carry the lamware group: 101(python)"),
    ({"procs": ()}, "no running cape process"),
    ({"readable": False}, "the pipeline cannot read the newest CAPE analysis"),
    ({"analyses": ()}, "none found"),
    ({"lamware": False}, "no lamware group"),
])
def test_check27_fails_each_way_it_should(tmp_path, kw, want):
    out = _run27(tmp_path, **kw)
    assert "FAIL" in out and want in out, out
