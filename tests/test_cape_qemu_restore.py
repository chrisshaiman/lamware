"""The cape role restores the patched QEMU from the preserved copy, never /tmp (#694).

It used to copy /tmp/qemu-9.2.2_builded/usr/bin/qemu-system-x86_64 over
/usr/bin/qemu-system-x86_64 on every cape deploy whenever that path existed.
/tmp is world-writable, so any local user could choose the hypervisor root
installed. These tests RUN the role's restore-qemu.yml with ansible-playbook
against temp files (connection local, unprivileged, owner set to the test
user), so they observe what the tasks do, not how they are spelled.

Skipped where ansible-playbook is not installed (the CI test job has none).
"""

import getpass
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "cape"
TASKS = ROLE / "tasks" / "restore-qemu.yml"

PATCHED = b"\x7fELF patched-qemu " * 64
STOCK = b"\x7fELF stock-qemu " * 64

needs_ansible = pytest.mark.skipif(shutil.which("ansible-playbook") is None,
                                   reason="ansible-playbook not installed")


def run(tmp_path: Path, preserved: Path, distro: Path) -> subprocess.CompletedProcess:
    play = [{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {
            "cape_qemu_binary": str(preserved),
            "cape_qemu_distro_path": str(distro),
            "cape_qemu_owner": getpass.getuser(),
            "cape_qemu_restart_libvirtd": False,
        },
        "tasks": [{"ansible.builtin.include_tasks": str(TASKS)}],
    }]
    pb = tmp_path / "play.yml"
    pb.write_text(yaml.safe_dump(play))
    env = {**os.environ, "ANSIBLE_STDOUT_CALLBACK": "json", "ANSIBLE_LOCALHOST_WARNING": "false",
           "ANSIBLE_INVENTORY_UNPARSED_WARNING": "false"}
    return subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)],
                          capture_output=True, text=True, env=env, timeout=180)


def task_result(proc: subprocess.CompletedProcess, name: str) -> dict:
    out = json.loads(proc.stdout[proc.stdout.index("{"):])
    for play in out["plays"]:
        for task in play["tasks"]:
            if task["task"]["name"] == name:
                return task["hosts"]["localhost"]
    raise AssertionError(f"task {name!r} not in the run")


COPY = "Copy the preserved emulator over a changed distro path"
REFUSE = "Refuse a preserved emulator that is not root's alone"


def refused_by_the_guard(proc) -> bool:
    """Failed, and failed AT the ownership/type guard -- not somewhere later."""
    return proc.returncode != 0 and task_result(proc, REFUSE).get("failed") is True


@pytest.fixture
def files(tmp_path):
    preserved, distro = tmp_path / "local-bin-qemu", tmp_path / "usr-bin-qemu"
    preserved.write_bytes(PATCHED)
    preserved.chmod(0o755)
    distro.write_bytes(STOCK)
    distro.chmod(0o755)
    return preserved, distro


@needs_ansible
def test_a_replaced_distro_emulator_is_restored_from_the_preserved_copy(tmp_path, files):
    preserved, distro = files
    proc = run(tmp_path, preserved, distro)
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert distro.read_bytes() == PATCHED
    assert task_result(proc, COPY).get("changed") is True


@needs_ansible
def test_an_identical_distro_emulator_is_left_alone(tmp_path, files):
    """No copy, so no libvirtd restart on an ordinary deploy."""
    preserved, distro = files
    distro.write_bytes(PATCHED)
    before = distro.stat().st_mtime_ns
    proc = run(tmp_path, preserved, distro)
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert task_result(proc, COPY).get("skipped") is True
    assert distro.stat().st_mtime_ns == before


@needs_ansible
def test_no_preserved_copy_changes_nothing(tmp_path, files):
    preserved, distro = files
    preserved.unlink()
    proc = run(tmp_path, preserved, distro)
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert distro.read_bytes() == STOCK


@needs_ansible
@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_a_preserved_copy_others_can_write_is_refused(tmp_path, files, mode):
    preserved, distro = files
    preserved.chmod(mode)
    proc = run(tmp_path, preserved, distro)
    assert refused_by_the_guard(proc), proc.stdout[-2000:]
    assert distro.read_bytes() == STOCK


@needs_ansible
def test_a_preserved_path_that_is_a_symlink_is_refused(tmp_path, files):
    """A link could point anywhere a writer chose; stat does not follow it."""
    preserved, distro = files
    planted = tmp_path / "planted"
    planted.write_bytes(b"\x7fELF attacker " * 64)
    preserved.unlink()
    preserved.symlink_to(planted)
    proc = run(tmp_path, preserved, distro)
    assert refused_by_the_guard(proc), proc.stdout[-2000:]
    assert distro.read_bytes() == STOCK


def _walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def test_no_cape_task_reads_from_tmp():
    """Structural, and a memory of #694 rather than a test of the host: no value in
    any cape task names a /tmp path. Parsed, so a comment that mentions the old
    path (restore-qemu.yml's header does) cannot satisfy or fail it."""
    for f in sorted((ROLE / "tasks").glob("*.yml")):
        for node in _walk(yaml.safe_load(f.read_text())):
            for value in node.values():
                if isinstance(value, str):
                    assert "/tmp/" not in value, f"{f.name}: {value!r}"


def test_the_role_includes_the_restore():
    tasks = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert any(t.get("ansible.builtin.include_tasks") == "restore-qemu.yml" for t in tasks)
