# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE reverts its guests and dumps their memory through a root-owned helper (ADR-027).

libvirt's snapshot and core-dump permissions both make libvirtd (root) write a file
wherever the caller names: measured on the host, a snapshot request overwrote an
existing root-owned file. So cape gets neither, and `lamware-vm` does the two
writes CAPE needs, taking no path:

  revert <guest> <snapshot>   only each configured guest's configured snapshot;
  dump <guest> <task-id>      libvirtd writes into a root-only staging directory,
                              the file gets cape's ownership, mode 0640 and the task
                              folder's default ACL, and is renamed into the task
                              folder through handles opened without following links.

Behavioural: the real template is rendered and run against a recording `virsh` stub,
with the analyses and staging directories in a temp tree. Every refusal must happen
before virsh is called. Structural for the deploy wiring, which no local run reaches.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/cape"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
PATCH4 = (ROLE / "files/patches/0004-libvirt-revert-through-root-helper.patch").read_text()
PATCH5 = (ROLE / "files/patches/0005-libvirt-memory-dump-through-root-helper.patch").read_text()
GUESTS = [{"name": "clean", "snapshot": "clean"}, {"name": "office", "snapshot": "office"}]
ME = os.environ.get("USER") or __import__("pwd").getpwuid(os.getuid()).pw_name

STUB = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if "snapshot-list" in args:
    print("\n".join(json.loads(os.environ["STUB_SNAPSHOTS"]).get(args[-1], [])))
if "dump" in args:
    with open(args[-1], "w") as f:
        f.write("ELF-MEMORY-IMAGE")
'''


def _render(virsh: str, analyses: str = "/opt/CAPEv2/storage/analyses",
            staging: str = "/var/lib/lamware-memdump", user: str = "cape") -> str:
    src = (ROLE / "templates/lamware-vm.j2").read_text()
    return Environment(undefined=StrictUndefined, keep_trailing_newline=True).from_string(src).render(
        cape_vm_helper=DEFAULTS["cape_vm_helper"], cape_vm_virsh=virsh, cape_guests=GUESTS,
        cape_vm_dump_analyses_dir=analyses, cape_vm_dump_staging=staging, cape_user=user)


@pytest.fixture
def env(tmp_path):
    stub = tmp_path / "virsh"
    stub.write_text(STUB)
    stub.chmod(0o755)
    analyses = tmp_path / "analyses"
    analyses.mkdir()
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    log = tmp_path / "virsh.log"

    def run(*args, snapshots=None, user=ME):
        script = tmp_path / "lamware-vm"
        script.write_text(_render(str(stub), str(analyses), str(staging), user))
        snaps = snapshots if snapshots is not None else {"clean": ["clean"], "office": ["office", "old"]}
        p = subprocess.run([sys.executable, "-I", str(script), *args], capture_output=True, text=True,
                           timeout=30, env={**os.environ, "STUB_LOG": str(log),
                                            "STUB_SNAPSHOTS": json.dumps(snaps)})
        calls = [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []
        log.unlink(missing_ok=True)
        return p, calls
    run.analyses, run.staging = analyses, staging
    return run


# --- revert ---------------------------------------------------------------------

def test_a_configured_pair_reverts_with_exactly_those_arguments(env):
    p, calls = env("revert", "clean", "clean")
    assert p.returncode == 0, p.stderr
    assert calls[-1] == ["-q", "-c", "qemu:///system", "snapshot-revert",
                         "--domain", "clean", "--snapshotname", "clean"]
    assert len(calls) == 2 and "snapshot-list" in calls[0]


@pytest.mark.parametrize("args,why", [
    (("revert", "clean"), "too few arguments"),
    (("revert", "clean", "clean", "extra"), "too many arguments"),
    (("create", "clean", "clean"), "an unknown action"),
    (("revert", "office", "clean"), "another guest's snapshot"),
    (("revert", "office", "old"), "an existing but unconfigured snapshot"),
    (("revert", "lamware-acl-probe", "x"), "a guest that is not configured"),
    (("revert", "clean", "clean --memspec file=/etc/shadow"), "an option smuggled in the name"),
    (("revert", "clean clean", "clean"), "a space inside the guest name"),
    (("revert", "", ""), "empty names"),
    (("revert", "clean", "*"), "a glob"),
])
def test_revert_refusals_happen_before_virsh_is_touched(env, args, why):
    p, calls = env(*args)
    assert p.returncode != 0, why
    assert calls == [], f"virsh was called for {why}: {calls}"


@pytest.mark.parametrize("present", [[], ["clean-old"], ["oldclean"], ["Clean"]])
def test_a_configured_snapshot_that_is_missing_is_refused_before_revert(env, present):
    """Matched as a whole line: a guest whose only snapshot is `clean-old` does not
    have `clean`."""
    p, calls = env("revert", "clean", "clean", snapshots={"clean": present})
    assert p.returncode != 0 and "no snapshot named clean" in p.stderr, present
    assert all("snapshot-revert" not in c for c in calls)


# --- dump -----------------------------------------------------------------------

def test_a_dump_lands_in_the_task_folder_as_the_cape_users_file(env):
    (env.analyses / "1316").mkdir()
    p, calls = env("dump", "clean", "1316")
    assert p.returncode == 0, p.stderr
    assert calls == [["-q", "-c", "qemu:///system", "dump", "--memory-only", "clean",
                      f"{env.staging}/1316.{calls[0][-1].split('.')[1]}.dmp"]]
    out = env.analyses / "1316" / "memory.dmp"
    assert out.read_text() == "ELF-MEMORY-IMAGE"
    st = out.stat()
    assert (st.st_uid, oct(st.st_mode & 0o777)) == (os.getuid(), "0o640")
    assert list(env.staging.iterdir()) == [], "the staged file must be moved, not copied"


def test_the_dump_gets_the_task_folders_default_acl(env):
    """A renamed file inherits no default ACL; the pipeline reads dumps through it."""
    if not (shutil.which("setfacl") and shutil.which("getfacl")):
        pytest.skip("acl tools not installed")
    d = env.analyses / "1317"
    d.mkdir()
    gid = os.getgid()
    if subprocess.run(["setfacl", "-d", "-m", f"g:{gid}:r-x", str(d)], capture_output=True).returncode:
        pytest.skip("this filesystem does not support ACLs")
    p, _ = env("dump", "clean", "1317")
    assert p.returncode == 0, p.stderr
    acl = subprocess.run(["getfacl", "-n", "--omit-header", str(d / "memory.dmp")],
                         capture_output=True, text=True).stdout
    assert f"group:{gid}:r--" in acl, acl
    assert "x" not in "".join(ln.split("#")[0].split(":")[-1] for ln in acl.splitlines() if ln.strip())


@pytest.mark.parametrize("args,why", [
    (("dump", "office-x", "1316"), "a guest that is not configured"),
    (("dump", "clean", "abc"), "a non-numeric task id"),
    (("dump", "clean", "../1316"), "a path in the task id"),
    (("dump", "clean", "/etc/shadow"), "an absolute path"),
    (("dump", "clean", "0"), "task id zero"),
    (("dump", "clean", "01316"), "a leading zero"),
    (("dump", "clean", "1234567890"), "a ten-digit id"),
    (("dump", "clean", "１２"), "non-ASCII digits"),
    (("dump", "clean", "9999"), "a task folder that does not exist"),
])
def test_dump_refusals_happen_before_virsh_is_touched(env, args, why):
    (env.analyses / "1316").mkdir(exist_ok=True)
    p, calls = env(*args)
    assert p.returncode != 0, why
    assert calls == [], f"virsh was called for {why}: {calls}"


@pytest.mark.parametrize("task_id", ["0", "01316", "1234567890", "１２", "1316 "])
def test_a_badly_shaped_task_id_is_refused_even_when_such_a_folder_exists(env, task_id):
    """The folder exists, so only the id check can refuse: the helper must not
    depend on a lookup failing to stay inside the expected shape."""
    (env.analyses / task_id).mkdir()
    p, calls = env("dump", "clean", task_id)
    assert p.returncode != 0 and "not a task id" in p.stderr, (task_id, p.stderr)
    assert calls == []


def test_a_linked_task_folder_is_refused(env, tmp_path):
    """cape owns the analyses tree, so it could swap a task folder for a link to
    somewhere root-owned; the helper must not follow it."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (env.analyses / "1316").symlink_to(elsewhere)
    p, calls = env("dump", "clean", "1316")
    assert p.returncode != 0 and calls == []
    assert not (elsewhere / "memory.dmp").exists()


def test_a_task_folder_not_owned_by_cape_is_refused(env):
    (env.analyses / "1316").mkdir()
    p, calls = env("dump", "clean", "1316", user="root")   # the folder is mine, not root's
    assert p.returncode != 0 and "not owned by root" in p.stderr and calls == []


def test_a_staging_directory_others_can_enter_is_refused(env):
    (env.analyses / "1316").mkdir()
    env.staging.chmod(0o755)
    p, calls = env("dump", "clean", "1316")
    assert p.returncode != 0 and "staging directory" in p.stderr and calls == []


def test_a_failed_dump_leaves_nothing_in_staging(env, tmp_path):
    (env.analyses / "1316").mkdir()
    # virsh that writes part of the file and then fails, as a dump cut short would.
    (tmp_path / "virsh").write_text("#!/bin/sh\nfor a; do f=$a; done; echo partial > \"$f\"; exit 1\n")
    p, _ = env("dump", "clean", "1316")
    assert p.returncode != 0
    assert list(env.staging.iterdir()) == [] and not (env.analyses / "1316" / "memory.dmp").exists()


def test_the_helper_never_creates_a_snapshot_or_takes_a_path():
    text = _render("/usr/bin/virsh")
    assert "snapshot-create" not in text and "--memspec" not in text
    assert 'f"{STAGING}/{name}"' in text, "the dump goes only to the staging directory"


# --- deploy wiring ------------------------------------------------------------

def _named(fragment: str) -> tuple[int, dict]:
    for i, t in enumerate(TASKS):
        if fragment.lower() in (t.get("name") or "").lower():
            return i, t
    raise AssertionError(f"no task {fragment!r}")


def test_the_helper_is_root_owned_and_not_writable_by_cape():
    _, t = _named("Install the guest-revert helper")
    tpl = t["ansible.builtin.template"]
    assert (tpl["dest"], tpl["owner"], tpl["group"], tpl["mode"]) == \
        ("{{ cape_vm_helper }}", "root", "root", "0755")


def test_the_staging_directory_is_root_only():
    _, t = _named("Create the memory-dump staging directory")
    f = t["ansible.builtin.file"]
    assert (f["path"], f["owner"], f["mode"]) == ("{{ cape_vm_dump_staging }}", "root", "0700")


def test_the_sudo_rule_names_only_the_helpers_two_actions_and_is_validated():
    _, t = _named("Let cape run the guest-revert helper")
    c = t["ansible.builtin.copy"]
    rules = [ln for ln in c["content"].splitlines() if ln and not ln.startswith("#")]
    assert rules == ["{{ cape_user }} ALL=(root) NOPASSWD: {{ cape_vm_helper }} revert *, "
                     "{{ cape_vm_helper }} dump *"]
    assert c["validate"] == "visudo -cf %s" and c["mode"] == "0440" and c["owner"] == "root"


def test_helper_sudo_rule_and_staging_are_in_place_before_the_patches():
    apply_i, _ = _named("Apply CAPE local patches")
    for n in ("Install the guest-revert helper", "Let cape run the guest-revert helper",
              "Create the memory-dump staging directory"):
        assert _named(n)[0] < apply_i, n


def _added(patch: str) -> list[str]:
    return [ln[1:] for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def _removed(patch: str) -> list[str]:
    return [ln[1:] for ln in patch.splitlines() if ln.startswith("-") and not ln.startswith("---")]


def test_patch_0004_replaces_the_libvirt_revert_with_the_helper():
    assert any("revertToSnapshot" in ln for ln in _removed(PATCH4))
    assert not any("revertToSnapshot" in ln for ln in _added(PATCH4))
    call = next(ln for ln in _added(PATCH4) if "lamware-vm" in ln)
    assert '"/usr/bin/sudo", "-n"' in call
    assert f'"{DEFAULTS["cape_vm_helper"]}", "revert", label, snapshot.getName()' in call


def test_patch_0005_replaces_the_libvirt_core_dump_with_the_helper():
    assert any("coreDump" in ln for ln in _removed(PATCH5))
    assert not any("coreDump" in ln for ln in _added(PATCH5))
    call = next(ln for ln in _added(PATCH5) if "lamware-vm" in ln)
    assert '"/usr/bin/sudo", "-n"' in call
    assert f'"{DEFAULTS["cape_vm_helper"]}", "dump", label, task_id' in call
    # The helper takes no path: the patch passes only the task id it reads back
    # out of CAPE's own path, and refuses any other shape.
    assert any('name != "memory.dmp" or not task_id.isdigit()' in ln for ln in _added(PATCH5))


@pytest.mark.parametrize("fragment,marker,patch", [
    ("Verify CAPE reverts its guests through the helper", "lamware ADR-027", PATCH4),
    ("Verify CAPE dumps memory through the helper", "lamware ADR-027 (dump)", PATCH5),
])
def test_each_patch_is_verified_by_its_marker(fragment, marker, patch):
    _, t = _named(fragment)
    cmd = t["ansible.builtin.command"]["cmd"]
    assert f'"{marker}"' in cmd and "abstracts.py" in cmd and marker in patch
    assert t.get("failed_when")
