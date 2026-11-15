# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE reverts its guests through a root-owned helper, not libvirt's snapshot API (ADR-027).

libvirt's snapshot permission also creates snapshots, and libvirtd (root) writes an
external snapshot's memory file to whatever path the caller names: measured on the
host, it overwrote an existing root-owned file. So cape does not get that
permission, and a root helper reverts each configured guest to its configured
snapshot, taking no path and creating nothing.

Behavioural: the real template is rendered and run against a recording `virsh` stub.
Every refusal must happen before virsh is called, and a valid call must reach
`snapshot-revert` with exactly the configured pair. Structural for the deploy
wiring, which no local run reaches: the sudo rule, the order of the tasks, and the
patch calling the helper at the path the role installs it to.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/cape"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
PATCH = (ROLE / "files/patches/0004-libvirt-revert-through-root-helper.patch").read_text()
GUESTS = [{"name": "clean", "snapshot": "clean"}, {"name": "office", "snapshot": "office"}]

STUB = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if "snapshot-list" in args:
    guest = args[-1]
    print("\n".join(json.loads(os.environ["STUB_SNAPSHOTS"]).get(guest, [])))
'''


def _render(virsh: str) -> str:
    src = (ROLE / "templates/lamware-vm.j2").read_text()
    return Environment(undefined=StrictUndefined, keep_trailing_newline=True).from_string(src).render(
        cape_vm_helper=DEFAULTS["cape_vm_helper"], cape_vm_virsh=virsh, cape_guests=GUESTS)


@pytest.fixture
def helper(tmp_path):
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    stub = tmp_path / "virsh"
    stub.write_text(STUB)
    stub.chmod(0o755)
    script = tmp_path / "lamware-vm"
    script.write_text(_render(str(stub)))
    script.chmod(0o755)
    log = tmp_path / "virsh.log"

    def run(*args, snapshots=None):
        snaps = snapshots if snapshots is not None else {"clean": ["clean"], "office": ["office", "old"]}
        p = subprocess.run([str(script), *args], capture_output=True, text=True, timeout=20,
                           env={**os.environ, "STUB_LOG": str(log), "STUB_SNAPSHOTS": json.dumps(snaps)})
        calls = [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []
        log.unlink(missing_ok=True)
        return p, calls
    return run


def test_a_configured_pair_reverts_with_exactly_those_arguments(helper):
    p, calls = helper("revert", "clean", "clean")
    assert p.returncode == 0, p.stderr
    assert calls[-1] == ["-q", "-c", "qemu:///system", "snapshot-revert",
                         "--domain", "clean", "--snapshotname", "clean"]
    assert len(calls) == 2 and "snapshot-list" in calls[0]   # existence check, then revert


@pytest.mark.parametrize("args,why", [
    (("revert", "clean"), "too few arguments"),
    (("revert", "clean", "clean", "extra"), "too many arguments"),
    (("create", "clean", "clean"), "an action other than revert"),
    (("revert", "office", "clean"), "another guest's snapshot"),
    (("revert", "office", "old"), "an existing but unconfigured snapshot"),
    (("revert", "lamware-acl-probe", "x"), "a guest that is not configured"),
    (("revert", "clean", "clean --memspec file=/etc/shadow"), "an option smuggled in the name"),
    (("revert", "clean clean", "clean"), "a space inside the guest name"),
    (("revert", "", ""), "empty names"),
    (("revert", "clean", "*"), "a glob"),
])
def test_refusals_happen_before_virsh_is_touched(helper, args, why):
    p, calls = helper(*args)
    assert p.returncode != 0, why
    assert calls == [], f"virsh was called for {why}: {calls}"


@pytest.mark.parametrize("present", [[], ["clean-old"], ["oldclean"], ["Clean"]])
def test_a_configured_snapshot_that_is_missing_is_refused_before_revert(helper, present):
    """Matched as a whole line: a guest whose only snapshot is `clean-old` does not
    have `clean`."""
    p, calls = helper("revert", "clean", "clean", snapshots={"clean": present})
    assert p.returncode != 0 and "no snapshot named clean" in p.stderr, present
    assert all("snapshot-revert" not in c for c in calls)


def test_the_helper_never_names_a_file_or_creates_a_snapshot():
    """The only virsh verbs in the helper are a listing and a revert."""
    text = _render("/usr/bin/virsh")
    verbs = set(re.findall(r'"\$VIRSH" -q -c qemu:///system ([a-z-]+)', text))
    assert verbs == {"snapshot-list", "snapshot-revert"}, verbs
    assert "snapshot-create" not in text and "--memspec" not in text


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


def test_the_sudo_rule_names_only_the_helper_and_is_validated():
    _, t = _named("Let cape run the guest-revert helper")
    c = t["ansible.builtin.copy"]
    rules = [ln for ln in c["content"].splitlines() if ln and not ln.startswith("#")]
    assert rules == ["{{ cape_user }} ALL=(root) NOPASSWD: {{ cape_vm_helper }} revert *"]
    assert c["validate"] == "visudo -cf %s" and c["mode"] == "0440" and c["owner"] == "root"


def test_helper_and_sudo_rule_are_in_place_before_the_patch_is_applied():
    apply_i, _ = _named("Apply CAPE local patches")
    assert _named("Install the guest-revert helper")[0] < apply_i
    assert _named("Let cape run the guest-revert helper")[0] < apply_i


def test_the_patch_replaces_the_libvirt_revert_with_the_helper():
    added = [ln[1:] for ln in PATCH.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln[1:] for ln in PATCH.splitlines() if ln.startswith("-") and not ln.startswith("---")]
    assert any("revertToSnapshot" in ln for ln in removed), "the direct libvirt revert is not removed"
    assert not any("revertToSnapshot" in ln for ln in added)
    call = next(ln for ln in added if "lamware-vm" in ln)
    assert '"/usr/bin/sudo", "-n"' in call, "sudo must be non-interactive, or CAPE hangs on a prompt"
    assert f'"{DEFAULTS["cape_vm_helper"]}", "revert", label, snapshot.getName()' in call
    assert any(ln.strip() == "import subprocess" for ln in added)


def test_the_patch_is_verified_by_its_marker():
    _, t = _named("Verify CAPE reverts its guests through the helper")
    cmd = t["ansible.builtin.command"]["cmd"]
    assert "lamware ADR-027" in cmd and "abstracts.py" in cmd
    assert "lamware ADR-027" in PATCH
    assert t.get("failed_when")
