# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""libvirtd could not execute its own AppArmor helper, so no guest could start.

    error: internal error: cannot load AppArmor profile 'libvirt-<uuid>'
    ... cannot execute binary /usr/lib/libvirt/virt-aa-helper: Permission denied

    audit: operation="exec" profile="libvirtd"
           name="/usr/lib/libvirt/virt-aa-helper" comm="rpc-libvirtd"

The shipped libvirtd profile permits `/usr/libexec/*`; libvirt-daemon installs
the helper at `/usr/lib/libvirt/virt-aa-helper` and libvirtd calls it there. Hit
on 2026-09-02 after the libvirt packages were reinstalled to repair the
half-replaced source build (#528).

The failure mode is the dangerous kind: Cape's guests are normally shut off, so
nothing looks wrong until an analysis tries to start one. Every external
indicator -- services active, virsh list working, API answering -- stayed green
while the sandbox could not run a single sample.
"""
import yaml
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "kvm"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
HANDLERS = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))


def _rule_lines(content: str) -> list[str]:
    """AppArmor rules only -- comments in this block quote the very paths the
    rules grant, so an unfiltered substring check is satisfied by the prose."""
    return [ln.strip() for ln in content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def _aa_task():
    for t in TASKS:
        c = t.get("ansible.builtin.copy")
        if isinstance(c, dict) and "apparmor.d" in str(c.get("dest", "")):
            return t
    return None


def test_the_override_is_written():
    assert _aa_task(), "nothing grants libvirtd exec on its helper"


def test_it_uses_a_local_include_not_the_shipped_profile():
    """A package update overwrites /etc/apparmor.d/usr.sbin.libvirtd and would
    silently drop an inline edit -- reintroducing a total-outage bug quietly."""
    dest = _aa_task()["ansible.builtin.copy"]["dest"]
    assert "/local/" in dest, f"{dest} is the shipped profile, not a local override"


def test_it_grants_the_path_libvirtd_actually_calls():
    content = _aa_task()["ansible.builtin.copy"]["content"]
    assert "/usr/lib/libvirt/virt-aa-helper" in content
    assert "PUxr" in content or "ix" in content, "granted without an exec permission"


def test_the_profile_is_reloaded_and_the_daemon_restarted():
    """A rule on disk that apparmor has not re-read changes nothing, and libvirtd
    caches the profile state -- both steps are needed or the fix appears applied
    and the next guest start still fails."""
    assert _aa_task().get("notify") == "Reload libvirtd apparmor profile"
    names = [h["name"] for h in HANDLERS]
    assert "Reload libvirtd apparmor profile" in names
    assert "Restart libvirtd after apparmor reload" in names
    reload_h = next(h for h in HANDLERS if h["name"] == "Reload libvirtd apparmor profile")
    assert reload_h.get("notify") == "Restart libvirtd after apparmor reload"


def test_the_pre_existing_grub_handler_survived():
    """I overwrote this file while adding the handlers above and had to restore
    it. Losing `Update GRUB` would silently stop hugepages being applied."""
    assert "Update GRUB" in [h["name"] for h in HANDLERS]
    grub = next(h for h in HANDLERS if h["name"] == "Update GRUB")
    assert grub["ansible.builtin.command"] == "update-grub"


@pytest.mark.parametrize("h", ["Update GRUB", "Reload libvirtd apparmor profile"])
def test_every_handler_is_actually_notified_by_something(h):
    """An unreferenced handler never runs."""
    body = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8") + \
           (ROLE / "handlers" / "main.yml").read_text(encoding="utf-8")
    assert body.count(h) >= 2, f"{h} is defined but never notified"


def test_the_patched_qemu_path_is_executable_by_libvirtd():
    """cape_qemu_binary is /usr/local/bin/qemu-system-x86_64 (roles/cape
    defaults) -- deliberately outside /usr/bin, so a qemu-system-x86 package
    update cannot silently replace the DSDT-patched binary with stock.

    The shipped profile has no /usr/local rules at all, so `virsh define` failed
    for EVERY guest on 2026-09-03:

        error: Failed to start QEMU binary /usr/local/bin/qemu-system-x86_64
               for probing: cannot execute binary: Permission denied
    """
    # Strip comments first: the path also appears in the explanatory comment,
    # so a plain substring check passed with the RULE deleted -- verified by
    # mutating it away.
    rules = _rule_lines(_aa_task()["ansible.builtin.copy"]["content"])
    assert any(r.startswith("/usr/local/bin/qemu-system-x86_64") and "PUxr" in r
               for r in rules), f"no exec rule for the patched qemu; rules={rules}"


def test_the_emulator_default_still_points_where_the_rule_grants():
    """If cape_qemu_binary moves, this rule silently stops covering it and
    defines start failing again -- so assert the two agree."""
    import yaml
    d = yaml.safe_load((ROOT / "ansible" / "roles" / "cape" / "defaults"
                        / "main.yml").read_text(encoding="utf-8"))
    emulator = d.get("cape_qemu_binary", "")
    rules = _rule_lines(_aa_task()["ansible.builtin.copy"]["content"])
    assert emulator, "cape_qemu_binary has no default"
    assert any(r.startswith(emulator) for r in rules), (
        f"cape_qemu_binary is {emulator} but no AppArmor RULE grants it; rules={rules}")
