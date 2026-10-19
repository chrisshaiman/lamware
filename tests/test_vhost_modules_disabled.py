# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The host refuses to load the vhost kernel modules nothing here uses.

Both detonation guests are defined with emulated e1000 NICs and the qemu
userspace disk driver, with no vsock device, so vhost_net, vhost_vsock and the
vhost core never load. /dev/vhost-* are root:kvm and the kvm group holds the
cape service account, so leaving them loadable hands the most exposed user a
kernel attack surface for a feature the deployment does not have.

Static checks over the deploy tree, like test_nested_virt_disabled.py: they
prove the repo cannot ship a configuration that re-opens the modules, and that
the role reports the live state instead of assuming the file took effect. Only
the host shows whether a module is resident, and the role prints that.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVM_TASKS = ROOT / "ansible" / "roles" / "kvm" / "tasks" / "main.yml"
GUEST_XML = (ROOT / "ansible" / "roles" / "cape-guests" / "templates"
             / "guest-domain.xml.j2")

MODULES = ("vhost", "vhost_net", "vhost_vsock")


def _text() -> str:
    return KVM_TASKS.read_text(encoding="utf-8")


def test_the_modprobe_drop_in_is_deployed():
    assert "99-lamware-no-vhost.conf" in _text()


def test_every_module_is_both_blacklisted_and_refused():
    """`blacklist` stops alias autoload only; `install … /bin/false` refuses an
    explicit modprobe too. Both are needed, for each of the three."""
    text = _text()
    for mod in MODULES:
        assert re.search(rf"^\s*blacklist {mod}$", text, re.M), f"blacklist {mod} missing"
        assert re.search(rf"^\s*install {mod} /bin/false$", text, re.M), f"install {mod} missing"


def test_the_deploy_reads_the_live_module_state_and_says_when_it_is_not_in_effect():
    text = _text()
    assert "lsmod" in text, "the role must read what is resident, not assume the file took effect"
    assert "STILL LOADED" in text, "and say so unmistakably when it has not"


def test_the_deploy_does_not_unload_modules_itself():
    """Unloading under running guests is the operator's window, not a deploy's."""
    text = _text()
    assert not re.search(r"modprobe -r\s+vhost|rmmod\s+vhost", text), (
        "the role must not unload vhost modules during a routine deploy")


def test_the_guests_do_not_depend_on_vhost():
    """The premise: if a guest ever gained a virtio NIC with the vhost backend
    or a vsock device, refusing the modules would break it silently at boot."""
    xml = GUEST_XML.read_text(encoding="utf-8")
    assert "vhost" not in xml, "a guest device asks for vhost; the refusal would break it"
    assert "<vsock" not in xml, "a guest has a vsock device; the refusal would break it"
