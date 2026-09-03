# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The standalone dnsmasq service fails on every boot, and should not exist here.

libvirt runs its OWN dnsmasq per network, from
/var/lib/libvirt/dnsmasq/detonation.conf, and that is what serves DNS and DHCP on
the detonation bridge. The packaged system service listens on all interfaces by
default, so it races for the same address and loses:

    dnsmasq[...]: failed to create listening socket for 192.168.100.1:
                  Address already in use

Harmless in itself -- libvirt won and the guests have DNS. The cost is that a
permanently failed unit trains people to skim `systemctl --failed`, which is
exactly where the next real failure appears. After the 2026-09-02 reboot this
host had four genuinely broken units and they were harder to pick out for it.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "kvm" / "tasks" / "main.yml").read_text(encoding="utf-8"))


def _task():
    for t in TASKS:
        s = t.get("ansible.builtin.systemd_service")
        if isinstance(s, dict) and s.get("name") == "dnsmasq":
            return s
    return None


def test_dnsmasq_is_masked_not_merely_disabled():
    """Disabled is not enough: a package update can re-enable a unit, and this
    one was installed by hand. Masking survives that."""
    s = _task()
    assert s, "nothing handles the standalone dnsmasq service"
    assert s.get("masked") is True
    assert s.get("state") == "stopped"


def test_only_dnsmasq_base_is_installed_by_us():
    """dnsmasq-base is the library libvirt needs. The full dnsmasq package brings
    the conflicting service and we must not start installing it."""
    text = (ROOT / "ansible" / "roles" / "kvm" / "tasks" / "main.yml").read_text(encoding="utf-8")
    pkgs = [t for t in TASKS
            if isinstance(t.get("ansible.builtin.apt"), dict)]
    names = []
    for t in pkgs:
        n = t["ansible.builtin.apt"].get("name")
        names += n if isinstance(n, list) else [n]
    assert "dnsmasq-base" in names
    assert "dnsmasq" not in names, "installing dnsmasq would reintroduce the conflict"
    # the comment must survive too, or the next person removes the mask as noise
    assert "Address already in use" in text


def test_the_libvirt_instance_is_not_touched():
    """Masking the system unit must not extend to libvirt's own dnsmasq, which
    is started by libvirtd and not by a systemd unit of its own."""
    s = _task()
    assert s["name"] == "dnsmasq", f"masking {s['name']} would be too broad"
    assert "libvirt" not in str(s.get("name"))
