# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Detonation guests must not be given nested virtualisation (#305).

Zapscape (CVE-2026-64561) is a use-after-free in KVM's shadow-MMU recursive zap path
giving a guest-to-host escape with root. Two of its three prerequisites are ours:

  1. kernel privilege inside the L1 guest  — satisfied BY DESIGN here. These guests
     detonate live malware with no in-guest containment; reaching SYSTEM and loading a
     driver is expected behaviour, not an exotic precondition.
  2. nested virtualisation exposed to that guest — the only one we control.

Verified on the host 2026-08-06 before mitigating: kernel 6.8.0-110-generic,
GenuineIntel, `kvm_intel nested = Y`, live domain XML passing `host-passthrough` with
only the `hypervisor` CPUID bit disabled. VMX was reaching the guests.

These are static checks over the deploy tree. They cannot prove the running host has
the module reloaded — the role reports that at deploy time, loudly, because a reload
needs every guest stopped. What they prove is that the repo cannot ship a configuration
that re-exposes nesting, which is the part that decays silently.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVM_TASKS = ROOT / "ansible" / "roles" / "kvm" / "tasks" / "main.yml"
GUEST_XML = (ROOT / "ansible" / "roles" / "cape-guests" / "templates"
             / "guest-domain.xml.j2")


def test_the_modprobe_drop_in_is_deployed():
    text = KVM_TASKS.read_text(encoding="utf-8")
    assert "99-lamware-no-nested.conf" in text, (
        "the kvm role must ship a modprobe.d drop-in disabling nested virt (#305)")


def test_both_intel_and_amd_are_covered():
    """The host is Intel today. A hardware change must not silently re-open this.

    Writing both is free — modprobe ignores options for a module that never loads.
    """
    text = KVM_TASKS.read_text(encoding="utf-8")
    for opt in ("options kvm_intel nested=0", "options kvm_amd nested=0"):
        assert opt in text, f"missing {opt!r} — a vendor switch would re-expose nesting"


def test_the_deploy_reports_when_the_mitigation_is_not_yet_live():
    """A modprobe.d file changes nothing until the module reloads.

    Without this report a deploy looks successful while the host is still exposed —
    the same shape as #269's setup target claiming readiness it had not verified.
    """
    text = KVM_TASKS.read_text(encoding="utf-8")
    assert "/sys/module/kvm_intel/parameters/nested" in text, (
        "the role must read the LIVE setting, not assume the file took effect")
    assert "STILL ENABLED" in text, "and say so unmistakably when it has not"


def test_the_deploy_does_not_silently_reload_the_module():
    """`modprobe -r kvm_intel` requires every VM stopped. Doing that inside a routine
    deploy would kill running detonations without warning, so the role must report
    rather than act."""
    text = KVM_TASKS.read_text(encoding="utf-8")
    assert "modprobe -r kvm_intel\n" not in text.replace("`", ""), (
        "the role must not reload the module itself — that would stop running "
        "analyses mid-detonation; it belongs in an operator-chosen window")


def test_guest_xml_does_not_re_enable_vmx():
    """The module parameter is the enforcement. This catches someone 'fixing'
    anti-detection fidelity by handing VMX back at the domain level."""
    xml = GUEST_XML.read_text(encoding="utf-8")
    for feat in ("vmx", "svm"):
        assert not re.search(rf"policy=['\"]require['\"]\s+name=['\"]{feat}['\"]", xml), (
            f"guest XML explicitly requires {feat} — that re-exposes the Zapscape "
            f"prerequisite (#305)")


def test_the_hypervisor_bit_is_still_hidden():
    """Guards the mitigation against collateral damage.

    Clearing the `hypervisor` CPUID bit is ADR-012's anti-detection measure and is
    unrelated to #305. Someone editing this block for nesting reasons must not remove
    it by accident.
    """
    xml = GUEST_XML.read_text(encoding="utf-8")
    assert re.search(r"policy=['\"]disable['\"]\s+name=['\"]hypervisor['\"]", xml), (
        "the hypervisor CPUID bit must stay disabled (ADR-012) — it is a separate "
        "concern from #305 and was not part of this mitigation")


def test_the_rationale_survives_in_the_role():
    """This trades a small amount of anti-detection fidelity for containment. The next
    person to read it will reasonably ask why, and must not have to reconstruct it."""
    text = KVM_TASKS.read_text(encoding="utf-8")
    assert "#305" in text and "CVE-2026-64561" in text
    assert "ADR-012" in text, (
        "the comment must acknowledge the anti-detection cost it is accepting")
