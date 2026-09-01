# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Stock identity strings the guest was still shipping (#517).

A census of 839 analyses ranked what samples actually probe. Most of the guest
was already deliberate under ADR-012 — CPU host-passthrough with the hypervisor
bit disabled, a real TPM, 8 GiB RAM, a Wistron MAC OUI, e1000 and SATA rather
than virtio, 1920x1080. Two surfaces were still stock:

  DMI / SMBIOS   no <sysinfo> block at all, so the guest reported QEMU/SeaBIOS
                 defaults — the strings `antivm_generic_bios` reads
  ComputerName   DESKTOP-PKRBLD, which is "Packer Build" written into the field
                 21% of the corpus queries

Neither makes the guest undetectable and this file does not pretend otherwise.
The point is narrower: a default is a free win for the sample, and these two were
free wins nobody had taken.
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOMAIN = ROOT / "ansible/roles/cape-guests/templates/guest-domain.xml.j2"
ANSWERS = ROOT / "packer/answer-files/win11-autounattend.xml"


def _domain_xml():
    """The template with Jinja removed, so it can be parsed as XML."""
    s = DOMAIN.read_text(encoding="utf-8")
    s = re.sub(r"{%.*?%}", "", s, flags=re.S)
    s = re.sub(r"{{.*?}}", "X", s, flags=re.S)
    return ET.fromstring(s)


# --- SMBIOS ---


def test_the_domain_declares_an_smbios_identity():
    root = _domain_xml()
    sysinfo = root.find("sysinfo")
    assert sysinfo is not None, "no <sysinfo> block — DMI reports QEMU defaults"
    assert sysinfo.get("type") == "smbios"


def test_the_smbios_block_is_actually_fed_to_the_guest():
    """Without <smbios mode='sysinfo'/> in <os>, the sysinfo block is inert and
    the guest still sees QEMU strings — a change that looks applied and is not."""
    root = _domain_xml()
    os_el = root.find("os")
    assert os_el is not None
    smbios = os_el.find("smbios")
    assert smbios is not None and smbios.get("mode") == "sysinfo", (
        "sysinfo is declared but never reaches the guest's DMI tables")


@pytest.mark.parametrize("section,entry", [
    ("bios", "vendor"), ("bios", "version"),
    ("system", "manufacturer"), ("system", "product"), ("system", "serial"),
    ("baseBoard", "manufacturer"),
])
def test_the_identity_is_complete_enough_to_be_plausible(section, entry):
    """A half-filled DMI table is its own tell: real hardware populates these."""
    root = _domain_xml()
    el = root.find(f"sysinfo/{section}")
    assert el is not None, f"no <{section}> in sysinfo"
    names = {e.get("name") for e in el.findall("entry")}
    assert entry in names, f"{section} omits {entry!r}"


def test_no_qemu_or_seabios_strings_survive():
    """Parsed, not grepped. My first version sliced the raw template between
    "<sysinfo" and "</sysinfo>" and failed on the COMMENT above the block, which
    explains what QEMU/SeaBIOS defaults are. A text search finds the prose about
    a fix as readily as the fix."""
    root = _domain_xml()
    values = [e.text or "" for e in root.iter("entry")]
    assert values, "no SMBIOS entries at all"
    for tell in ("QEMU", "SeaBIOS", "Bochs", "VirtualBox", "VMware", "innotek"):
        offenders = [v for v in values if tell.lower() in v.lower()]
        assert not offenders, f"{tell!r} left in the SMBIOS identity: {offenders}"


def test_every_guest_is_asked_for_its_own_serial():
    """Two machines sharing a serial number is itself an anomaly.

    Asserted against `main.yml.example`, because the real `ansible/vars/main.yml`
    is GITIGNORED — my first version read it and passed locally while failing in
    CI on a file that is not in the repo. An operator's actual vars file cannot
    be checked from here at all; what can be checked is that the shape is
    documented for whoever writes one.

    Explicit in vars rather than derived in the template: the repo's other domain
    tests render with plain Jinja2, where Ansible's `hash` filter does not exist
    — deriving it there broke three of them.
    """
    import yaml
    example = ROOT / "ansible/vars/main.yml.example"
    guests = yaml.safe_load(example.read_text(encoding="utf-8"))["cape_guests"]
    missing = [g.get("name") for g in guests if not g.get("smbios_serial")]
    assert not missing, f"guests with no smbios_serial in the example: {missing}"


def test_the_local_vars_file_is_not_what_ci_checks():
    """A guard against reintroducing the mistake: `ansible/vars/main.yml` is
    gitignored, so a test reading it is one that cannot fail in CI for the
    reason it was written."""
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "ansible/vars/main.yml" in ignored
    # The needle is built at runtime. Spelled literally it would appear in this
    # file and the assertion would find itself — a test failing on its own text
    # is not a test of anything.
    needle = 'ROOT / "ansible/vars/' + 'main.yml"'
    src = Path(__file__).read_text(encoding="utf-8")
    assert needle not in src, "a test reads the gitignored vars file again"


def test_the_template_renders_without_a_serial():
    """The other domain tests build their own `item` fixture with no serial.
    Requiring one would break them, and a template that only works with the
    full vars file is one nothing can test."""
    s = DOMAIN.read_text(encoding="utf-8")
    assert "item.smbios_serial is defined" in s


# --- in-guest identity ---


def test_the_computer_name_is_not_a_build_tool_fingerprint():
    """DESKTOP-PKRBLD is 'Packer Build'. 21% of the corpus queries this field."""
    name = ET.parse(ANSWERS).getroot().iter()
    text = ANSWERS.read_text(encoding="utf-8")
    for tell in ("PKRBLD", "PACKER", "SANDBOX", "MALWARE", "ANALYSIS", "VIRUS",
                 "CUCKOO", "CAPE"):
        assert tell not in text.upper().split("<COMPUTERNAME>")[-1][:40], (
            f"{tell!r} appears in the computer name")
    assert name is not None


def test_the_computer_name_matches_windows_own_default_shape():
    """DESKTOP- plus seven alphanumerics. A name that is merely DIFFERENT but
    oddly shaped trades one tell for another."""
    text = ANSWERS.read_text(encoding="utf-8")
    m = re.search(r"<ComputerName>([^<]+)</ComputerName>", text)
    assert m, "no ComputerName in the answer file"
    assert re.fullmatch(r"DESKTOP-[A-Z0-9]{7}", m.group(1)), m.group(1)


def test_the_registered_organisation_is_not_microsofts_sample():
    """'Contoso' ships in every Microsoft tutorial answer file."""
    text = ANSWERS.read_text(encoding="utf-8")
    assert "Contoso" not in text


def test_the_answer_file_is_still_valid_xml():
    """It is consumed by Windows setup from a floppy image; a malformed one
    fails the build 45 minutes in."""
    ET.parse(ANSWERS)
