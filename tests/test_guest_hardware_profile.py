# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The image must be built on the hardware it will run on (#553).

Windows binds activation to a hardware hash. Building in one VM shape and running
in another invalidates the licence on first boot in the real domain. Measured
2026-09-03, same image an hour apart:

    in packer's VM              LicenseStatus = 1 (Licensed), 89.8 days
    in the cape-guests domain   "Windows License is expired"

An expired guest is shut down hourly by WLMS, truncating analyses at
unpredictable points and reading as sample behaviour -- the confound the whole
rebuild existed to remove.

The deltas were large: 4096 vs 8192 MB, 2 vs 4 vCPUs, no SMBIOS vs a full Dell
block, and `-cpu host` without the hypervisor bit cleared.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = (ROOT / "packer" / "windows11-base.pkr.hcl").read_text(encoding="utf-8")
MK = (ROOT / "Makefile").read_text(encoding="utf-8")
DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape-guests" / "defaults" / "main.yml").read_text(encoding="utf-8"))


def _pkr_default(name: str) -> str:
    block = BASE.split(f'variable "{name}"')[1].split("\n}")[0]
    m = re.search(r'default\s*=\s*"?([^"\n]+)"?', block)
    assert m, f"{name} has no default"
    # strip a trailing inline comment -- these lines end with "# ADR-012", and
    # capturing it turned an int() into a ValueError rather than a real failure
    return m.group(1).split("#")[0].strip()


def test_memory_matches_the_domain():
    """RAM is in the activation hash, and antivm_checks_available_memory is a
    33% probe in the corpus (#517) -- so a 4 GB build image is wrong twice."""
    assert int(_pkr_default("memory")) * 1024 == DEFAULTS["cape_guest_memory_kb"]


def test_vcpus_match_the_domain():
    assert int(_pkr_default("cpus")) == DEFAULTS["cape_guest_vcpus"]


def test_the_hypervisor_bit_is_cleared_in_the_build_too():
    """The domain disables it; a build image that advertises it differs, and it
    is the single most-checked CPU-level VM tell."""
    assert '"-cpu", "host,-hypervisor"' in BASE


@pytest.mark.parametrize("smbios_type,field", [
    ("type=0", "vendor="),          # BIOS
    ("type=1", "manufacturer="),    # system
    ("type=1", "serial="),
    ("type=1", "uuid="),
    ("type=2", "serial="),          # baseboard
])
def test_the_smbios_identity_is_asserted_at_build_time(smbios_type, field):
    args = re.findall(r'\["-smbios",\s*"([^"]+)"', BASE)
    assert any(a.startswith(smbios_type) and field in a for a in args), \
        f"no -smbios {smbios_type} carrying {field}; args={args}"


def test_serial_and_uuid_are_supplied_not_defaulted():
    """A hardcoded default would silently build the wrong identity when the
    Makefile fails to supply one. Empty defaults force the failure to be loud."""
    assert _pkr_default("guest_smbios_serial") == ""
    assert _pkr_default("guest_smbios_uuid") == ""


def test_the_makefile_sources_them_from_the_real_places():
    """Not restated in the template or pkrvars: the serial comes from the same
    vars Ansible renders the domain from, and the UUID from libvirt itself --
    so packer and the domain cannot describe different machines."""
    seg = MK.split("win11-base:")[0]
    assert "vars/main.yml" in seg and "cape_guests" in seg, "serial not read from Ansible vars"
    assert "virsh domuuid" in seg, "UUID not read from the live domain"
    assert "-var guest_smbios_serial=" in MK
    assert "-var guest_smbios_uuid=" in MK


def test_a_missing_value_stops_the_build_before_it_starts():
    """Failing 70 minutes in, or worse producing an image with the wrong
    identity, is the outcome this guards against."""
    target = MK.split("win11-base:")[1].split("\n\n")[0]
    assert 'ERROR: no smbios_serial' in target
    assert 'could not read the libvirt UUID' in target
    assert target.index("ERROR") < target.index("packer build")


def test_the_unmatched_mac_is_documented_not_forgotten():
    """Packer owns the NIC for WinRM forwarding, so the MAC is the one component
    still differing. That is a deliberate, recorded decision with an empirical
    test attached -- not an oversight."""
    assert "NOT matched" in BASE and "MAC" in BASE
    assert "verify-license" in BASE


def test_every_smbios_field_the_domain_sets_is_also_set_at_build_time():
    """The point of this profile is that Windows sees no hardware change. A
    field present in the domain but absent from the build IS a change.

    Found by comparing them on the live host: the domain's system block carries
    version='Not Specified' and the build's type=1 omitted version entirely."""
    tpl = (ROOT / "ansible" / "roles" / "cape-guests" / "templates"
           / "guest-domain.xml.j2").read_text(encoding="utf-8")
    # Pick the block that actually contains <entry> elements. Splitting on the
    # bare tag matched a COMMENT discussing sysinfo earlier in the file, which
    # is how this test first failed with an IndexError rather than a real result.
    blocks = [b for b in re.findall(r"<sysinfo\b.*?</sysinfo>", tpl, re.S)
              if "<entry" in b]
    assert blocks, "no sysinfo block with entries found"
    sysinfo = blocks[0]

    def entries(section: str) -> set[str]:
        seg = sysinfo.split(f"<{section}>")[1].split(f"</{section}>")[0]
        return set(re.findall(r"entry name='([a-z]+)'", seg))

    args = re.findall(r'\["-smbios",\s*"([^"]+)"', BASE)
    by_type = {a.split(",")[0]: a for a in args}
    for section, smbios_type in (("system", "type=1"), ("baseBoard", "type=2")):
        arg = by_type.get(smbios_type, "")
        missing = {f for f in entries(section) if f"{f}=" not in arg}
        # uuid is only meaningful on type=1; family/version/serial must all appear
        assert not missing, (
            f"{section} sets {sorted(missing)} but the build's {smbios_type} does not")
