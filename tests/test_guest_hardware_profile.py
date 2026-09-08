# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The image must be built against the hardware profile it will run under (#553, #573).

Against the *profile*, not the machine. The profile is what these tests pin, and
pinning all of it is what lets any machine build an image that runs here -- the
portability property the build is supposed to have.

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

Closing those was not enough, because two components were still unpinned.
Measured 2026-09-04, on the first uncontaminated test -- matched SMBIOS, no
intermediate boots:

    Notification Reason: 0xC004F00F
    (hardware ID binding is beyond the level of tolerance)

`-cpu host` names the builder's own silicon, so the two sides agreed only while
the build machine and the sandbox were the same box; they were not. The NIC MAC
was unpinned too, and Windows enumerated the domain's card as a second adapter.

The SMBIOS identity, by contrast, changed between the base and guest stages and
the licence survived it -- which is how we know the CPU is the component that
decides (#573).
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = (ROOT / "packer" / "windows11-base.pkr.hcl").read_text(encoding="utf-8")
GUEST = (ROOT / "packer" / "windows11-guest.pkr.hcl").read_text(encoding="utf-8")
OFFICE = (ROOT / "packer" / "windows11-office.pkr.hcl").read_text(encoding="utf-8")
DOMAIN = (ROOT / "ansible" / "roles" / "cape-guests" / "templates"
          / "guest-domain.xml.j2").read_text(encoding="utf-8")
MK = (ROOT / "Makefile").read_text(encoding="utf-8")

# Every stage that BOOTS the guest, not just the one that installs it. The
# licence broke because windows11-guest ran -cpu host with no -smbios at all,
# so the image was bound to three machines on its way here (#573).
STAGES = [("base", BASE), ("guest", GUEST), ("office", OFFICE)]
DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape-guests" / "defaults" / "main.yml").read_text(encoding="utf-8"))


def _pkr_default(name: str) -> str:
    block = BASE.split(f'variable "{name}"')[1].split("\n}")[0]
    m = re.search(r'default\s*=\s*"?([^"\n]+)"?', block)
    assert m, f"{name} has no default"
    # strip a trailing inline comment -- these lines end with "# ADR-012", and
    # capturing it turned an int() into a ValueError rather than a real failure
    return m.group(1).split("#")[0].strip()


def _target(name: str) -> tuple[str, str]:
    """(prerequisites, recipe) for the declaration of `name` that has a recipe.

    Parsed rather than regexed out of the whole file: "windows11-base.pkr.hcl"
    also appears in a comment 300 lines earlier, and `win11-office:` is
    declared twice (once to set a target-specific GUEST). Both matched first
    and made these tests fail for the wrong reason."""
    lines = MK.split("\n")
    for i, line in enumerate(lines):
        if not line.startswith(f"{name}:"):
            continue
        recipe = []
        for nxt in lines[i + 1:]:
            if nxt.startswith("\t"):
                recipe.append(nxt)
            elif nxt.strip() == "":
                continue
            else:
                break
        if recipe:
            return line.split(":", 1)[1], "\n".join(recipe)
    raise AssertionError(f"no {name} target with a recipe")


def test_memory_matches_the_domain():
    """RAM is in the activation hash, and antivm_checks_available_memory is a
    33% probe in the corpus (#517) -- so a 4 GB build image is wrong twice."""
    assert int(_pkr_default("memory")) * 1024 == DEFAULTS["cape_guest_memory_kb"]


def test_vcpus_match_the_domain():
    assert int(_pkr_default("cpus")) == DEFAULTS["cape_guest_vcpus"]


def _cpu_arg(src: str) -> str:
    """The value of the -cpu qemuarg, e.g. '${var.guest_cpu_model},-hypervisor'."""
    m = re.search(r'\["-cpu",\s*"([^"]+)"\]', src)
    assert m, "no -cpu qemuarg at all"
    return m.group(1)


@pytest.mark.parametrize("stage,src", STAGES)
def test_the_hypervisor_bit_is_cleared_in_every_build_stage(stage, src):
    """The domain disables it; a build image that advertises it differs, and it
    is the single most-checked CPU-level VM tell."""
    assert "-hypervisor" in _cpu_arg(src).split(",")[1:], \
        f"{stage} does not clear the hypervisor bit: {_cpu_arg(src)}"


@pytest.mark.parametrize("stage,src", STAGES)
def test_no_stage_builds_against_the_build_hosts_own_cpu(stage, src):
    """`-cpu host` is why the rebuilt image arrived unlicensed (#573): it
    resolves to the builder's silicon, so the build machine and the sandbox
    agreed only when they were the same box. Measured, on first boot here:

        Notification Reason: 0xC004F00F
        (hardware ID binding is beyond the level of tolerance)

    The model must come from the variable, so it is the same value the domain
    template renders -- a literal here would drift from Ansible silently."""
    model = _cpu_arg(src).split(",")[0]
    assert model != "host", f"{stage} still builds against the build host's CPU"
    assert model == "${var.guest_cpu_model}", \
        f"{stage} hardcodes a CPU model ({model}) instead of taking the shared one"


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
    guard = MK.split("guest-profile-check:")[1].split("\n\n")[0]
    assert 'ERROR: no smbios_serial' in guard
    assert 'ERROR: no mac' in guard
    assert 'could not read the libvirt UUID' in guard
    # and it runs before any packer build, for every stage that boots the guest
    for stage in ("base", "guest", "office"):
        prereqs, _ = _target(f"win11-{stage}")
        assert "guest-profile-check" in prereqs, \
            f"win11-{stage} can run without the profile guard"


@pytest.mark.parametrize("stage,src", STAGES)
def test_every_stage_pins_the_nic_mac(stage, src):
    """Packer generates its own e1000 for the WinRM forward, so the MAC used to
    be the one component nothing controlled. Windows enumerated the domain's
    NIC as a SECOND adapter on first boot -- "Intel(R) PRO/1000 MT Network
    Connection #2" -- which is both a hash input and a visible tell that the
    image was built elsewhere.

    -global rather than -device: a second -device on the same netdev will not
    start."""
    globals_ = re.findall(r'\["-global",\s*"([^"]+)"\]', src)
    macs = [g.split("=", 1)[1] for g in globals_ if g.startswith("e1000.mac=")]
    assert macs, f"{stage} does not pin the NIC MAC; globals={globals_}"
    assert macs[0] == "${var.guest_mac}", \
        f"{stage} hardcodes a MAC ({macs[0]}) instead of taking the domain's"


def test_the_mac_is_supplied_not_defaulted():
    """Same reasoning as the serial: a default would build the wrong identity
    quietly."""
    assert _pkr_default("guest_mac") == ""
    assert _pkr_default("guest_cpu_model") == ""


def test_the_domain_and_the_build_name_the_same_cpu_model():
    """The two sides agreeing is the whole point. host-passthrough made them
    agree only by coincidence of being on one machine."""
    blocks = re.findall(r"<cpu\b.*?</cpu>", DOMAIN, re.S)
    assert blocks, "no <cpu> block in the domain template"
    cpu = blocks[0]
    assert "host-passthrough" not in cpu, \
        "the domain still passes the host CPU through; the image cannot match it"
    m = re.search(r"<model[^>]*>\{\{\s*([a-z_]+)\s*\}\}</model>", cpu)
    assert m, f"the domain does not render a variable CPU model: {cpu}"
    assert m.group(1) == "cape_guest_cpu_model"
    assert "disable" in cpu and "hypervisor" in cpu


def test_the_shared_cpu_model_is_a_real_named_model():
    """Empty or 'host' here defeats every test above."""
    model = DEFAULTS["cape_guest_cpu_model"]
    assert model and model not in ("host", "host-passthrough")


def test_the_cpu_model_is_a_name_libvirt_can_accept():
    """qemu and libvirt disagree about which names exist, and only qemu was
    checked. `qemu-system-x86_64 -cpu Skylake-Client-v4` runs happily; libvirt
    validates <model> against its own cpu_map, which carries only the
    unversioned aliases, so the domain died at START with

        internal error: Unknown CPU model Skylake-Client-v4

    after the image had already been built against it. The cpu_map has never
    contained -vN names, so the shape is checkable here (#573)."""
    model = DEFAULTS["cape_guest_cpu_model"]
    assert not re.search(r"-v\d+$", model), (
        f"{model} is a qemu version name; libvirt's cpu_map holds only aliases "
        f"(use e.g. Skylake-Client-noTSX-IBRS for Skylake-Client-v3)")


def test_the_deploy_rechecks_the_model_against_both_layers():
    """The shape test above cannot know what THIS host's libvirt and qemu
    actually carry, so the deploy asserts it before defining any domain --
    rather than 40 minutes into the next rebuild."""
    tasks = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "cape-guests" / "tasks" / "main.yml")
        .read_text(encoding="utf-8"))
    asserts = [t for t in tasks if "ansible.builtin.assert" in t]
    checked = " ".join(str(t["ansible.builtin.assert"].get("that", "")) for t in asserts)
    assert "cape_libvirt_cpu_models" in checked, "libvirt's cpu_map is not checked"
    assert "cape_qemu_cpu_model_line" in checked, "the qemu model table is not checked"
    # naming the variable is not the same as testing the dangerous property:
    # a machine-type alias resolves to different silicon on different qemu
    # versions, and merely checking the model EXISTS would pass for one
    assert "alias configured by machine type" in checked, \
        "nothing rejects a machine-type-dependent alias"

    # and it must run BEFORE the domains are defined
    names = [t.get("name", "") for t in tasks]
    guard = next(i for i, n in enumerate(names) if "libvirt does not know" in n)
    define = next(i for i, n in enumerate(names) if n.startswith("Define guest libvirt domains"))
    assert guard < define, "the CPU model is checked after the domains are defined"


@pytest.mark.parametrize("stage", ["base", "guest", "office"])
def test_the_makefile_hands_every_stage_the_whole_profile(stage):
    """A stage built without the profile is the #573 bug exactly. Resolved
    through the variable the recipe actually uses, so renaming it fails here."""
    _, recipe = _target(f"win11-{stage}")
    build = recipe.rsplit("packer build", 1)
    assert len(build) == 2, f"win11-{stage} has no packer build"
    assert f"windows11-{stage}.pkr.hcl" in build[1], \
        f"win11-{stage} does not build windows11-{stage}.pkr.hcl"
    assert "$(GUEST_PROFILE_VARS)" in build[1], \
        f"win11-{stage} does not pass the guest hardware profile to packer"
    profile = MK.split("GUEST_PROFILE_VARS =")[1].split("\n\n")[0]
    for var in ("guest_smbios_serial", "guest_smbios_uuid",
                "guest_mac", "guest_cpu_model"):
        assert f"-var {var}=" in profile, f"{var} missing from the shared profile"


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
