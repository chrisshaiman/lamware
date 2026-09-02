# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A first-time build host had to discover its prerequisites by failing.

The requirements for `make win11-base` were spread across three files and none
was complete: `DEPLOYMENT.md` listed qemu but not ovmf, swtpm, mtools or packer;
the `apt-get install qemu-system-x86 ovmf swtpm` line lived in a comment at the
top of `windows11-base.pkr.hcl`; mtools and unzip appeared only in
`packer/README.md`. Membership of the `kvm` group was written down nowhere, and
that is the one that presents worst: the device node is world-visible, so
`ls -l /dev/kvm` looks correct on a host where the build cannot run.

Measured on a clean WSL2 box that had never built an image: 8 missing
prerequisites, discovered in one run instead of over eight failed builds.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-preflight.sh"
BASE = ROOT / "packer" / "windows11-base.pkr.hcl"
BODY = SCRIPT.read_text(encoding="utf-8")


def test_the_script_is_executable():
    """A checked-in script without +x fails for a reason unrelated to the build."""
    assert stat.S_IMODE(SCRIPT.stat().st_mode) & stat.S_IXUSR


def test_the_packer_version_is_read_from_the_templates_not_duplicated():
    """The whole point of #520 was one source of truth for the builder version.
    A number pasted in here would be a third place to drift."""
    assert "required_version" in BODY, "the constraint must be parsed from the templates"
    stripped = re.sub(r"^\s*#.*$", "", BODY, flags=re.M)
    literals = set(re.findall(r"\b1\.\d+\.\d+\b", stripped))
    assert not literals, f"hardcoded packer version(s) {literals} will drift from the templates"


@pytest.mark.parametrize("pkg", ["qemu-system-x86", "ovmf", "swtpm"])
def test_every_package_the_template_names_is_checked(pkg):
    """The pkr.hcl header names the apt packages. Anything it names and this
    does not check is a prerequisite someone still finds by failing."""
    header = BASE.read_text(encoding="utf-8")
    assert pkg in header, "the template stopped naming it; update this test deliberately"
    assert pkg in BODY, f"{pkg} is required by the build but unchecked by preflight"


def test_kvm_is_opened_rather_than_stat_ed():
    """THE check that motivated this. `test -e /dev/kvm` passes on a host whose
    user is not in the kvm group — the device is world-visible and the build
    still cannot run. Same shape as #490: a proxy that agrees with itself."""
    assert "< /dev/kvm" in BODY, "preflight must OPEN /dev/kvm"
    assert "usermod -aG kvm" in BODY, "and must say how to fix it"


def test_the_firmware_paths_are_overridable_not_assumed():
    """The defaults are the Debian/Ubuntu layout. Reporting only the default
    would make this lie on a Fedora or Arch host that is correctly configured."""
    assert "packer.auto.pkrvars.hcl" in BODY
    assert "other distros" in BODY


def test_the_ovmf_default_is_parsed_from_the_whole_variable_block():
    """`ovmf_vars` puts its default 14 lines below its header. A fixed -A window
    yielded an empty path and reported "not found" on a host where the file was
    present — a false alarm pointing at a non-problem."""
    text = BASE.read_text(encoding="utf-8")
    for var in ("ovmf_code", "ovmf_vars"):
        block = text.split(f'variable "{var}"')[1].split("\n}")[0]
        offset = len(block[:block.index("default")].splitlines())
        assert re.search(r'/\S+\.fd', block), f"{var} has no default path"
        if var == "ovmf_vars":
            assert offset > 6, (
                "the >6-line offset this guards against is gone; if the template "
                "was reflowed, re-confirm the parse still works before relaxing")


def test_win11_base_will_not_start_without_the_preflight():
    """A preflight nobody runs is a file, not a gate."""
    mk = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = re.search(r"^win11-base:(.*)$", mk, re.M)
    assert target, "win11-base target missing"
    assert "build-preflight" in target.group(1), (
        f"win11-base prerequisites are '{target.group(1).strip()}'")
    assert re.search(r"^\.PHONY:.*\bbuild-preflight\b", mk, re.M)


def test_it_exits_non_zero_when_something_is_missing():
    """Run it for real. On a host with every prerequisite this passes trivially;
    on one without, the exit code is what makes make stop."""
    r = subprocess.run([str(SCRIPT)], capture_output=True, text=True,
                       cwd=ROOT, env={**os.environ, "TERM": "dumb"})
    if r.returncode == 0:
        assert "Ready" in r.stdout
    else:
        assert "prerequisite(s) missing" in r.stdout
        assert re.search(r"MISSING", r.stdout)


def test_the_deployment_guide_no_longer_sends_you_for_a_windows_10_iso():
    """The build moved to the three-tier Win11 strategy in April; the guide's
    ISO section still described Windows 10 22H2 four months later."""
    doc = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "### Windows 11 evaluation ISO" in doc
    assert "### Windows 10 evaluation ISO" not in doc
    section = doc.split("### Windows 11 evaluation ISO")[1].split("\n---")[0]
    assert "Win10_22H2" not in section
    assert "Windows 10" not in section
    assert "evaluate-windows-11-enterprise" in section


def test_the_guide_points_at_the_preflight_rather_than_a_manual_list():
    doc = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "make build-preflight" in doc
    assert "usermod -aG kvm" in doc, "the undocumented prerequisite must now be documented"
