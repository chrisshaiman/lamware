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


@pytest.mark.parametrize("placeholder", [
    "TODO", "TODO-sha256:", "<sha256-of-iso>", "CHANGEME", "your-build-password",
])
def test_a_placeholder_value_is_not_accepted_as_set(placeholder, tmp_path):
    """The first version knew only '<...>' and CHANGEME, so a hand-written
    "TODO-sha256:" was reported OK — the check agreeing with a value nobody had
    filled in. Anything that is obviously not a real value must fail."""
    pat = re.search(r"grep -qiE '([^']+)'", BODY)
    assert pat, "the placeholder pattern is gone"
    assert re.search(pat.group(1), placeholder, re.I), (
        f"{placeholder!r} would be accepted as a real value")


def test_a_real_looking_value_is_still_accepted():
    """The guard must not become one that rejects everything."""
    pat = re.search(r"grep -qiE '([^']+)'", BODY).group(1)
    for real in ("Packer@Build1", "3.12.10",
                 "fdfe385b94f5b8785a0226a886979527fd26eb65defdbf29992fd22cc4b0e31e"):
        assert not re.search(pat, real, re.I), f"{real!r} wrongly rejected"


def test_required_variables_are_derived_not_restated():
    """The first version hardcoded six variable names and printed "Ready" while
    guest_password was still TODO. windows11-base actually declares NINE
    variables with no default. A list maintained by hand drifts from the
    template; parsing it cannot."""
    assert "windows11-base.pkr.hcl" in BODY, "the required list must come from the template"
    base = BASE.read_text(encoding="utf-8")
    declared = {m.group(1) for m in re.finditer(
        r'variable "([^"]+)"\s*\{(.*?)\n\}', base, re.S)
        if not re.search(r"^\s*default\s*=", m.group(2), re.M)}
    assert len(declared) >= 9, declared
    # Assert on the MECHANISM: the loop must iterate the parsed list. Checking
    # only for quoted variable names missed a mutation that swapped in a bare
    # `for var in win11_iso_path winrm_password ...` -- the test passed against
    # its own blind spot, which is the defect this whole script is about.
    assert re.search(r"for\s+var\s+in\s+\$required\b", BODY), (
        "the loop no longer iterates the list parsed from the template")
    stripped = re.sub(r"^\s*#.*$", "", BODY, flags=re.M)
    # win11_iso_path is named once on purpose: it gets an extra file-exists check.
    hardcoded = {v for v in declared
                 if re.search(rf"(?<![\w$]){re.escape(v)}(?![\w])", stripped)}
    assert hardcoded <= {"win11_iso_path"}, (
        f"restated in the script instead of parsed: {hardcoded - {'win11_iso_path'}}")


def test_a_comment_saying_no_default_is_not_mistaken_for_one():
    """`guest_password` carries the comment "# No default - set in
    packer.auto.pkrvars.hcl". A check for the word `default` matches that and
    concludes the variable is optional, which is exactly what went wrong."""
    base = BASE.read_text(encoding="utf-8")
    block = base.split('variable "guest_password"')[1].split("\n}")[0]
    assert "default" in block, "the comment this guards against is gone; re-confirm the parser"
    assert not re.search(r"^\s*default\s*=", block, re.M), "guest_password gained a real default"
    assert "default[[:space:]]*=" in BODY or "default[[:space:]]*=" in BODY.replace("\\", ""), \
        "the script must match an assignment, not the bare word"
