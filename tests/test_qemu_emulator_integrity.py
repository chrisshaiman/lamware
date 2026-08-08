# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The DSDT-patched emulator must survive package operations (#308).

On 2026-08-06 an apt transaction installing `libguestfs-tools` pulled in
`qemu-system-x86` as a dependency, overwriting the CAPE-built DSDT-patched
`/usr/bin/qemu-system-x86_64` with stock 8.2.2. Both detonation guests then failed:

    error: unsupported configuration: Emulator '/usr/bin/qemu-system-x86_64'
           does not support machine type 'pc-q35-9.2'

Two things made it durable rather than self-healing:

  1. The patched binary lived at a dpkg-owned path, so ANY package operation
     touching qemu-system-x86 could replace it.
  2. The build's idempotence guard checked only a stamp file. The stamp survived
     the clobber, so the role reported "already run" and would never have rebuilt.

Had a guest started, it would have run an emulator WITHOUT the ACPI anti-detection
the sandbox depends on (ADR-012) — a silent fidelity loss, worse than the visible
failure. Verified afterwards: no analysis completed after the replacement, so no
stored result is affected.

THIS CHANGE PRESERVES ONLY. `cape_qemu_binary` still points at /usr/bin, so guests
are unaffected; #327 repoints them once preservation has been observed working on a
real host. The first attempt at this fix is why: it guarded the preserve step on
"has the build ever run" rather than "is this binary the patched one", so it copied
stock 8.2.2 to the preserve path. With a simultaneous repoint that would have
re-caused #308 with the fix installed and the tests green.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
QEMU_TASKS = ROOT / "ansible" / "roles" / "qemu-patched" / "tasks" / "main.yml"
QEMU_DEFAULTS = ROOT / "ansible" / "roles" / "qemu-patched" / "defaults" / "main.yml"
CAPE_DEFAULTS = ROOT / "ansible" / "roles" / "cape" / "defaults" / "main.yml"
GUEST_XML = (ROOT / "ansible" / "roles" / "cape-guests" / "templates"
             / "guest-domain.xml.j2")

TASKS = QEMU_TASKS.read_text(encoding="utf-8")

# Comment-free view of the same file.
#
# Absence assertions must not be satisfiable by the prose that explains the
# absence. This file's comments quote both removed constructs verbatim
# (`cape_kvm_qemu_stamp` in the preserve rationale, `'q35' in` in the assertion
# rationale), so a plain substring check over the source finds them and passes
# while the code is still wrong. Round-tripping through the YAML parser drops
# comments structurally — they never survive parsing.
CODE = yaml.safe_dump(yaml.safe_load(TASKS), default_flow_style=False)


def _tasks() -> list:
    """Every task, including those nested inside a block."""
    out = []
    for entry in yaml.safe_load(TASKS) or []:
        out.append(entry)
        for key in ("block", "always", "rescue"):
            out.extend(entry.get(key) or [])
    return out


def _task(fragment: str) -> dict:
    matches = [t for t in _tasks() if fragment in (t.get("name") or "")]
    assert matches, f"no task named like {fragment!r}"
    return matches[0]


def _task_index(fragment: str) -> int:
    idx = TASKS.find(fragment)
    assert idx != -1, f"task not found: {fragment!r}"
    return idx


def _assert_conditions(fragment: str) -> list:
    """The `that:` conditions of an assert task, as parsed strings.

    Parsed values, never dumped text: `yaml.safe_dump` re-escapes embedded quotes,
    so a substring check over its output cannot see a condition like `'q35' in x`.
    """
    task = _task(fragment)
    body = task.get("ansible.builtin.assert") or task.get("assert") or {}
    that = body.get("that")
    assert that is not None, f"{fragment!r} is not an assert task"
    return [str(c) for c in (that if isinstance(that, list) else [that])]

def test_the_comment_stripper_actually_strips():
    """Guards the guard.

    A stripper that mangles content would make every `not in CODE` assertion below
    pass unconditionally — which is how the first version of this file's Python
    equivalent shipped a vacuous check. Negative control: comment text is gone.
    Positive control: real task content survives, contiguously.
    """
    assert "the same shape as #238's unfirable" not in CODE, "comments must go"
    assert "qemu_usrbin_origin" in CODE, "real task content must survive"
    assert "Preserve the DSDT-patched emulator" in CODE


# ---------------------------------------------------------------------------
# The preserve step must verify its SOURCE
# ---------------------------------------------------------------------------

def test_preserve_is_gated_on_the_binary_being_ours_not_on_the_stamp():
    """THE bug in the first attempt.

    `cape_kvm_qemu_stamp.stat.exists` means "the build once succeeded" — which is
    true precisely when the binary has since been clobbered. Guarding on it copies
    stock QEMU to the preserve path.
    """
    when = str(_task("Preserve the DSDT-patched emulator").get("when", ""))
    assert "qemu_usrbin_origin" in when, (
        f"the preserve step must check what the source binary actually IS; "
        f"its condition is {when!r}")
    assert "cape_kvm_qemu_stamp" not in when, (
        f"preserve must NOT be gated on the stamp — that is the bug this fixes. "
        f"Condition: {when!r}")
    assert "NOT_PACKAGED" in when and "MODIFIED" in when


def test_a_pristine_packaged_binary_is_refused():
    """If /usr/bin holds the unmodified package file and nothing is preserved, the
    patched build is gone. Preserving would enshrine stock QEMU as 'patched'."""
    assert "PRISTINE_PACKAGE" in TASKS
    task = _task("Refuse to preserve the stock emulator")
    block = yaml.safe_dump(task)
    assert "ansible.builtin.assert" in block
    assert "cape_qemu_preserved.stat.exists" in block, (
        "an existing good copy must make this survivable rather than fatal")


def test_origin_is_determined_by_dpkg_not_by_a_version_string():
    """Version comparison breaks the moment the distro ships a version matching
    ours. dpkg answers 'is this the file the package shipped' directly."""
    block = yaml.safe_dump(_task("Ask dpkg whether the distro-path emulator"))
    assert "dpkg -S" in block and "dpkg -V" in block


def test_preserve_runs_before_the_package_restore():
    """Ordering is load-bearing: the restore can pull qemu-system-x86 in as a
    dependency of libvirt-daemon-system and clobber the source first."""
    assert (_task_index("Preserve the DSDT-patched emulator")
            < _task_index("Reinstall libvirt and QEMU ROM packages"))


# ---------------------------------------------------------------------------
# The build guard must detect a clobbered binary
# ---------------------------------------------------------------------------

def test_the_build_guard_checks_the_binary_not_only_a_stamp():
    """Why the damage was durable: apt replaced the binary, the stamp survived,
    the role said 'already run'."""
    assert "cape_kvm_qemu_stamp.stat.exists and cape_qemu_preserved.stat.exists" in TASKS
    assert TASKS.count(
        "not (cape_kvm_qemu_stamp.stat.exists and cape_qemu_preserved.stat.exists)") == 2, (
        "both the config write and the build block must re-trigger on a clobber")


# ---------------------------------------------------------------------------
# The post-deploy assertion must check what the domains actually need
# ---------------------------------------------------------------------------

def test_the_assertion_uses_the_domains_own_machine_types():
    """The required machine type is NOT in this repo.

    guest-domain.xml.j2 says machine='q35', the generic alias; libvirt resolves it
    at define time and freezes the result ("pc-q35-9.2") into the persistent domain
    XML. Asking the domains is the only way to know it without inventing a version.
    """
    assert "virsh dumpxml" in TASKS, (
        "the required machine type must come from the defined domains")
    conditions = _assert_conditions("Fail if an emulator cannot run a machine type")
    assert any("qemu_required_machines" in c for c in conditions)
    assert any("difference" in c for c in conditions), (
        "the check must be a set difference against the domains' requirements, "
        "not a substring match on the emulator's output")

def test_the_assertion_is_not_satisfiable_by_the_bare_q35_alias():
    """Regression guard on the vacuous check that shipped in the first attempt.

    `'q35' in stdout` is true for stock QEMU 8.2.2, so it would have passed
    throughout the outage it was written to catch.

    Asserted against the PARSED condition strings, not dumped YAML. `safe_dump`
    re-escapes quotes (`'q35'` becomes `''q35''`), so a substring check over dumped
    text silently misses it — this test passed against the mutation until that was
    found.
    """
    conditions = _assert_conditions("Fail if an emulator cannot run a machine type")
    joined = " ".join(conditions)
    assert "q35" not in joined, (
        f"the assertion matches a bare machine-type alias, which stock QEMU also "
        f"advertises: {conditions!r}")
    assert "qemu_required_machines" in joined, (
        f"the assertion must compare against what the DOMAINS require: {conditions!r}")

def test_both_the_configured_and_preserved_emulators_are_checked():
    """During the split, cape_qemu_binary and the preserved path differ. Checking
    only one would leave the other unverified at exactly the moment it matters."""
    block = yaml.safe_dump(_task("Read the machine types each candidate emulator"))
    assert "cape_qemu_binary" in block
    assert "qemu_patched_preserved_path" in block


def test_no_defined_domains_is_reported_rather_than_passing_quietly():
    """A check that cannot run must not look like a check that passed."""
    assert "It is NOT a pass" in TASKS


# ---------------------------------------------------------------------------
# The split: this change preserves, it does not repoint
# ---------------------------------------------------------------------------

def test_the_preserved_path_is_outside_dpkgs_namespace():
    text = QEMU_DEFAULTS.read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines()
                if ln.strip().startswith("qemu_patched_preserved_path:"))
    path = line.split(":", 1)[1].strip()
    assert not path.startswith("/usr/bin/"), (
        f"{path!r} is dpkg-owned — apt would overwrite the preserved copy too")
    assert path.startswith("/usr/local/")


def test_the_domains_point_at_the_preserved_emulator():
    """#327. Repointed only after the preserved copy was verified on the host:
    identical sha256 to a binary dpkg reports as MODIFIED (i.e. our build, not the
    package's), version 9.2.2 against stock 8.2.2, and supporting pc-q35-9.2 —
    the type both domains are frozen against."""
    text = CAPE_DEFAULTS.read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines()
                if ln.strip().startswith("cape_qemu_binary:"))
    path = line.split(":", 1)[1].strip()
    assert not path.startswith("/usr/bin/"), (
        f"cape_qemu_binary is {path!r}, a dpkg-owned path — apt overwrites the "
        f"DSDT-patched build there, which is #308")
    assert path.startswith("/usr/local/")


def test_the_snapshot_mismatch_is_reported():
    """The repoint is INCOMPLETE on its own, and nothing else would say so.

    libvirt stores the full domain config inside each snapshot, and CAPE reverts to
    snapshot before every detonation — so a redefined domain still boots the OLD
    emulator until the snapshots are recreated. Verified 2026-08-08: both `clean`
    and `office` snapshots pinned /usr/bin/qemu-system-x86_64.

    Reported rather than fatal: recreating a snapshot means taking a fresh pristine
    baseline, which is an operator decision, not something a deploy should do. But
    a repoint that cannot take effect must not look finished.
    """
    assert "snapshot-dumpxml" in TASKS, (
        "the role must read what the snapshots would actually restore")
    assert "SNAPSHOT EMULATOR MISMATCH" in TASKS
    assert "NOT a failure" in TASKS, (
        "must be explicit that this reports incompleteness, not an error")

def test_the_guest_template_uses_the_variable_not_a_hardcoded_path():
    """A hardcoded /usr/bin path in the template would defeat #327 before it starts."""
    xml = GUEST_XML.read_text(encoding="utf-8")
    assert "<emulator>{{ cape_qemu_binary }}</emulator>" in xml
    assert "<emulator>/usr/bin/" not in xml


def test_the_rationale_survives():
    """Someone will later ask why an emulator is being copied around."""
    assert "#308" in TASKS
    assert "libguestfs" in TASKS.lower(), (
        "record HOW it broke — an incidental dependency, not a deliberate upgrade")
    assert "#327" in TASKS, "the deferred repoint must be discoverable from here"
