# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Which CAPE guest ran a sample, and did the pin hold.

Shared deliberately. The production pipeline and the measurement harness both
submit to CAPE, and when they each carried their own copy of this the two
drifted: `lamware_detonate` pinned the guest and verified the pin, while
`run-pipeline` did neither. A second copy of a rule is how the rule becomes two
different rules.

Both CAPE guests are tagged `x64` in kvm.conf, so a submission tagged only x64
matches EITHER. `clean` has a pinned custom CPU model; `office` has
host-passthrough plus Office installed. Which one a sample lands on is therefore
a real variable, and unpinned it is decided by whichever machine happens to be
free -- recorded nowhere, and different between two runs of the same sample.
Tasks 1132 and 1133 were discarded for exactly this.
"""
from __future__ import annotations

MACHINE_REQUIRED = (
    "machine must be pinned: both CAPE guests are tagged x64, so an unpinned "
    "submission silently lands on whichever is free and the guest becomes an "
    "uncontrolled variable recorded nowhere")


def derive_machine(tags, default_machine: str, office_machine: str) -> str:
    """Pick the guest for a submission from its routing tags.

    Triage emits `office` for Word/Excel/PowerPoint/RTF/ODT and for YARA matches
    tagged macro or vba; everything else gets no routing tag. Office samples
    genuinely need the office guest (it has Office installed), so this is a real
    routing decision rather than a pin that could be constant -- which is why it
    is derived here rather than hardcoded at the call site.
    """
    if not default_machine or not office_machine:
        raise ValueError(MACHINE_REQUIRED)
    return office_machine if "office" in (tags or []) else default_machine


def verify_ran_on(info: dict, expected: str) -> str | None:
    """None if the completed task ran on `expected`, else why not.

    CAPE writes info.machine as a dict on current versions and a bare string on
    older ones. An unrecognised shape is a verification FAILURE, not a pass:
    "we could not check" and "it checked out" must never look alike, and a
    pinned parameter that silently stops being honoured is the failure this
    project keeps finding.
    """
    machine = (info or {}).get("machine")
    name = machine.get("name") if isinstance(machine, dict) else machine
    if not name:
        return (f"could not determine which machine the task ran on "
                f"(info.machine={machine!r}); refusing to assume it was {expected!r}")
    if name != expected:
        return f"ran on {name!r}, not {expected!r} -- pinning is not holding"
    return None


def machine_of(info: dict) -> str | None:
    """The guest name CAPE recorded, or None if the shape is unrecognised."""
    machine = (info or {}).get("machine")
    name = machine.get("name") if isinstance(machine, dict) else machine
    return name or None
