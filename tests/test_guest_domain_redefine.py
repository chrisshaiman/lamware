# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""`virsh define` must be able to UPDATE an existing guest domain.

Observed 2026-08-08, deploying #327's emulator repoint:

    error: Failed to define domain from /tmp/cape-guest-clean.xml
    error: operation failed: domain 'clean' already exists with uuid
           0f6cdad0-dce8-4925-8f48-e8f80c639a98

libvirt updates an existing domain only when the incoming XML carries that
domain's UUID. The template emitted `<name>` and no `<uuid>`, so libvirt minted a
fresh identity and refused the name collision.

The consequence is worse than one failed deploy: **the guest domain XML could
never be changed after first deploy.** The task runs unconditionally on every
`cape-guests` run, so it had been failing — or never re-running against defined
domains — for as long as the domains have existed. #327 was simply the first
change that needed a redefine to take effect.

Undefining first is not the fix: `virsh undefine` discards snapshot metadata, and
those snapshots are the pristine baseline for every detonation (#332).
"""
from pathlib import Path

import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "ansible" / "roles" / "cape-guests" / "tasks" / "main.yml"
TEMPLATE = (ROOT / "ansible" / "roles" / "cape-guests" / "templates"
            / "guest-domain.xml.j2")

TASKS_SRC = TASKS.read_text(encoding="utf-8")
TEMPLATE_SRC = TEMPLATE.read_text(encoding="utf-8")


def _render(uuid_map) -> str:
    """Render just the identity block — the rest of the template needs the full
    cape_guests item and is not what this file is about."""
    env = Environment(autoescape=False)  # noqa: S701 - libvirt XML, not HTML
    start = TEMPLATE_SRC.index("<name>")
    end = TEMPLATE_SRC.index("<memory")
    ctx = {"item": {"name": "clean"}}
    if uuid_map is not None:
        ctx["cape_guest_uuid_map"] = uuid_map
    return env.from_string(TEMPLATE_SRC[start:end]).render(**ctx)


def _task_index(fragment: str) -> int:
    idx = TASKS_SRC.find(fragment)
    assert idx != -1, f"task not found: {fragment!r}"
    return idx


def test_an_existing_uuid_is_emitted():
    """THE fix. Without this element libvirt rejects the redefine outright."""
    out = _render({"clean": "0f6cdad0-dce8-4925-8f48-e8f80c639a98"})
    assert "<uuid>0f6cdad0-dce8-4925-8f48-e8f80c639a98</uuid>" in out


def test_a_first_define_omits_the_uuid():
    """A domain that does not exist yet has no UUID to reuse; libvirt assigns one.
    Emitting an empty <uuid></uuid> would be worse than omitting it."""
    assert "<uuid>" not in _render({"clean": ""})
    assert "<uuid>" not in _render({})
    assert "<uuid>" not in _render(None), (
        "the map being undefined entirely must not raise — it is undefined on the "
        "very first run, before the lookup task has ever registered anything")


def test_a_different_guests_uuid_is_not_used():
    """Cross-assigning UUIDs would define `clean` with `office`'s identity."""
    assert "<uuid>" not in _render({"office": "8215c1c5-2f51-48c4-b551-b10f240f8bb4"})


def test_the_lookup_runs_before_the_template_is_rendered():
    """Ordering is load-bearing: the map has to exist when the template runs."""
    assert (_task_index("Read existing domain UUIDs")
            < _task_index("Deploy guest libvirt domain XML")
            < _task_index("Define guest libvirt domains"))


def test_the_lookup_tolerates_an_absent_domain():
    """First deploy has no domains. A failing lookup must not abort the run."""
    tasks = yaml.safe_load(TASKS_SRC)
    lookup = next(t for t in tasks
                  if "Read existing domain UUIDs" in (t.get("name") or ""))
    assert lookup.get("failed_when") is False
    assert lookup.get("changed_when") is False


def test_the_role_never_undefines_a_domain():
    """`virsh undefine` discards snapshot metadata, and those snapshots are the
    pristine baseline for every detonation (#332). Redefining in place is the
    only acceptable way to change domain XML."""
    assert "virsh undefine" not in TASKS_SRC, (
        "undefining to force a redefine would destroy the snapshots")


def test_the_rationale_survives():
    assert "#327" in TASKS_SRC or "#327" in TEMPLATE_SRC, (
        "record why the UUID is threaded through — it looks like noise otherwise")
