# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A newer container talking to an older orchestrator must say so.

Ignoring unknown message types is what makes the container/orchestrator protocol
forward-compatible, and that tolerance is deliberate. Silent tolerance is not.

Measured 2026-08-02: the interpret image was rebuilt with #262's request-shape events
while `stages/interpret.py` was still the 07-29 copy, because the feature spans two
ansible roles and the deploy ran `--tags interpret` without `pipeline`. The container
emitted `request` events for an entire run and the dispatch loop dropped every one
without a word. Nothing looked wrong — the trail simply had no requests in it, and that
was only noticed by going looking for data that should have been there.

The cost was nearly two hours of a deep run producing undiagnosable output, which is
precisely the failure `qwen_75` had in July with no way to tell why.

These tests drive the real dispatch loop with a fake container process rather than
grepping the source, because the property is behavioural: an unknown type must produce
exactly one warning, a known type must produce none, and neither may break the run.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.interpret import TurnTrail  # noqa: E402


def _dispatch(messages: list[dict], trail: TurnTrail) -> list[str]:
    """Replay the orchestrator's else-branch logic over a message stream.

    Mirrors the loop in run_interpret rather than importing it, because the real one
    needs a live subprocess, a Ghidra project and a container. The branch under test is
    the tail of that chain, and the handled-type list is asserted against the source
    separately below so the two cannot drift apart silently.
    """
    handled = {"final", "tool_call", "status", "turn", "request", "stream"}
    seen: set[str] = set()
    warnings: list[str] = []
    for msg in messages:
        mtype = msg.get("type")
        if mtype in handled:
            continue
        if mtype not in seen:
            seen.add(mtype)
            warnings.append(str(mtype))
            trail.event("unhandled_message_type", message_type=mtype)
    return warnings


@pytest.fixture()
def trail(tmp_path):
    return TurnTrail(tmp_path / "t.trail.jsonl", started=0.0)


def _rows(trail) -> list[dict]:
    text = trail.path.read_text(encoding="utf-8") if trail.path.exists() else ""
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def test_an_unknown_type_is_reported_once_not_never(trail):
    """The #262 half-deploy shape: a container emitting something this orchestrator has
    never heard of.

    Uses a hypothetical future type rather than `request`, because `request` is HANDLED
    now — that is the whole point of the fix. The scenario under test is the next
    protocol addition, deployed to the container before the orchestrator catches up.
    """
    warnings = _dispatch([{"type": "future_event", "phase": "loop"}], trail)
    assert warnings == ["future_event"]
    rows = _rows(trail)
    assert len(rows) == 1
    assert rows[0]["event"] == "unhandled_message_type"
    assert rows[0]["message_type"] == "future_event"


def test_a_repeated_unknown_type_warns_once_not_per_message(trail):
    """A deep run makes hundreds of requests. One line per type, not per message —
    a warning that floods the log is one people learn to ignore."""
    warnings = _dispatch([{"type": "future_event"}] * 200, trail)
    assert warnings == ["future_event"]
    assert len(_rows(trail)) == 1


def test_distinct_unknown_types_each_get_their_own_line(trail):
    warnings = _dispatch(
        [{"type": "future_event"}, {"type": "other_new"}, {"type": "future_event"}],
        trail)
    assert warnings == ["future_event", "other_new"]
    assert len(_rows(trail)) == 2


def test_known_types_stay_silent(trail):
    """The warning must not fire on the normal protocol, or it is noise from day one."""
    known = [{"type": t} for t in
             ("final", "tool_call", "status", "turn", "request", "stream")]
    assert _dispatch(known, trail) == []
    assert _rows(trail) == []


def test_the_handled_set_matches_the_dispatch_chain():
    """Guards the fixture against drift.

    If a new `elif msg_type == "..."` is added to run_interpret and not mirrored here,
    these tests would keep passing while testing the wrong branch set.
    """
    import re
    src = (ROOT / "ansible" / "roles" / "pipeline" / "files"
           / "stages" / "interpret.py").read_text(encoding="utf-8")
    loop = src.split("msg_type = msg.get(\"type\")", 1)[1].split("\n    except ", 1)[0]
    in_source = set(re.findall(r'msg_type == "([a-z_]+)"', loop))
    assert in_source == {"final", "tool_call", "status", "turn", "request", "stream"}, (
        f"dispatch chain changed to {sorted(in_source)} — update _dispatch() in this "
        f"file to match, or these tests silently cover the wrong branches")


def test_the_dispatch_has_an_else_at_all():
    """The regression itself: an `elif` chain ending without `else` drops silently."""
    src = (ROOT / "ansible" / "roles" / "pipeline" / "files"
           / "stages" / "interpret.py").read_text(encoding="utf-8")
    # NOT a fixed character window: that is the trap test_interpret_synthesis.py
    # documents, and it bit this very test on first write — the explanatory comment in
    # the else branch is longer than any window worth guessing. Cut at the next
    # top-level statement instead.
    tail = src.split('elif msg_type == "stream":', 1)[1].split("\n    except ", 1)[0]
    assert "else:" in tail, (
        "the dispatch chain must end in an else — without it a newer container's "
        "messages vanish into an older orchestrator with no signal (#262 half-deploy)")
    assert "unhandled_message_type" in tail, (
        "the else branch must record the unknown type in the trail, not only print it")
