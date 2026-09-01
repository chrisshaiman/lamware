# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The provenance marker recorded intent, not outcome (#515).

It was written in `pre_tasks` — before a single role ran — so a play that
aborted halfway left a marker claiming full success. On 2026-09-01 a deploy of
`pipeline,dotnet-analysis,java-analysis` failed at the first role's container
build, and the marker afterwards said:

    {"sha": "c59c0a8691ce", "tags": ["dotnet-analysis","java-analysis","pipeline"]}

while the host disagreed:

    grep -c single_shot_backend /opt/pipeline/lamware_eval/runner.py  ->  0

`make provenance-has` answered LIVE for code that was not there. That target is
the first step in verifying every measurement this project makes, so a marker
that cannot be wrong in that direction is worse than no marker.

Two markers now: STARTED in pre_tasks, COMPLETED in post_tasks. A started stamp
newer than a completed one means a deploy died in the middle — the state that
misled us, and the one thing the single marker could never express.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAY = yaml.safe_load((ROOT / "ansible" / "site.yml").read_text(encoding="utf-8"))[0]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def _copies(section):
    return [t["ansible.builtin.copy"] for t in PLAY.get(section, [])
            if isinstance(t, dict) and isinstance(t.get("ansible.builtin.copy"), dict)]


def _dests(section):
    return [c.get("dest", "") for c in _copies(section)]


# --- the split ---


def test_the_completed_marker_is_written_after_the_roles():
    """THE fix. In post_tasks it can only exist if every role ran."""
    assert any(d.endswith("deploy-provenance.json") for d in _dests("post_tasks")), \
        _dests("post_tasks")


def test_the_completed_marker_is_not_written_before_them():
    """Writing it in pre_tasks is the defect. If it appears in both, the
    post_tasks copy is decoration."""
    assert not any(d.endswith("deploy-provenance.json") for d in _dests("pre_tasks")), \
        _dests("pre_tasks")


def test_a_started_marker_still_records_the_intent():
    """Intent is worth recording — it is what makes an ABORTED deploy
    distinguishable from one that never began."""
    assert any(d.endswith("deploy-started.json") for d in _dests("pre_tasks")), \
        _dests("pre_tasks")


def test_the_two_markers_are_different_files():
    started = {d for d in _dests("pre_tasks") if "deploy-" in d}
    completed = {d for d in _dests("post_tasks") if "deploy-" in d}
    assert started and completed and not (started & completed)


@pytest.mark.parametrize("section,name", [
    ("pre_tasks", "deploy-started.json"),
    ("post_tasks", "deploy-provenance.json"),
])
def test_both_markers_run_regardless_of_tags(section, name):
    """`make deploy TAGS=pipeline` is the common case. A marker that only wrote
    on a full run would be absent exactly when it is most needed (#151)."""
    task = next(t for t in PLAY[section]
                if isinstance(t, dict)
                and isinstance(t.get("ansible.builtin.copy"), dict)
                and t["ansible.builtin.copy"].get("dest", "").endswith(name))
    assert "always" in (task.get("tags") or []), task.get("tags")


# --- the consumer must act on it ---


def test_the_provenance_targets_refuse_on_an_unfinished_deploy():
    """A marker nobody checks is the same as no marker. Both targets gate on it,
    because `provenance-has` is the one used before trusting a measurement."""
    assert "provenance-unfinished-check:" in MAKEFILE
    for target in ("provenance:", "provenance-has:"):
        i = MAKEFILE.index(target)
        body = MAKEFILE[i:i + 700]
        assert "provenance-unfinished-check" in body, target


def test_the_unfinished_check_compares_the_two_markers_by_time():
    """Existence alone is not enough: both files persist across deploys, so only
    their ORDER says whether the last one finished."""
    i = MAKEFILE.index("provenance-unfinished-check:")
    body = MAKEFILE[i:i + 900]
    assert "deploy-started.json" in body and "deploy-provenance.json" in body
    assert "-gt" in body, "the check does not compare timestamps"
    assert "exit 1" in body, "the check reports but does not refuse"


def test_the_completed_marker_says_it_completed():
    """A reader with the file in hand and no memory of this change should be
    able to tell which kind of marker they are holding."""
    task = next(t for t in PLAY["post_tasks"]
                if isinstance(t, dict)
                and isinstance(t.get("ansible.builtin.copy"), dict))
    assert "completed" in task["ansible.builtin.copy"]["content"]
