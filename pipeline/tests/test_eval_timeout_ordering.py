# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The harness backstop must sit ABOVE the interpret container's own timeout.

If the harness kills first, a stuck run surfaces as an opaque subprocess kill
instead of the container's own "exited without final result" — which is the
signal that told us qwen@25 was timing out in benchmark pass 1 rather than
failing for a model reason.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _container_timeout() -> int:
    txt = (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text()
    m = re.search(r'^interpret_container_timeout:\s*"?(\d+)"?', txt, re.MULTILINE)
    assert m, "interpret_container_timeout not found"
    return int(m.group(1))


def _harness_timeout() -> int:
    txt = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval"
           / "runner.py").read_text()
    m = re.search(r"^_EVAL_TIMEOUT\s*=\s*(\d+)", txt, re.MULTILINE)
    assert m, "_EVAL_TIMEOUT not found"
    return int(m.group(1))


def test_harness_backstop_exceeds_container_timeout():
    container, harness = _container_timeout(), _harness_timeout()
    assert harness > container, (
        f"_EVAL_TIMEOUT={harness}s must exceed interpret_container_timeout="
        f"{container}s so the container reaps stuck runs first"
    )


def test_container_budget_covers_the_measured_slow_tail_plus_synthesis():
    """The container timeout is a TOTAL budget: tool loop AND synthesis.

    On 2026-07-27 the same arm on the same sample took 25min and 86min on two runs,
    depending on how many functions the model chose to decompile. The 86min run then
    reached synthesis with ~4min left and was SIGKILLed at exactly 5400.5s — the budget
    was spent before the work that produces the answer ever started.

    Sized as: slow-tail tool loop (~86min) + a real synthesis window (~30min) + margin.
    """
    container = _container_timeout()
    assert container >= 10800, (
        f"interpret_container_timeout={container}s leaves no room for synthesis after a "
        f"slow tool loop; a 30-cycle run has been measured at 86min of tool calls alone")


def test_backstop_leaves_room_for_the_container_to_reap_first():
    """A margin too thin and the harness wins the race, hiding the container's error."""
    container, harness = _container_timeout(), _harness_timeout()
    assert harness - container >= 900, (
        f"only {harness - container}s between container reap and harness backstop; "
        f"leave at least 15min so the container's own error reaches the scorecard")
