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
