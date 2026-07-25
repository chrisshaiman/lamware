# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: the runner sets max_tool_calls + re_backend per arm on the cfg."""
from pathlib import Path

RUNNER = (Path(__file__).resolve().parents[2]
          / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval" / "runner.py")


def test_runner_sets_per_arm_cfg():
    t = RUNNER.read_text(encoding="utf-8")
    assert "max_tool_calls" in t and "re_backend" in t
    assert "run_interpret(" in t and "compose_cell(" in t
