# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: the runner sets max_tool_calls + re_backend per arm on the cfg."""
from pathlib import Path  # noqa: F401  (used by the existing guards below)


def test_runner_persists_the_full_result_for_adjudication():
    """Family-ID is analyst-adjudicated, so the narrative must survive the run.

    Before this, only llm_audit/tool_calls.json was written per cell — a
    completed benchmark left nothing to adjudicate but a one-word guess.
    """
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "runner.py").read_text()
    assert '"result.json"' in src, "runner must persist the interpret result"

RUNNER = (Path(__file__).resolve().parents[2]
          / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval" / "runner.py")


def test_runner_sets_per_arm_cfg():
    t = RUNNER.read_text(encoding="utf-8")
    assert "max_tool_calls" in t and "re_backend" in t
    assert "run_interpret(" in t and "compose_cell(" in t
