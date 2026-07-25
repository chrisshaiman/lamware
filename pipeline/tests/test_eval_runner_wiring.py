# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: the runner sets max_tool_calls + re_backend per arm on the cfg."""
from pathlib import Path  # noqa: F401  (used by the existing guards below)


def test_escalation_is_pinned_to_the_arm_for_every_arm():
    """An arm that escalates into another model is not measuring itself.

    In pass 1 (2026-07-25) escalation_model was pinned only for LOCAL arms, so
    all 7 claude-sonnet-5 cells finished on claude-opus-4-6 and the run produced
    no clean sonnet-5 data. The pin must sit in the base cfg, outside the
    local-only branch.
    """
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "runner.py").read_text()
    cfg_block = src.split("cfg = {", 1)[1].split("}", 1)[0]
    assert '"escalation_model": arm.model' in cfg_block, (
        "escalation_model must be pinned for ALL arms, not just local ones"
    )


def test_grounding_source_includes_tool_output():
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "runner.py").read_text()
    assert "tool_output_text(out)" in src, (
        "grounding source must include tool-call output, not just the ghidra dump"
    )


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
