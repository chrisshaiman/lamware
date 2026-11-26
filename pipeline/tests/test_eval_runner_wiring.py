# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: the runner sets max_tool_calls + re_backend per arm on the cfg."""
from pathlib import Path  # noqa: F401  (used by the existing guards below)


def test_an_arm_runs_its_own_model_and_no_escalation_key_reaches_it():
    """An arm that switches into another model is not measuring itself.

    In pass 1 (2026-07-25) all 7 claude-sonnet-5 cells finished on claude-opus-4-6
    through escalation. ADR-038 removed escalation; a stale base config that still
    carries escalation_* keys must not pass them on. Calls arm_config for real.
    """
    from lamware_eval.arms import Arm
    from lamware_eval.runner import arm_config
    base = {"model": "local-qwen-llamacpp-re", "escalation_model": "claude-opus-4-6",
            "escalation_threshold": 5, "max_output_tokens": 4096, "re_backend": "local"}
    for arm in (Arm("cloud", "eval-sonnet55", "router", 10), Arm("local", "local-qwen-llamacpp-re", "local", 10)):
        cfg = arm_config(arm, base, "agentic")
        assert cfg["model"] == arm.model
        assert not [k for k in cfg if k.startswith("escalation_")], cfg


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
