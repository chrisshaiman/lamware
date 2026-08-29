# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The evidence axis that makes #420's experiment possible.

The project's claim is "correlation before generation". In the code, correlation
runs AFTER the agent and its findings never reach it — `run_arm` passed
`report["ghidra"]` and nothing else. So the eval measured an agent reading
decompiler output, while the thesis is about an agent reading correlated
evidence. Those are different hypotheses and only the first was ever run.

These tests cover the axis itself. They do not assert that richer evidence helps
— that is the experiment, and its result is not decided here.
"""
import ast
import json
import sys
from pathlib import Path

_EVAL = Path(__file__).resolve().parents[2] / "ansible/roles/pipeline/files"
sys.path.insert(0, str(_EVAL))

from lamware_eval.arms import EVIDENCE_MODES, Arm, resolve_arm  # noqa: E402
from lamware_eval.runner import correlated_evidence  # noqa: E402


def test_the_pair_differs_in_exactly_one_variable():
    """Otherwise the comparison measures something other than evidence."""
    base, corr = resolve_arm("qwen@10"), resolve_arm("qwen@10+corr")
    assert (base.model, base.max_tool_calls, base.seed) == (corr.model, corr.max_tool_calls, corr.seed)
    assert base.evidence == "ghidra"
    assert corr.evidence == "correlated"


def test_every_base_arm_gets_a_corr_variant():
    """Evidence variants are registered BEFORE seed variants, so the naming is
    `qwen@10+corr:s42`, not `qwen@10:s42+corr`. Order matters: registering seeds
    first would leave the +corr arms unseeded, and test_eval_seed_arms requires
    every local arm to have them."""
    from lamware_eval.arms import _REGISTRY
    for name, arm in list(_REGISTRY.items()):
        if arm.evidence == "ghidra" and arm.seed is None:
            assert f"{name}+corr" in _REGISTRY, f"no +corr variant for {name}"


def test_seeded_corr_variants_keep_their_evidence_mode():
    """A seeded +corr arm that silently reverted to ghidra-only would compare an
    arm against itself while looking correctly configured."""
    a = resolve_arm("qwen@10+corr:s42")
    assert a.evidence == "correlated"
    assert a.seed == 42


def test_a_correlated_arm_is_actually_given_the_evidence():
    """The silent failure that matters most (caught by mutation, not by the
    earlier tests): if the wiring stops passing evidence, both arms get
    identical prompts and the run reports "no difference" having tested
    nothing — indistinguishable from a real null result."""
    from lamware_eval.runner import evidence_for
    report = {"cross_correlations": [{"type": "dropped_file_loaded"}]}
    assert evidence_for(resolve_arm("qwen@10+corr"), report) != {}
    assert evidence_for(resolve_arm("qwen@10"), report) == {}


def test_evidence_modes_are_the_declared_set():
    assert set(EVIDENCE_MODES) == {"ghidra", "correlated"}
    assert Arm("x", "m", None, 10).evidence == "ghidra", "default must not change behaviour"


# --- what the correlated arm is actually shown ---

def test_gathers_the_evidence_the_summary_writer_already_gets():
    report = {
        "cross_correlations": [{"type": "dropped_file_loaded", "severity": "high"}],
        "correlation_warnings": ["malfind unavailable"],
        "cape": {"signatures": [{"name": "injection_process_hollowing"}]},
        "volatility": {"insights": {"unique_mutexes": 284}},
    }
    ev = correlated_evidence(report)
    assert set(ev) == {"cross_correlations", "correlation_warnings",
                       "cape_signatures", "volatility_insights"}


def test_warnings_are_included_not_filtered():
    """A rule that could not run is evidence about coverage. Withholding it lets
    an empty finding list read as a clean sample — the substitution the warnings
    exist to prevent."""
    ev = correlated_evidence({"correlation_warnings": ["netscan unavailable"]})
    assert ev["correlation_warnings"] == ["netscan unavailable"]


def test_empty_report_yields_empty_evidence():
    """Samples with no correlations must make +corr byte-identical to its base
    arm. Those samples are then a control: the arms should agree exactly where
    the evidence is the same."""
    assert correlated_evidence({}) == {}
    assert correlated_evidence({"cross_correlations": [], "cape": {}}) == {}


# --- the agent side ---

def _agent_fn(name):
    src = (Path(__file__).resolve().parents[2]
           / "ansible/roles/interpret/files/interpret-ghidra.py").read_text()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"json": json}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<x>", "exec"), ns)
    return ns[name]


def test_agent_renders_nothing_without_evidence():
    assert _agent_fn("_correlated_evidence_context")({}) == ""


def test_agent_prompt_asks_for_corroboration_not_repetition():
    """Wording is part of the experiment. Presenting these as established
    findings would invite the model to restate them, raising grounded counts
    without the analysis improving — measuring recitation, not comprehension.
    It also risks anchoring the agent onto a conclusion instead of investigating.
    """
    out = _agent_fn("_correlated_evidence_context")({"correlated_evidence": {
        "cross_correlations": [{"severity": "high", "title": "T", "sources": ["Cape"], "detail": "d"}]}})
    low = out.lower()
    assert "corroborate or contradict" in low
    assert "not as conclusions to repeat" in low
    # It must not assert the observations are true findings.
    assert "confirmed" not in low
    assert "these are your findings" not in low


def test_agent_marks_warnings_as_coverage_limits():
    out = _agent_fn("_correlated_evidence_context")({"correlated_evidence": {
        "correlation_warnings": ["malfind unavailable"]}})
    assert "not evidence of absence" in out.lower()
