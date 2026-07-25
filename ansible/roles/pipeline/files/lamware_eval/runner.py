# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Run one (sample x arm) through the agentic RE loop; return a scorecard cell."""
import json
import time
from pathlib import Path

from stages.interpret import run_interpret
from llm_ab_re import extract_metrics
from lamware_eval.arms import Arm
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import compose_cell

_EVAL_TIMEOUT = 4800

# $/1M tokens (input, output). Local arms cost $0. Extend as models are added.
_RATES = {
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-4-6": (3.0, 15.0),
}


def _rough_cost(model: str, usage: dict) -> float:
    ci, co = _RATES.get(model, (0.0, 0.0))
    return round(usage.get("input_tokens", 0) / 1e6 * ci
                 + usage.get("output_tokens", 0) / 1e6 * co, 4)


def run_arm(sample: CorpusSample, arm: Arm, base_cfg: dict,
            interpret_cmd: str, ghidra_cmd: str) -> dict:
    report = json.loads((Path(sample.corpus_dir) / "report.json").read_text())
    gr = report["ghidra"]
    claude_family = (report.get("llm_interpretation") or {}).get("analysis", {}).get("malware_family_guess")
    cfg = {**base_cfg, "model": arm.model, "max_tool_calls": arm.max_tool_calls,
           "max_output_tokens": max(base_cfg.get("max_output_tokens", 0), 16384)}
    if arm.re_backend == "local":
        cfg["re_backend"] = "local"
        cfg["escalation_model"] = arm.model
    out = Path(sample.corpus_dir) / "eval" / arm.name.replace("/", "_").replace("@", "_")
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    res = run_interpret(gr, out, interpret_cmd, True, _EVAL_TIMEOUT, cfg, ghidra_cmd)
    secs = round(time.time() - t0, 1)
    analysis = res.get("analysis", {}) or {}
    usage = res.get("usage", {}) or {}
    cost = 0.0 if arm.re_backend == "local" else _rough_cost(arm.model, usage)
    source = json.dumps(gr)  # grounding corpus = the ghidra data the model saw
    return compose_cell(arm.name, sample, analysis, source, claude_family, secs, cost,
                        extract_metrics(res), res.get("error") or analysis.get("error"))
