# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Run one (sample x arm) through the agentic RE loop; return a scorecard cell."""
import json
import time
from pathlib import Path

from llm_ab_re import extract_metrics
from stages.interpret import run_interpret

from lamware_eval.arms import Arm
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import compose_cell

_EVAL_TIMEOUT = 4800

# $/1M tokens (input, output). Local arms cost $0. Extend as models are added.
# Hand-maintained rates drift silently (see the opus-4-6 3x overcount fixed in
# db_ingest, PR #182). LiteLLM's spend log is authoritative; treat these as an
# estimate for the scorecard only.
# NOTE: sonnet-5 is at INTRODUCTORY pricing through 2026-08-31, then $3/$15.
_RATES = {
    "claude-sonnet-5": (2.0, 10.0),
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-4-6": (3.0, 15.0),
}


def _rough_cost(model: str, usage: dict) -> float:
    ci, co = _RATES.get(model, (0.0, 0.0))
    return round(usage.get("input_tokens", 0) / 1e6 * ci
                 + usage.get("output_tokens", 0) / 1e6 * co, 4)


def tool_output_text(out_dir: Path) -> str:
    """Everything the tools returned during the agentic loop.

    Grounding must score against everything the model actually SAW. In an
    AGENTIC run that is not just the initial Ghidra dump — the model pulls more
    via decompile_function/get_strings_at, and IOCs it legitimately read out of
    decompiled code do not appear in that dump.

    Scoring against the dump alone reported 85% "fabrication" for the cloud arm
    on 2026-07-25, when its flagged values (`-id=`, `~%u.tmp`) were independently
    confirmed by a separate baseline run — i.e. almost all of that was artifact.
    """
    audit = out_dir / "llm_audit" / "tool_calls.json"
    if not audit.exists():
        return ""
    try:
        records = json.loads(audit.read_text())
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return ""  # a malformed audit must not sink the cell
    if not isinstance(records, list):
        return ""
    return " ".join(json.dumps(r.get("result", ""))
                    for r in records if isinstance(r, dict))


def run_arm(sample: CorpusSample, arm: Arm, base_cfg: dict,
            interpret_cmd: str, ghidra_cmd: str) -> dict:
    report = json.loads((Path(sample.corpus_dir) / "report.json").read_text())
    gr = report["ghidra"]
    claude_family = (report.get("llm_interpretation") or {}).get("analysis", {}).get("malware_family_guess")
    # Pin escalation to the arm's OWN model for EVERY arm, not just local ones.
    # Otherwise the interpret stage escalates into base_cfg's escalation_model
    # and the arm silently measures a different model: on 2026-07-25 all 7
    # claude-sonnet-5 cells finished on claude-opus-4-6 (escalated=True), so the
    # run produced no clean sonnet-5 data at all.
    cfg = {**base_cfg, "model": arm.model, "max_tool_calls": arm.max_tool_calls,
           "escalation_model": arm.model,
           "max_output_tokens": max(base_cfg.get("max_output_tokens", 0), 16384)}
    if arm.re_backend == "local":
        cfg["re_backend"] = "local"
    out = Path(sample.corpus_dir) / "eval" / arm.name.replace("/", "_").replace("@", "_")
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    res = run_interpret(gr, out, interpret_cmd, True, _EVAL_TIMEOUT, cfg, ghidra_cmd)
    secs = round(time.time() - t0, 1)
    analysis = res.get("analysis", {}) or {}
    usage = res.get("usage", {}) or {}
    cost = 0.0 if arm.re_backend == "local" else _rough_cost(arm.model, usage)
    # Grounding corpus = the initial Ghidra dump PLUS everything the tools
    # returned, i.e. the full set of bytes the model actually saw.
    source = json.dumps(gr) + " " + tool_output_text(out)

    # Persist the full interpret result. Family-ID is analyst-ADJUDICATED, which
    # is impossible after the fact if only the scorecard's one-word guess
    # survives — the narrative, capabilities and IOC list are what an analyst
    # actually reads to decide "right family / right class / wrong".
    (out / "result.json").write_text(json.dumps(res, indent=2, default=str))

    return compose_cell(arm.name, sample, analysis, source, claude_family, secs, cost,
                        extract_metrics(res), res.get("error") or analysis.get("error"))
