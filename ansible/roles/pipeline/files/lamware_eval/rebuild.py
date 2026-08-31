# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Rebuild a scorecard from persisted result.json files - no model calls.

A scoring bug should never cost a re-run. Every cell's full interpret result is
written to <corpus_dir>/eval/<arm>/result.json before scoring, so a fixed metric
can be applied to completed work offline. On 2026-07-25 an IOC-shape crash
zeroed 5 of 7 local cells in a 2-hour sweep; this recovers that in seconds.
"""
import json
from pathlib import Path

from llm_ab_re import TOOL_LAYER_BROKEN_THRESHOLD, analysis_completed, is_tool_error

from lamware_eval.arms import resolve_arm
from lamware_eval.corpus import load_corpus
from lamware_eval.metrics import (
    aggregate,
    cell_error,
    compose_cell,
    ghidra_warnings_for,
)
from lamware_eval.provenance import gather as gather_provenance
from lamware_eval.runner import (
    _RATES,
    arm_name_from_cell_dir,
    evidence_for,
    held_out_techniques,
    tool_output_text,
)
from lamware_eval.scorecard import render_scorecard, write_scorecard


def _tool_call_metrics(arm_dir: Path) -> dict:
    """Recompute the tool-call figures from the persisted audit log.

    Uses the same `is_tool_error` the live path uses, for the reason #380
    established: two copies of a definition drift, and the offline re-scorer
    then disagrees with the sweep it is re-scoring.
    """
    # audit_filename() writes tool_calls.json for the main pass and
    # tool_calls_<analysis_type>.json for the others. The eval harness only ever
    # produces the plain one; prefer it, and fall back rather than assume.
    audit_dir = arm_dir / "llm_audit"
    candidates = [audit_dir / "tool_calls.json", *sorted(audit_dir.glob("tool_calls_*.json"))]
    log: list[dict] = []
    for p in candidates:
        if p.exists():
            try:
                log = json.loads(p.read_text())
            except (json.JSONDecodeError, OSError):
                log = []
            break
    if not log:
        return {"tool_calls_logged": 0, "tool_call_errors": 0,
                "tool_call_error_rate": 0.0, "tool_layer_broken": False}
    errors = sum(1 for e in log if is_tool_error(e))
    rate = round(errors / len(log), 3)
    return {"tool_calls_logged": len(log), "tool_call_errors": errors,
            "tool_call_error_rate": rate,
            "tool_layer_broken": rate >= TOOL_LAYER_BROKEN_THRESHOLD}


def _cost(model: str, usage: dict) -> float:
    ci, co = _RATES.get(model, (0.0, 0.0))
    return round(usage.get("input_tokens", 0) / 1e6 * ci
                 + usage.get("output_tokens", 0) / 1e6 * co, 4)


def rebuild(corpus_path: str, label: str) -> tuple[str, list[dict]]:
    """Re-score every persisted cell. Returns (markdown, cells)."""
    cells = []
    for sample in load_corpus(corpus_path):
        cdir = Path(sample.corpus_dir)
        report = json.loads((cdir / "report.json").read_text())
        gr = report.get("ghidra") or {}
        claude_family = ((report.get("llm_interpretation") or {})
                         .get("analysis", {}).get("malware_family_guess"))
        for arm_dir in sorted((cdir / "eval").glob("*")):
            # Skip the archive of superseded runs (#245); those are history, not arms,
            # and counting them would silently double-report old cells.
            if arm_dir.name.startswith("_"):
                continue
            rp = arm_dir / "result.json"
            if not rp.is_dir() and rp.exists():
                res = json.loads(rp.read_text())
                analysis = res.get("analysis") or {}
                usage = res.get("usage") or {}
                model = res.get("model_final") or ""
                local = "qwen" in arm_dir.name or "local" in model
                source = json.dumps(gr) + " " + tool_output_text(arm_dir)
                # The sweep scored an evidence-fed arm against its evidence too.
                # A re-score that did not would call those claims FABRICATED and
                # disagree with the run that produced the cell — the defect #380
                # already found in the tool figures here. Resolved by an exact
                # reverse lookup, not by matching on "+corr" in the directory
                # name.
                arm_name = arm_name_from_cell_dir(arm_dir.name)
                evidence = (evidence_for(resolve_arm(arm_name), report)
                            if arm_name else {})
                cells.append(compose_cell(
                    arm_dir.name, sample, analysis, source, claude_family,
                    res.get("duration_seconds") or 0.0,
                    0.0 if local else _cost(model, usage),
                    # Shared with the live path so a re-score cannot disagree
                    # with the sweep that produced the cell (#380). The tool
                    # figures were hardcoded to 0.0 here, which meant a re-score
                    # reported a clean tool layer no matter what the audit log
                    # said — the same defect in a second place (#316).
                    {"completed": analysis_completed(res),
                     "parse_failed": bool(analysis.get("parse_note")),
                     "tool_calls_used": res.get("tool_calls_used"),
                     **_tool_call_metrics(arm_dir)},
                    cell_error(res, analysis),
                    ghidra_warnings=ghidra_warnings_for(gr),
                    evidence=evidence,
                    cape_techniques=held_out_techniques(report)))
    provenance = gather_provenance(corpus_path, [c["sample"] for c in cells])
    return render_scorecard(label, cells, aggregate(cells), provenance), cells


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="lamware_eval.rebuild")
    ap.add_argument("--corpus", default="/opt/pipeline/eval/corpus.json")
    ap.add_argument("--label", default="rebuild")
    ap.add_argument("--force", action="store_true",
                    help="replace an existing scorecard of the same label")
    ap.add_argument("--out-dir", default="/opt/pipeline/eval-corpus/results")
    args = ap.parse_args()
    md, cells = rebuild(args.corpus, args.label)
    out = Path(args.out_dir) / f"{args.label}.md"
    write_scorecard(out, md, args.force)
    print(f"[rebuild] {len(cells)} cells -> {out}")
    print(md)


if __name__ == "__main__":
    main()
