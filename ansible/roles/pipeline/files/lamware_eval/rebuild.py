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

from llm_ab_re import analysis_completed

from lamware_eval.corpus import load_corpus
from lamware_eval.metrics import aggregate, compose_cell
from lamware_eval.runner import _RATES, tool_output_text
from lamware_eval.scorecard import render_scorecard


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
                cells.append(compose_cell(
                    arm_dir.name, sample, analysis, source, claude_family,
                    res.get("duration_seconds") or 0.0,
                    0.0 if local else _cost(model, usage),
                    # Shared with the live path so a re-score cannot disagree
                    # with the sweep that produced the cell (#380).
                    {"completed": analysis_completed(res),
                     "parse_failed": bool(analysis.get("parse_note")),
                     "tool_calls_used": res.get("tool_calls_used"),
                     "tool_call_error_rate": 0.0},
                    analysis.get("parse_note")))
    return render_scorecard(label, cells, aggregate(cells)), cells


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(prog="lamware_eval.rebuild")
    ap.add_argument("--corpus", default="/opt/pipeline/eval/corpus.json")
    ap.add_argument("--label", default="rebuild")
    ap.add_argument("--out-dir", default="/opt/pipeline/eval-corpus/results")
    args = ap.parse_args()
    md, cells = rebuild(args.corpus, args.label)
    out = Path(args.out_dir) / f"{args.label}.md"
    out.write_text(md)
    print(f"[rebuild] {len(cells)} cells -> {out}")
    print(md)


if __name__ == "__main__":
    main()
