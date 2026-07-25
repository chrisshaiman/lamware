# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CLI: python -m lamware_eval run --corpus <path> --arms <csv> --label <name>"""
import argparse
import json
import os
from pathlib import Path

from lamware_eval.arms import parse_arms
from lamware_eval.corpus import load_corpus
from lamware_eval.metrics import aggregate
from lamware_eval.runner import run_arm
from lamware_eval.scorecard import render_scorecard


def _failed_cell(arm_name: str, sample, err: str) -> dict:
    return {"arm": arm_name, "sample": sample.sha256[:12], "family_guess": None,
            "mb_family": sample.mb_family, "claude_family": None, "grounded": 0,
            "total": 0, "fabricated": [], "grounded_ratio": 1.0, "completed": False,
            "tool_calls_used": 0, "tool_call_error_rate": 0.0, "wall_seconds": 0.0,
            "cost_usd": 0.0, "error": err}


def main() -> None:
    ap = argparse.ArgumentParser(prog="lamware_eval")
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--arms", required=True)
    ap.add_argument("--label", default="eval")
    ap.add_argument("--config", default="/opt/pipeline/config.json")
    ap.add_argument("--interpret-cmd", default="/opt/interpret/run-interpret")
    ap.add_argument("--ghidra-cmd", default="/opt/ghidra/run-ghidra")
    ap.add_argument("--out-dir", default="/opt/pipeline/eval-corpus/results")
    args = ap.parse_args()

    base_cfg = json.loads(Path(args.config).read_text())["interpret"]
    samples = load_corpus(args.corpus)
    arms = parse_arms(args.arms)
    cells = []
    for s in samples:
        for a in arms:
            try:  # one bad (sample x arm) never kills the run
                cells.append(run_arm(s, a, base_cfg, args.interpret_cmd, args.ghidra_cmd))
            except Exception as e:
                cells.append(_failed_cell(a.name, s, f"{type(e).__name__}: {e}"))
    md = render_scorecard(args.label, cells, aggregate(cells))
    os.makedirs(args.out_dir, exist_ok=True)
    out = Path(args.out_dir) / f"{args.label}.md"
    out.write_text(md)
    print(f"[eval] wrote {out}")
    print(md)


if __name__ == "__main__":
    main()
