# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CLI: python -m lamware_eval run --corpus <path> --arms <csv> --label <name>"""
import argparse
import json
import os
from pathlib import Path

from lamware_eval.arms import parse_arms
from lamware_eval.consensus import consensus, render_consensus
from lamware_eval.corpus import filter_samples, load_corpus
from lamware_eval.metrics import aggregate
from lamware_eval.runner import cell_out_dir, run_arm
from lamware_eval.scorecard import render_scorecard


def _failed_cell(arm_name: str, sample, err: str, seed: int | None = None) -> dict:
    return {"arm": arm_name, "seed": seed, "sampling": None,
            "sample": sample.sha256[:12], "family_guess": None,
            "mb_family": sample.mb_family, "claude_family": None, "grounded": 0,
            "total": 0, "fabricated": [], "grounded_ratio": 1.0, "completed": False,
            "tool_calls_used": 0, "tool_call_error_rate": 0.0, "wall_seconds": 0.0,
            "cost_usd": 0.0, "error": err}


def _base_arm(name: str) -> str:
    """`qwen@30:s42` -> `qwen@30`. Seed variants of one base are what get reconciled."""
    return name.split(":s")[0]


def _collect_consensus(samples, arms, k: int) -> dict:
    """Group each sample's seeded runs by base arm and reconcile them.

    Reads the persisted result.json rather than holding analyses in memory, so a
    sweep that partially failed still yields consensus over the cells that DID
    complete — which is the common case for long local runs.
    """
    groups: dict[tuple, list] = {}
    for sample in samples:
        for arm in arms:
            if arm.seed is None:
                continue  # unseeded runs are not repeatable; nothing to reconcile
            path = cell_out_dir(sample, arm) / "result.json"
            if not path.exists():
                continue
            try:
                analysis = (json.loads(path.read_text()).get("analysis") or {})
            except (ValueError, OSError):
                continue  # a truncated cell must not take the whole section down
            groups.setdefault((sample.sha256[:12], _base_arm(arm.name)), []).append(analysis)
    # A single seed is not a consensus. Reconciling one run would report every
    # claim as "1/1 agreement", which reads like confirmation and is nothing.
    return {f"{sha} — {base}": consensus(a, k)
            for (sha, base), a in groups.items() if len(a) >= 2}


def main() -> None:
    ap = argparse.ArgumentParser(prog="lamware_eval")
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--arms", required=True)
    ap.add_argument("--label", default="eval")
    ap.add_argument("--samples", default="",
                    help="comma-separated sha256 prefixes or family names; "
                         "default is the whole corpus")
    ap.add_argument("--config", default="/opt/pipeline/config.json")
    ap.add_argument("--interpret-cmd", default="/opt/interpret/run-interpret")
    ap.add_argument("--ghidra-cmd", default="/opt/ghidra/run-ghidra")
    ap.add_argument("--out-dir", default="/opt/pipeline/eval-corpus/results")
    ap.add_argument("--consensus-k", type=int, default=2,
                    help="a claim is 'agreed' when it appears in at least this many "
                         "seeded runs of the same arm (default 2). Only applies to "
                         "seeded arms, e.g. --arms qwen@30:s42,qwen@30:s1337")
    args = ap.parse_args()
    if args.consensus_k < 2:
        ap.error("--consensus-k must be >= 2; k=1 keeps every claim and asserts nothing")

    base_cfg = json.loads(Path(args.config).read_text())["interpret"]
    samples = filter_samples(load_corpus(args.corpus), args.samples)
    arms = parse_arms(args.arms)
    print(f"[eval] {len(samples)} sample(s) x {len(arms)} arm(s) = {len(samples) * len(arms)} cells")
    cells = []
    for s in samples:
        for a in arms:
            try:  # one bad (sample x arm) never kills the run
                cells.append(run_arm(s, a, base_cfg, args.interpret_cmd, args.ghidra_cmd))
            except Exception as e:
                cells.append(_failed_cell(a.name, s, f"{type(e).__name__}: {e}", a.seed))
    md = render_scorecard(args.label, cells, aggregate(cells))
    if any(a.seed is not None for a in arms):
        md += render_consensus(args.label,
                               _collect_consensus(samples, arms, args.consensus_k),
                               args.consensus_k)
    os.makedirs(args.out_dir, exist_ok=True)
    out = Path(args.out_dir) / f"{args.label}.md"
    out.write_text(md)
    print(f"[eval] wrote {out}")
    print(md)


if __name__ == "__main__":
    main()
