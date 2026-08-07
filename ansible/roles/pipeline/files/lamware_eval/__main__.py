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


def consensus_axis_error(arms) -> str | None:
    """Why consensus cannot run over these arms, or None if it can.

    Consensus rests entirely on the runs being INDEPENDENT. Two axes look like
    they supply that and do not, so both are refused here rather than silently
    producing a table that confirms every claim for free (#292).

    This check runs BEFORE the sweep. Discovering it afterwards costs hours of
    local inference and yields a scorecard whose most authoritative-looking
    section is meaningless.
    """
    if len({a.name for a in arms}) < 2:
        return ("--consensus-k needs at least two arms to reconcile; a single arm "
                "run once is one opinion, not agreement.")
    bases = {_base_arm(a.name) for a in arms}
    if len(bases) == 1:
        return (
            "--consensus-k cannot reconcile seed variants of one arm: the seeds are "
            "inert (#292). llama-server honours `seed` on /v1/chat/completions but "
            "ignores it on /v1/messages, and #285 moved the RE transport to "
            "/v1/messages because the OpenAI leg discarded thinking and returned "
            "content: [] on tool-calling turns (#283). Seeded runs of one arm are "
            "byte-identical, so every claim would agree with itself and k=2 would "
            "do exactly what k=1 is rejected for. Re-run without --consensus-k.")
    models = {a.model for a in arms}
    if len(models) < 2:
        return (
            "--consensus-k cannot reconcile arms that differ only by depth. Runs are "
            "deterministic (#292), so qwen@10's trajectory is a literal PREFIX of "
            "qwen@15's on the same sample: agreement on anything found in the first "
            "10 calls is guaranteed by construction, not evidence. Cross-MODEL "
            "consensus is the real axis and is #310; it is not implemented yet.")
    # Distinct models IS the valid axis — but _collect_consensus still groups by
    # seed, so it would return nothing and render an empty section. Refusing beats
    # a silent no-op: the request is sound, the implementation is not here yet.
    return (
        "--consensus-k over distinct models is the right idea and is not implemented "
        "yet (#310). _collect_consensus still groups by seed, so this would silently "
        "reconcile nothing and print an empty section rather than failing. Re-run "
        "without --consensus-k until #310 lands.")


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


def build_parser() -> argparse.ArgumentParser:
    """Split out so a test can assert --consensus-k's default is a VALUE.

    The alternative is grepping this file for `default=0` near the flag name,
    which passes on a comment mentioning the default and cannot see argparse's
    actual behaviour.
    """
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
    # OFF by default (#292). It used to default to 2 and auto-render for any seeded
    # arm, so every sweep printed a consensus section that confirmed 100% of claims
    # because the runs behind it were identical. Off-by-default means the scorecard
    # asserts nothing it cannot support, and asking for it fails loudly below.
    ap.add_argument("--consensus-k", type=int, default=0,
                    help="0 (default) disables consensus. >=2 reconciles claims across "
                         "INDEPENDENT runs of a sample. No independent axis exists "
                         "today — seeds are inert (#292) and depth arms share a "
                         "deterministic prefix — so any value >=2 is currently "
                         "rejected with an explanation. See #310.")
    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    if args.consensus_k == 1:
        ap.error("--consensus-k must be >= 2; k=1 keeps every claim and asserts nothing")
    if args.consensus_k < 0:
        ap.error("--consensus-k cannot be negative; use 0 to disable")

    # Resolved before the config and corpus are even read, so an unusable consensus
    # request costs a syntax error rather than a sweep.
    arms = parse_arms(args.arms)
    if args.consensus_k >= 2:
        err = consensus_axis_error(arms)
        if err:
            ap.error(err)

    base_cfg = json.loads(Path(args.config).read_text())["interpret"]
    samples = filter_samples(load_corpus(args.corpus), args.samples)
    print(f"[eval] {len(samples)} sample(s) x {len(arms)} arm(s) = {len(samples) * len(arms)} cells")
    cells = []
    for s in samples:
        for a in arms:
            try:  # one bad (sample x arm) never kills the run
                cells.append(run_arm(s, a, base_cfg, args.interpret_cmd, args.ghidra_cmd))
            except Exception as e:
                cells.append(_failed_cell(a.name, s, f"{type(e).__name__}: {e}", a.seed))
    md = render_scorecard(args.label, cells, aggregate(cells))
    # Explicit request only. This used to trigger on `any(a.seed is not None)`, so a
    # seeded arm silently added a section nobody asked for — and that section was the
    # one reporting 100% agreement over identical runs (#292).
    if args.consensus_k >= 2:
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
