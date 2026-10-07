# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CLI: python -m lamware_eval run --corpus <path> --arms <csv> --label <name> [--variants K]"""
import argparse
import json
import os
from pathlib import Path

from lamware_eval.arms import parse_arms
from lamware_eval.consensus import consensus, render_consensus
from lamware_eval.corpus import filter_samples, load_corpus
from lamware_eval.metrics import aggregate
from lamware_eval.provenance import gather as gather_provenance
from lamware_eval.runner import (
    VariantNotApplicable,
    cell_dir_name,
    cell_out_dir,
    eligible_for_variants,
    run_arm,
)
from lamware_eval.scorecard import render_scorecard, write_scorecard
from lamware_eval.stats import render_variant_stats
from lamware_eval.variants import VARIANT_MODALITIES, split_variant_dir


def _failed_cell(arm_name: str, sample, err: str, seed: int | None = None,
                 variant: int | None = None) -> dict:
    cell = {"arm": arm_name, "seed": seed, "sampling": None,
            "sample": sample.sha256[:12], "family_guess": None,
            "mb_family": sample.mb_family, "claude_family": None, "grounded": 0,
            "total": 0, "fabricated": [], "grounded_ratio": 1.0, "completed": False,
            # An arm that errored before running made no tool calls, so its tool
            # layer is unknown rather than broken — it must not be filtered out
            # of the aggregates as though infrastructure were the cause.
            "tool_calls_used": 0, "tool_call_error_rate": 0.0,
            "tool_call_errors": 0, "tool_layer_broken": False, "wall_seconds": 0.0,
            "cost_usd": 0.0, "error": err}
    if variant is not None:
        # So the statistics count it as this variant's (invalid) draw, not v0's.
        cell["input_detail"] = {"variant": variant}
    return cell


def variants_blocked(v0_cell: dict) -> str | None:
    """Why a (sample x arm)'s order-variants are not run, judged from its v0 cell.

    From the modality v0 ACTUALLY read rather than a prediction: whether a
    routed sample reads an unpacked payload or the C# depends on the Ghidra
    verifier, which only the sweep runs.
    """
    modality = v0_cell.get("modality")
    if modality in VARIANT_MODALITIES:
        return None
    if modality is None:
        return f"v0 failed before reading its input ({str(v0_cell.get('error'))[:160]})"
    return f"{modality}: no order-variants for .NET inputs in this change (v0 only)"


def _prior_wall_seconds(samples, arms) -> list[float]:
    """`duration_seconds` of every persisted cell of these samples x arms, any variant."""
    names = {cell_dir_name(a.name) for a in arms}
    out = []
    for s in samples:
        root = Path(s.corpus_dir) / "eval"
        if not root.is_dir():
            continue
        for d in root.iterdir():
            if split_variant_dir(d.name)[0] not in names or not (d / "result.json").is_file():
                continue
            try:
                secs = json.loads((d / "result.json").read_text()).get("duration_seconds")
            except (ValueError, OSError):
                continue
            if isinstance(secs, (int, float)) and secs > 0:
                out.append(float(secs))
    return out


def cost_line(samples, arms, variants: int) -> str:
    """What this sweep will run, said before it runs (#715).

    cells = samples x arms x (K+1) for samples whose input order-variants apply
    to, x 1 for the rest; a range when that depends on the Ghidra verifier. The
    time estimate is the mean `duration_seconds` of cells already on disk.
    """
    lo = hi = 0
    for s in samples:
        try:
            report = json.loads((Path(s.corpus_dir) / "report.json").read_text())
            ok = eligible_for_variants(report)
        except (ValueError, OSError):
            ok = None  # the sweep will fail this sample's cells; count it both ways
        lo += len(arms) * (1 + (variants if ok else 0))
        hi += len(arms) * (1 + (variants if ok is not False else 0))
    cells = str(lo) if lo == hi else f"{lo}..{hi}"
    line = (f"[eval] {len(samples)} sample(s) x {len(arms)} arm(s) x (1 + {variants} "
            f"order-variant(s) where the input is {'/'.join(VARIANT_MODALITIES)}) "
            f"= {cells} cells")
    prior = _prior_wall_seconds(samples, arms)
    if prior:
        mean = sum(prior) / len(prior)
        line += (f"; ~{lo * mean / 3600:.1f}"
                 + ("" if lo == hi else f"..{hi * mean / 3600:.1f}")
                 + f" h at the {mean:.0f}s mean of {len(prior)} prior cell(s)")
    return line


def sweep_variants(samples, arms, base_cfg: dict, interpret_cmd: str, ghidra_cmd: str,
                   variants: int, run=None) -> list[dict]:
    """Every sample x variant x arm, variant-major within a sample.

    Arms are interleaved inside each variant so an interrupted sweep leaves
    complete PAIRS (same sample, same k, every arm) rather than one arm's
    variants with nothing to pair them with. v0 of every arm runs first; an
    arm whose v0 read a .NET input, or failed before reading anything, runs no
    variants, and the reason is printed rather than becoming K failed cells.
    `run` is `run_arm`, injectable for tests.
    """
    run = run or run_arm
    cells: list[dict] = []
    for s in samples:
        blocked: dict[str, str] = {}
        for k in range(variants + 1):
            for a in arms:
                if a.name in blocked:
                    continue
                try:  # one bad cell never kills the run
                    cell = run(s, a, base_cfg, interpret_cmd, ghidra_cmd, variant=k)
                except VariantNotApplicable as e:
                    blocked[a.name] = str(e)
                    print(f"    [eval] {s.sha256[:12]} {a.name}: variants not run: {e}",
                          flush=True)
                    continue
                except Exception as e:
                    cell = _failed_cell(a.name, s, f"{type(e).__name__}: {e}", a.seed,
                                        variant=k)
                cells.append(cell)
                if k == 0 and (why := variants_blocked(cell)):
                    blocked[a.name] = why
                    print(f"    [eval] {s.sha256[:12]} {a.name}: variants not run: {why}",
                          flush=True)
    return cells


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
    ap.add_argument("--force", action="store_true",
                    help="replace an existing scorecard of the same label")
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
    # OFF by default: 0 runs and records exactly what a run did before #715.
    ap.add_argument("--variants", type=int, default=0,
                    help="K >= 1 also runs K deterministic reorderings of each "
                         "native/unpacked-payload sample's shown imports and strings "
                         "(cells in eval/<arm>__v<k>/) and adds distribution and "
                         "paired-comparison sections. .NET inputs run v0 only.")
    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    if args.consensus_k == 1:
        ap.error("--consensus-k must be >= 2; k=1 keeps every claim and asserts nothing")
    if args.consensus_k < 0:
        ap.error("--consensus-k cannot be negative; use 0 to disable")
    if args.variants < 0:
        ap.error("--variants cannot be negative; use 0 to disable")

    # Resolved before the config and corpus are even read, so an unusable consensus
    # request costs a syntax error rather than a sweep.
    arms = parse_arms(args.arms)
    if args.consensus_k >= 2:
        err = consensus_axis_error(arms)
        if err:
            ap.error(err)

    base_cfg = json.loads(Path(args.config).read_text())["interpret"]
    samples = filter_samples(load_corpus(args.corpus), args.samples)
    if args.variants:
        print(cost_line(samples, arms, args.variants))
        cells = sweep_variants(samples, arms, base_cfg, args.interpret_cmd,
                               args.ghidra_cmd, args.variants)
    else:
        print(f"[eval] {len(samples)} sample(s) x {len(arms)} arm(s) = {len(samples) * len(arms)} cells")
        cells = []
        for s in samples:
            for a in arms:
                try:  # one bad (sample x arm) never kills the run
                    cells.append(run_arm(s, a, base_cfg, args.interpret_cmd, args.ghidra_cmd))
                except Exception as e:
                    cells.append(_failed_cell(a.name, s, f"{type(e).__name__}: {e}", a.seed))
    provenance = gather_provenance(args.corpus, [c["sample"] for c in cells])
    md = render_scorecard(args.label, cells, aggregate(cells), provenance)
    # "" without variants: --variants 0 renders the scorecard it always did.
    md += render_variant_stats(cells)
    # Explicit request only. This used to trigger on `any(a.seed is not None)`, so a
    # seeded arm silently added a section nobody asked for — and that section was the
    # one reporting 100% agreement over identical runs (#292).
    if args.consensus_k >= 2:
        md += render_consensus(args.label,
                               _collect_consensus(samples, arms, args.consensus_k),
                               args.consensus_k)
    os.makedirs(args.out_dir, exist_ok=True)
    out = Path(args.out_dir) / f"{args.label}.md"
    write_scorecard(out, md, args.force)
    print(f"[eval] wrote {out}")
    print(md)


if __name__ == "__main__":
    main()
