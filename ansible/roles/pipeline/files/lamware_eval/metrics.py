# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Per-cell metric composition + per-arm aggregation for the eval scorecard."""
import json
from collections import defaultdict

from grounding_check import grounding_scorecard
from stages.ghidra import collect_analysis_warnings

from lamware_eval.corpus import CorpusSample


def cell_error(res: dict, analysis: dict) -> str | None:
    """The reason a cell failed, composed identically for live and re-scored runs.

    Shared because the two paths disagreed. The live sweep built this from the
    run's actual error and appended the container's stderr tail; the offline
    re-scorer passed `analysis["parse_note"]` instead — a different field
    entirely. So a re-score of a cell that died on a container OOM reported
    "recovered JSON from a markdown fence", and one that timed out with no parse
    note reported nothing at all, blanking the failure column in the scorecard.

    `parse_note` is already carried as the `parse_failed` metric, so passing it
    here also double-reported it in the wrong place.

    Same principle as the tool metrics in #380: a re-score must not disagree with
    the sweep that produced the cell.
    """
    err = res.get("error") or analysis.get("error")
    stderr_tail = (res.get("container_stderr") or "").strip()
    if err and stderr_tail:
        err = f"{err} | container stderr: {stderr_tail[-1500:]}"
    return err


def technique_hits(claimed: list[str], available: list[str]) -> list[str]:
    """Claimed technique IDs that Cape independently observed (#491).

    A sub-technique counts against its parent — claiming `T1055.003` when Cape
    saw `T1055` is a more specific version of the same finding, and penalising
    precision is not the point.

    The reverse deliberately does NOT count. Claiming `T1055` when Cape saw only
    `T1055.003` is a LESS specific claim, and crediting it would make the metric
    generous in both directions, which is another way of saying unfalsifiable.
    """
    have = set(available or [])
    return [t for t in (claimed or [])
            if t in have or t.split(".")[0] in have]


def ghidra_warnings_for(gr: dict) -> list[str]:
    """The analysis warnings for a cell, resolved identically live and offline.

    Top-level list when the report has one, otherwise derived from the per-file
    records. Reports written before #367 carry warnings only on each analysed
    file, and the eval NEVER analyses a sample — it runs against persisted
    corpus reports, which are precisely those older ones. So the fallback is not
    an offline nicety; it is the normal case.

    It lived only in `rebuild.py`, so a live run reported 0 where a re-score of
    the same cell reported 2 — on `unclassified_42b9c406`, two analysed files
    that recovered zero functions each (#496). `cells_with_ghidra_warnings`
    exists so a cell built on an analysis that read nothing is not mistaken for
    a cell where the model had nothing to say, and on the live path it read zero
    for every corpus sample.

    Shared for the same reason `cell_error` below is: a re-score must not
    disagree with the sweep that produced the cell (#380).
    """
    top = gr.get("analysis_warnings")
    if top:
        return list(top)
    return collect_analysis_warnings(gr.get("analyzed_files") or [],
                                     derive_when_absent=True)


def compose_cell(arm_name: str, sample: CorpusSample, analysis: dict, source_text: str,
                 claude_family: str | None, wall_seconds: float, cost_usd: float,
                 tool_metrics: dict, error: str | None,
                 seed: int | None = None, sampling: dict | None = None,
                 ghidra_warnings: list[str] | None = None,
                 evidence: dict | None = None,
                 cape_techniques: list[str] | None = None,
                 modality: str = "native_pe") -> dict:
    """Compose one scorecard cell.

    `seed` is the seed REQUESTED for this cell (None = unpinned, so the run is not
    reproducible). `sampling` is what the inference server reported it actually
    applied. Both are recorded per cell rather than once per sweep because the
    server can be restarted mid-sweep, and a result whose sampling config is only
    known by recollection is not a result anyone can reproduce.

    `ghidra_warnings` are the ways the static analysis contradicted its input —
    a PE whose import directory is intact yielding zero imports, one function
    recovered from a 150KB binary (#367). A cell built on an analysis that read
    nothing is not a cell where the model had nothing to say, and without this
    the two are identical in the scorecard.

    `source_text` is the Ghidra dump and tool output. `evidence` is what an
    evidence-fed arm was ADDITIONALLY shown, passed as the dict rather than as
    pre-serialised text so the SIZE recorded on the cell and the text appended
    to the grounding corpus cannot drift apart (#502). Grounding is computed
    twice:

      grounded          against source + evidence — what the model could support
      grounded_novel    against source ALONE — what it got from the CODE
      grounded_recited  the difference — claims that only its prompt supports

    Without the split, restating the prompt scored identically to reading the
    binary. On the #420 pilot with a dead tool layer, the evidence-fed arm
    reported 7 grounded / 0 fabricated claims having read nothing at all, and no
    column in the scorecard could say so (#491).
    """
    evidence_text = json.dumps(evidence) if evidence else None
    g = grounding_scorecard(analysis or {}, source_text + " " + (evidence_text or ""))
    # Same claims, smaller corpus. Skipped entirely when there is no evidence,
    # where the two are identical by construction.
    g_novel = (grounding_scorecard(analysis or {}, source_text)
               if evidence_text else g)
    techniques = (analysis or {}).get("attack_techniques") or []
    capabilities = (analysis or {}).get("capabilities") or []
    claimed_ids = sorted({t.get("id") for t in techniques
                          if isinstance(t, dict) and t.get("id")})
    hits = technique_hits(claimed_ids, cape_techniques or [])
    return {
        "arm": arm_name,
        "seed": seed,
        "sampling": sampling,
        "sample": sample.sha256[:12],
        # NOT a capability metric for this stage — see ADR-019. Measured: qwen 0/14
        # and the Claude reference 0/7 on the same samples, against labels that
        # disagree with the reference on every one of them. The MOTIF paper puts
        # AVClass at 46.78% and AV majority voting at 62.10%, so the label itself is
        # under 50% reliable.
        #
        # Scope the claim: supervised byte-level classifiers DO reach ~91% on packed
        # samples. What cannot work is an LLM reading DECOMPILED code over an open set
        # of 454+ families — a packer stub is generic as source while staying
        # distinctive as bytes.
        #
        # Read it as a CONTAMINATION PROBE. Near-zero is correct. An unexpectedly high
        # score is evidence of memorised published analyses rather than analysis of the
        # code, because analysis cannot get there from a packer stub.
        #
        # Do not tune prompts against this column.
        "family_guess": (analysis or {}).get("malware_family_guess"),
        "mb_family": sample.mb_family,
        "claude_family": claude_family,
        "grounded": g["grounded"], "total": g["total"],
        "fabricated": g["fabricated"], "grounded_ratio": g["grounded_ratio"],
        # The comparable figure across the evidence axis (#491).
        "grounded_novel": g_novel["grounded"],
        "grounded_recited": g["grounded"] - g_novel["grounded"],
        # Both are computed by grounding_scorecard and neither was ever shown.
        # A cell citing two Ghidra auto-generated DAT_ labels scored 1.00 and
        # outranked one citing three concrete addresses at 0.75.
        "bare_symbols": len(g.get("bare_symbol_claims") or []),
        "unscoreable": len(g.get("unscoreable") or []),
        # NOT scored by grounding_scorecard, which reads code_level_ioc only.
        # Counted so an unscored field cannot quietly double while the scored
        # one holds still — which is what the pilot's +corr arm did, 3 -> 6.
        "techniques": len(techniques),
        "capabilities": len(capabilities),
        # Scored against Cape's MITRE observations, which no arm is shown
        # (#491). Precision is the trustworthy half: Cape's list is broad and
        # itself noisy, so a low recall says as much about the answer key as
        # about the model, while a claim that Cape never observed is a claim
        # nothing supports.
        # How much treatment this cell actually received (#502). Zero on a base
        # arm, which puts the pairing on the row itself. Without it two cells in
        # one table can differ by more than an order of magnitude — measured
        # across the stage-2 corpus, four samples got 26-30KB and latrodectus
        # got 1.4KB — and the reader cannot tell, so "did correlation help or
        # did more text help" is unanswerable from the output.
        # Which analyser produced what the agent read. Native PE and .NET are
        # two experiments and are never pooled (#505); this is on the row so a
        # scorecard that somehow mixed them would say so out loud.
        "modality": modality,
        "evidence_bytes": len(evidence_text or ""),
        "evidence_keys": len(evidence or {}),
        # Separate from total volume because THIS is the variable the thesis is
        # about. Cape signatures and Volatility insights ride along with it.
        "correlations_shown": len((evidence or {}).get("cross_correlations") or []),
        "techniques_hit": len(hits),
        "technique_precision": (round(len(hits) / len(claimed_ids), 3)
                                if claimed_ids else None),
        "technique_recall": (round(len(hits) / len(cape_techniques), 3)
                             if cape_techniques else None),
        "cape_techniques": len(cape_techniques or []),
        "completed": tool_metrics.get("completed"),
        # Reported separately because "finished, but the answer was unparseable"
        # is neither success nor error, and folding it into either hides it.
        "parse_failed": bool(tool_metrics.get("parse_failed")),
        "tool_calls_used": tool_metrics.get("tool_calls_used"),
        "tool_call_error_rate": tool_metrics.get("tool_call_error_rate"),
        "tool_call_errors": tool_metrics.get("tool_call_errors"),
        # The tool layer was dead for this cell, so it measured infrastructure,
        # not the model. Kept out of the arm aggregates below rather than
        # scored as an ordinary zero-claim result (#316).
        "tool_layer_broken": bool(tool_metrics.get("tool_layer_broken")),
        # Count in the table, full text in the cell dict — a scorecard column
        # has to stay skimmable, but the reason must survive for whoever asks.
        "ghidra_warnings": len(ghidra_warnings or []),
        "ghidra_warning_detail": list(ghidra_warnings or []),
        "wall_seconds": wall_seconds, "cost_usd": cost_usd,
        "error": error,
    }


def _mean(values: list) -> float | None:
    """None over an empty set rather than 0.0: a rate computed over nothing is
    not a score of zero, and the two must not render alike."""
    return round(sum(values) / len(values), 3) if values else None


def aggregate(cells: list[dict]) -> dict:
    """Summarise cells per arm.

    Grounding is reported as a PAIR: the ratio, plus how many claims it was
    computed over. A cell that claims no IOCs scores a vacuous grounded_ratio of
    1.0 ("nothing claimed = nothing to fake"), so averaging every cell would
    rank a silent model above one making checkable claims — observed live on
    2026-07-25, where qwen@10 emitted 0 IOCs on IcedID and scored a 'perfect'
    1.0 against an Opus 4.6 baseline that made 15 real claims. mean_grounded_ratio
    therefore covers only cells with claims, and is None when there are none.

    Cells whose tool layer was broken are excluded from every capability figure
    and counted separately (#316). Such a cell never measured the model: on
    2026-07-25 latrodectus/qwen@10 had 8 of 8 tool calls fail and still
    contributed a 0/0 to both arms of a depth A/B, as though depth had been
    fairly tested on it. `n` is what was attempted, `n_valid` what could be
    measured, and `n_valid` is the denominator for the rates below.
    """
    by_arm: dict[str, list[dict]] = defaultdict(list)
    for c in cells:
        by_arm[c["arm"]].append(c)
    out = {}
    for arm, cs in by_arm.items():
        n = len(cs)
        broken = [c for c in cs if c.get("tool_layer_broken")]
        valid = [c for c in cs if not c.get("tool_layer_broken")]
        n_valid = len(valid)
        scored = [c for c in valid if (c.get("total") or 0) > 0]
        out[arm] = {
            "n": n,
            "n_valid": n_valid,
            "tool_layer_broken": len(broken),
            "n_with_claims": len(scored),
            "total_claims": sum(c.get("total") or 0 for c in valid),
            "mean_grounded_ratio": (
                round(sum(c["grounded_ratio"] for c in scored) / len(scored), 3)
                if scored else None
            ),
            "total_fabricated": sum(len(c["fabricated"]) for c in valid),
            # Compare THESE across the evidence axis. total_grounded includes
            # claims an arm could only have got from its own prompt (#491).
            "total_grounded_novel": sum(c.get("grounded_novel") or 0 for c in valid),
            "total_grounded_recited": sum(c.get("grounded_recited") or 0 for c in valid),
            "total_bare_symbols": sum(c.get("bare_symbols") or 0 for c in valid),
            "total_unscoreable": sum(c.get("unscoreable") or 0 for c in valid),
            # Unscored by grounding, so shown rather than trusted.
            "total_techniques": sum(c.get("techniques") or 0 for c in valid),
            "total_evidence_bytes": sum(c.get("evidence_bytes") or 0 for c in valid),
            "total_correlations_shown": sum(c.get("correlations_shown") or 0
                                            for c in valid),
            "total_techniques_hit": sum(c.get("techniques_hit") or 0 for c in valid),
            "mean_technique_precision": _mean(
                [c["technique_precision"] for c in valid
                 if c.get("technique_precision") is not None]),
            "mean_technique_recall": _mean(
                [c["technique_recall"] for c in valid
                 if c.get("technique_recall") is not None]),
            "completed_rate": (
                round(sum(1 for c in valid if c["completed"]) / n_valid, 3)
                if n_valid else None
            ),
            "parse_failures": sum(1 for c in valid if c.get("parse_failed")),
            # Over ALL cells: a broken tool layer does not make the static
            # analysis behind it any less broken, and both are worth knowing.
            "cells_with_ghidra_warnings": sum(1 for c in cs if c.get("ghidra_warnings")),
            # Wall and cost cover EVERY cell, broken included: a cell that burned
            # an hour failing still cost an hour.
            "mean_wall_seconds": round(sum(c["wall_seconds"] for c in cs) / n, 1),
            "total_cost_usd": round(sum(c["cost_usd"] for c in cs), 4),
        }
    return out
