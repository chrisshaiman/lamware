# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Run one (sample x arm) through the agentic RE loop; return a scorecard cell."""
import json
import re
import shutil
import time
from pathlib import Path

import requests
from llm_ab_re import extract_metrics
from stages.interpret import run_interpret

from lamware_eval.arms import Arm
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import cell_error, compose_cell, ghidra_warnings_for

# Harness backstop. MUST stay ABOVE the interpret container's own --timeout
# (10800s) so the container is the thing that reaps a stuck run and we get a
# clean "exited without final result" cell instead of an opaque subprocess kill.
# Guarded by test_eval_timeout_ordering.
_EVAL_TIMEOUT = 12600

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


# The llama.cpp server's own view of its sampler. Recorded per cell so a result
# carries the config it was produced under, rather than depending on someone
# remembering what the server was running that week.
_LLAMACPP_PROPS_URL = "http://127.0.0.1:11435/props"
_SAMPLING_KEYS = ("temperature", "top_p", "top_k", "min_p", "presence_penalty",
                  "repeat_penalty", "frequency_penalty")


def _server_sampling() -> dict:
    """Read the sampling profile llama-server ACTUALLY applied.

    Deliberately not the values we intended: a flag that never reached the sampler
    is exactly the bug this is here to catch (cf. the #218 timeout, which was
    present in the file and absent from the socket).

    NB: the server's `seed` is its startup default, NOT the seed a given request
    used — per-request seeds arrive via the LiteLLM alias and never appear here.
    The requested seed is recorded separately from the arm. Reporting /props'
    seed would silently claim every run used 42.

    Fails soft: provenance is worth recording, never worth killing a run over.
    """
    try:
        resp = requests.get(_LLAMACPP_PROPS_URL, timeout=10)
        resp.raise_for_status()
        params = resp.json()["default_generation_settings"]["params"]
    except (requests.RequestException, KeyError, ValueError) as e:
        return {"error": f"{type(e).__name__}: {e}"}
    # Round the float32 round-trip noise (0.95 -> 0.949999988079071) so the
    # recorded profile is comparable to the profile as written down.
    return {k: (round(v, 6) if isinstance(v, float) else v)
            for k, v in params.items() if k in _SAMPLING_KEYS}


def cell_out_dir(sample: CorpusSample, arm: Arm) -> Path:
    """Where one (sample x arm) cell's artifacts live.

    Shared with the consensus reader rather than re-derived there: a second copy
    of this path expression would silently stop finding results the moment either
    copy changed, and the symptom would be "no consensus data", not an error.
    """
    return Path(sample.corpus_dir) / "eval" / cell_dir_name(arm.name)


def cell_dir_name(arm_name: str) -> str:
    """Directory-safe form of an arm name."""
    return arm_name.replace("/", "_").replace("@", "_").replace(":", "_")


def arm_name_from_cell_dir(dirname: str) -> str | None:
    """The arm a persisted cell directory belongs to, or None.

    An exact reverse lookup rather than a `endswith("+corr")` guess. The offline
    re-scorer needs to know an arm's EVIDENCE MODE to score it the way the sweep
    did, and inferring that from a directory name would be the same class of
    proxy check that #490 turned on.
    """
    from lamware_eval.arms import registered_arms
    for name in registered_arms():
        if cell_dir_name(name) == dirname:
            return name
    return None


# Cells whose name starts with this are bookkeeping, not results. Readers that walk
# `<corpus>/eval/*` must skip it or they will treat archived runs as live arms.
ARCHIVE_DIR = "_archive"


def archive_previous_cell(out: Path) -> Path | None:
    """Move a previous run's artifacts aside before this run writes anything.

    Cell paths are keyed only by (sample, arm), so re-running an arm lands on top of the
    last run. `result.json` and the trail were overwritten, but `llm_audit/results/NNNN.json`
    is numbered PER TOOL CALL and never cleared, so a shorter second run left the first
    run's higher-numbered files in place — and `tool_output_text` greps exactly those files
    to decide whether a claim is grounded. A claim could therefore be scored against
    evidence from a DIFFERENT run, with nothing anywhere saying so.

    Observed 2026-07-29: a re-run of qwen@10:s42 destroyed the previous run's forensic
    trail (#197) while a question about that run was still open, making it permanently
    unanswerable. It survives SIGKILL and did not survive a re-run, which is the far more
    common event.

    Moving rather than deleting keeps the history the trail exists for. The archive is
    named for the PREVIOUS run's own timestamp rather than the current label, so it is
    self-describing without threading the label through the runner.
    """
    if not out.exists() or not any(out.iterdir()):
        return None
    stamped = out / "result.json"
    when = stamped.stat().st_mtime if stamped.exists() else out.stat().st_mtime
    dest = out.parent / ARCHIVE_DIR / f"{out.name}__{time.strftime('%Y%m%d-%H%M%S', time.localtime(when))}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        # Same-second re-run of the same cell; the newer copy wins.
        shutil.rmtree(dest)
    out.rename(dest)
    return dest


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


#: A MITRE technique ID, with or without a sub-technique.
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def held_out_techniques(report: dict) -> list[str]:
    """CAPE's MITRE observations, which NO arm is shown (#491).

    These are the answer key. Cape derives them from behaviour it watched during
    detonation, independently of anything Ghidra saw, which is what makes them
    usable as ground truth (#314) — and holding them out is what makes a
    technique claim something an arm has to earn rather than repeat.

    Before this, `+corr` was handed `T1059 — Execution` and `T1055 — Process
    Injection` on the correlations and then scored on nothing at all, because
    `attack_techniques` was unscored entirely. On the pilot it claimed both.
    """
    ttps = (report.get("cape") or {}).get("mitre_ttps") or []
    return sorted({t.get("id") for t in ttps
                   if isinstance(t, dict) and t.get("id")})


def strip_technique_ids(obj):
    """Remove every MITRE ID from an evidence payload. Returns (obj, removed).

    The `mitre` field on a correlation is dropped outright; the finding's title
    and detail carry its meaning without naming the answer. Any ID surviving
    elsewhere is REDACTED rather than left, and counted rather than hidden — a
    non-zero count on a sample means something leaks the answer key by another
    route, which is a bug to find, not a number to bury.
    """
    removed = 0
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "mitre":
                removed += len(_TECHNIQUE_ID.findall(str(v)))
                continue
            sub, n = strip_technique_ids(v)
            out[k] = sub
            removed += n
        return out, removed
    if isinstance(obj, list):
        pairs = [strip_technique_ids(v) for v in obj]
        return [p[0] for p in pairs], sum(p[1] for p in pairs)
    if isinstance(obj, str):
        redacted, n = _TECHNIQUE_ID.subn("[held out]", obj)
        return redacted, n
    return obj, removed


def correlated_evidence(report: dict) -> dict:
    """The evidence an arm with evidence="correlated" is additionally shown (#420).

    Deliberately narrow. Everything here is already computed by the pipeline and
    already shown to the SUMMARY writer; the only change is that the investigating
    agent sees it too. Nothing is derived specially for the eval, so a positive
    result is actionable — it says move cross_correlate ahead of stage 4.5 in
    production, not "build something new".

    Returns {} when the report carries none of it, which keeps `+corr` byte-identical
    to its base arm on those samples. That is a feature: such samples become a
    negative control showing the two arms agree when the evidence is the same.
    """
    out: dict = {}
    cc = report.get("cross_correlations") or []
    if cc:
        out["cross_correlations"] = cc
    warn = report.get("correlation_warnings") or []
    if warn:
        # Shown deliberately. A rule that could not run is evidence about coverage,
        # and withholding it would let the agent read an empty finding list as a
        # clean sample — the substitution the warnings exist to prevent.
        out["correlation_warnings"] = warn
    cape = report.get("cape") or {}
    sigs = cape.get("signatures") or []
    if sigs:
        out["cape_signatures"] = sigs
    vol = (report.get("volatility") or {}).get("insights")
    if vol:
        out["volatility_insights"] = vol
    # The MITRE IDs come out before the agent sees any of this. They are the
    # answer key both arms are scored against (#491), and an arm shown the key
    # is not being measured on the same thing as one that is not.
    out, _ = strip_technique_ids(out)
    return out


def evidence_for(arm: Arm, report: dict) -> dict:
    """What THIS arm is shown beyond the Ghidra dump.

    A separate function because the failure it guards is silent: if a
    "correlated" arm receives nothing, both arms get identical prompts and the
    experiment reports "no difference" while having tested nothing. That is
    indistinguishable from a real null result in the output, so it has to be
    unit-testable rather than buried in run_arm.
    """
    if arm.evidence != "correlated":
        return {}
    return correlated_evidence(report)


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
    out = cell_out_dir(sample, arm)
    # Start from an empty cell: see archive_previous_cell for why overwriting is not
    # enough. Stale per-tool-call artifacts would otherwise be scored as this run's
    # evidence.
    archived = archive_previous_cell(out)
    if archived is not None:
        print(f"    [eval] previous cell archived -> {archived}", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    evidence = evidence_for(arm, report)
    if arm.evidence == "correlated":
        print(f"    [eval] correlated evidence: {sorted(evidence) or 'NONE (identical to base arm)'}",
              flush=True)
    t0 = time.time()
    res = run_interpret(gr, out, interpret_cmd, True, _EVAL_TIMEOUT, cfg, ghidra_cmd,
                        extra_evidence=evidence or None)
    secs = round(time.time() - t0, 1)
    analysis = res.get("analysis", {}) or {}
    usage = res.get("usage", {}) or {}
    cost = 0.0 if arm.re_backend == "local" else _rough_cost(arm.model, usage)
    # Grounding corpus = the initial Ghidra dump PLUS everything the tools
    # returned, i.e. the full set of bytes the model actually saw.
    #
    # The evidence is passed SEPARATELY, not concatenated here, so the scorecard
    # can tell the two apart (#491).
    #
    # It has to be part of the grounding corpus: omitting it would score claims
    # the agent drew from correlation findings as FABRICATED, penalising the arm
    # for using exactly what the experiment gave it. But folding it in silently
    # made `grounded` unreadable in the other direction — a claim copied out of
    # the prompt scored identically to one derived from decompiled code.
    #
    # This comment used to say "compare ABSOLUTE grounded findings, never the
    # ratio". That advice was wrong: the absolute count inflates the same way.
    # The #420 pilot on 25d18a2b made it unmissable — with the tool layer dead,
    # `+corr` scored 7 grounded / 0 fabricated by restating its own evidence
    # while the base arm, able to read nothing, honestly said nothing.
    #
    # `grounded_novel` is the comparable figure: grounded in the Ghidra dump and
    # tool output, WITHOUT the evidence. `grounded_recited` is the difference.
    source = json.dumps(gr) + " " + tool_output_text(out)

    # Persist the full interpret result. Family-ID is analyst-ADJUDICATED, which
    # is impossible after the fact if only the scorecard's one-word guess
    # survives — the narrative, capabilities and IOC list are what an analyst
    # actually reads to decide "right family / right class / wrong".
    (out / "result.json").write_text(json.dumps(res, indent=2, default=str))

    # Append the container's own stderr to the cell error. Without it a crashed
    # container reports only "exited without final result", which is a symptom, not a
    # cause — and costs a full re-run (26 min on 2026-07-27) to learn anything.
    err = cell_error(res, analysis)

    return compose_cell(arm.name, sample, analysis, source, claude_family, secs, cost,
                        extract_metrics(res), err, evidence=evidence,
                        seed=arm.seed,
                        sampling=_server_sampling() if arm.re_backend == "local" else None,
                        ghidra_warnings=ghidra_warnings_for(gr),
                        cape_techniques=held_out_techniques(report))
