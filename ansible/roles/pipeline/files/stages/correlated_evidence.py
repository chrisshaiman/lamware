# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The behavioural evidence the investigating RE agent is shown (#420, #630, #674).

One builder, imported by both production (run-pipeline.py, Stage 4.5) and the
eval (lamware_eval.runner, the `+corr` arms). It lived in lamware_eval until
#674; production never called it, so the agent doing the investigation never
saw what #630 measured as the largest gain: on the 2026-10-03 re-measure,
`+corr` turned empty answers into grounded claims in both server sessions
(cells with claims 4/6 -> 6/6) with zero fabrications.

It is a single module rather than a copy in each caller because two copies of
the same rule drift (#380): the eval would then be measuring an input
production no longer sends.

What the agent is shown is CAPE's signatures, Volatility's insights, the
cross-tool correlation findings and the warnings naming the correlation rules
that could not run. MITRE technique IDs are removed first, in production too:
they are the eval's answer key (#491), and production shows the agent exactly
what was measured, nothing more. CAPE signature NAMES can carry a family label
(#670); in production that is legitimate evidence, and it is not stripped.
"""
from __future__ import annotations

import json
import re

#: A MITRE technique ID, with or without a sub-technique.
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


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
    """The evidence the investigating agent is additionally shown (#420).

    Deliberately narrow. Everything here is already computed by the pipeline and
    already shown to the SUMMARY writer; the only change is that the investigating
    agent sees it too. Nothing is derived specially for the eval, so a positive
    eval result is directly a statement about production.

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


# Why the agent was NOT given the evidence, as recorded in
# llm_interpretation.input.correlated_evidence.reason. Distinct values, because
# "not given" for each of these means something different about the run.
NOT_GIVEN_DISABLED = "disabled_by_config"      # interpret_correlated_evidence: false
NOT_GIVEN_SINGLE_SHOT = "single_shot_path"     # the container's single-shot paths never read it
NOT_GIVEN_NONE_IN_REPORT = "report_has_none"   # no signatures, insights, findings or warnings


def evidence_record(evidence: dict | None, reason: str | None = None) -> dict:
    """What the agent was given, small enough to keep in every report.

    ``bytes`` is ``len(json.dumps(evidence))``, the same measure as the eval's
    per-cell ``evidence_bytes``, so a production run and an eval cell on the
    same sample can be compared. ``counts`` is entries per key (list length, or
    key count for the insights dict). The evidence itself is not copied here:
    it is the report's own sections, already in the report.
    """
    if evidence:
        return {
            "given": True,
            "keys": sorted(evidence),
            "bytes": len(json.dumps(evidence)),
            "counts": {k: len(v) if isinstance(v, (list, dict)) else 1
                       for k, v in sorted(evidence.items())},
        }
    return {"given": False, "reason": reason or NOT_GIVEN_NONE_IN_REPORT}


def _as_written(report: dict) -> dict:
    """The sections the builder reads, as report.json will hold them.

    run-pipeline writes report.json with ``json.dump(..., default=str)``, and
    the eval builds its evidence from that file. Production builds from the
    in-memory report, where a value json cannot encode would be a str in the
    file and an object here: the two would differ, and ``run_interpret``'s
    plain ``json.dumps`` of the init would raise mid-Stage-4.5. Round-tripping
    the four sections the same way makes production's evidence the eval's for
    the same report, by construction.
    """
    cape = report.get("cape") if isinstance(report.get("cape"), dict) else {}
    vol = report.get("volatility") if isinstance(report.get("volatility"), dict) else {}
    sections = {
        "cross_correlations": report.get("cross_correlations"),
        "correlation_warnings": report.get("correlation_warnings"),
        "cape": {"signatures": cape.get("signatures")},
        "volatility": {"insights": vol.get("insights")},
    }
    return json.loads(json.dumps(sections, default=str))


def evidence_for_interpret(report: dict, enabled: bool,
                           agentic: bool) -> tuple[dict | None, dict]:
    """The ``extra_evidence`` for one run_interpret call, and its record.

    ``agentic`` is whether the init goes to the container's agentic loop. Only
    that loop puts ``correlated_evidence`` into the agent's first message
    (interpret-ghidra.py, ``_correlated_evidence_context``); the single-shot
    paths never read it. Sending it there would change nothing the model sees
    while the record claimed it had been given, so it is not sent, and the
    record says why.
    """
    if not enabled:
        return None, evidence_record(None, NOT_GIVEN_DISABLED)
    if not agentic:
        return None, evidence_record(None, NOT_GIVEN_SINGLE_SHOT)
    evidence = correlated_evidence(_as_written(report))
    if not evidence:
        return None, evidence_record(None, NOT_GIVEN_NONE_IN_REPORT)
    return evidence, evidence_record(evidence)
