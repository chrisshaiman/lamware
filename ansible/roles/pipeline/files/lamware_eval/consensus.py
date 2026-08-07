# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Consensus: keep claims that INDEPENDENT runs agree on.

Rather than fighting run-to-run variance, use it as evidence. Run the same sample
several times independently and count how many runs surface each claim. A claim
several independent runs arrive at is more likely real; a claim exactly one run
makes is more likely confabulation.

This is a different question from grounding, and complements it:

    grounding  — "does this claim appear in the evidence the model was shown?"
    consensus  — "do independent runs over that evidence agree it matters?"

A fabricated address fails grounding. A real-but-incidental one passes grounding
and fails consensus. Neither check subsumes the other.

CURRENTLY UNREACHABLE FROM THE CLI. The whole method rests on the word
INDEPENDENT, and no axis currently supplies it (#292):

    seeds — inert. llama-server honours `seed` on /v1/chat/completions but ignores
            it on /v1/messages, and #285 moved the RE transport to /v1/messages
            because the OpenAI leg discarded thinking and returned content: [] on
            tool-calling turns (#283). Seeding and correct tool-use are mutually
            exclusive on this backend; #285 chose correctly.
    depth — worse, and it looks fine. Under that same determinism qwen@10's
            trajectory is a literal PREFIX of qwen@15's on the same sample, so
            agreement on anything found in the first 10 calls is guaranteed by
            construction.

`__main__` therefore refuses `--consensus-k` rather than printing a table that
reports 100% agreement for free. The module is kept intact because #310 —
reconciling across MODELS instead of seeds — is a real axis and reuses all of it.

Cost note for #310: this was affordable because local inference is $0 per run.
Cross-model consensus is metered, so it has to be explicit opt-in. A cheap cousin
of #196.
"""
from collections import defaultdict

from grounding_check import _extract_literals, _ioc_value, normalize

# Claim fields to reconcile. Both schema spellings of the IOC key are accepted
# because the models disagree on it (see _ioc_value's docstring for the crash
# this class of disagreement already caused once).
_IOC_KEYS = ("code_level_ioc", "code_level_iocs")
_LIST_FIELDS = ("capabilities", "mitre_techniques", "attack_techniques")


def claim_keys(claim: object) -> list[str]:
    """Match keys for one claim: its embedded literals, else the whole claim.

    Matching on literals rather than whole strings is what makes cross-run
    comparison work at all. The same finding is written very differently from run
    to run — "MilcoSoft.dll" versus "loads `MilcoSoft.dll` from the resource
    section" — and whole-string equality would score those as two separate claims
    and report no agreement where there is total agreement.

    A claim with no extractable literal falls back to its normalized text, which
    matches only near-identical phrasing. That is the correct conservative
    behaviour: it UNDER-reports agreement on prose claims rather than inventing it.
    """
    value = _ioc_value(claim)
    if not value:
        return []
    literals = _extract_literals(value)
    if literals:
        return [normalize(lit) for lit in literals]
    return [normalize(value)]


def _claims_of(analysis: dict) -> dict[str, list]:
    out: dict[str, list] = {}
    iocs: list = []
    for key in _IOC_KEYS:
        iocs.extend(analysis.get(key) or [])
    out["code_level_iocs"] = iocs
    for field in _LIST_FIELDS:
        if analysis.get(field):
            out.setdefault("techniques" if "technique" in field else field, []).extend(
                analysis[field])
    return out


def consensus(analyses: list[dict], k: int = 2) -> dict:
    """Reconcile claims across independent runs of the same sample.

    Returns, per claim field:
        agreed        — [{key, runs, example}] for claims seen in >= k runs
        singleton     — [{key, runs, example}] for claims seen in exactly one run
        n_runs        — how many analyses were reconciled
        distinct_runs — how many of those produced DIFFERENT claim sets

    `k` defaults to 2 and MUST be interpreted against n_runs: "2 of 2" is a much
    weaker signal than "2 of 5". The caller reports both; this function does not
    collapse them into a score, because a bare consensus ratio would hide exactly
    that distinction.

    `distinct_runs` exists because n_runs cannot distinguish agreement from
    duplication. Reconciling identical transcripts reports every claim at 100%
    agreement, which reads like confirmation and is nothing — that is #292,
    where three "seeds" produced byte-identical output and k=2 silently did what
    __main__ rejects k=1 for. This counts the condition itself rather than
    inferring it from arm names, so it stays correct if independence is ever
    restored (#310) and needs no updating when it is.
    """
    if k < 2:
        raise ValueError("consensus needs k >= 2; k=1 keeps every claim and asserts nothing")
    per_field: dict[str, dict] = {}
    fields = {f for a in analyses for f in _claims_of(a or {})}
    for field in sorted(fields):
        # run_index sets, not counts: the same claim repeated twice WITHIN one run
        # is one run's opinion, and counting it twice would let a single run
        # manufacture its own consensus.
        seen: dict[str, set[int]] = defaultdict(set)
        example: dict[str, str] = {}
        per_run_keys: list[frozenset[str]] = []
        for i, analysis in enumerate(analyses):
            run_keys: set[str] = set()
            for claim in _claims_of(analysis or {}).get(field, []):
                for key in claim_keys(claim):
                    seen[key].add(i)
                    example.setdefault(key, _ioc_value(claim))
                    run_keys.add(key)
            per_run_keys.append(frozenset(run_keys))
        agreed, singleton = [], []
        for key, runs in sorted(seen.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            entry = {"key": key, "runs": len(runs), "example": example[key]}
            if len(runs) >= k:
                agreed.append(entry)
            elif len(runs) == 1:
                singleton.append(entry)
        per_field[field] = {"agreed": agreed, "singleton": singleton,
                            "n_runs": len(analyses),
                            "distinct_runs": len(set(per_run_keys))}
    return per_field


def render_consensus(label: str, per_sample: dict[str, dict], k: int) -> str:
    """Markdown for the consensus section of a scorecard.

    Singletons are reported, not hidden. A claim only one run made is the most
    interesting row on the page: it is either the deepest finding in the sweep or
    a confabulation, and which one it is needs an analyst, not a threshold.
    """
    lines = [f"\n## Consensus — {label} (k >= {k})\n",
             "Claims are matched on embedded literals, so the same finding counts "
             "as agreement even when two runs word it differently.\n"]
    if not per_sample:
        lines.append("_No sample ran more than once — nothing to reconcile._\n")
        return "\n".join(lines)
    for sample, fields in sorted(per_sample.items()):
        lines.append(f"\n### {sample}\n")
        for field, res in sorted(fields.items()):
            n = res["n_runs"]
            lines.append(f"**{field}** ({n} run(s))\n")
            # Vacuity is reported INSTEAD of the table, not above it. A reader
            # who sees "3/3" rows takes the warning as a caveat on a real result;
            # there is no real result here, and the rows would be the only thing
            # anyone quoted. See #292.
            if n >= 2 and res.get("distinct_runs", n) <= 1:
                lines.append(
                    f"> **NOT A RESULT.** All {n} runs produced an identical claim "
                    f"set, so every claim 'agrees' with itself and k has no effect. "
                    f"This measures nothing about confabulation — it measures that "
                    f"the runs were not independent. See #292; #310 tracks a real "
                    f"axis.\n")
                continue
            lines.append("| agreement | claim |")
            lines.append("|---|---|")
            for e in res["agreed"]:
                lines.append(f"| {e['runs']}/{n} | {e['example']} |")
            for e in res["singleton"]:
                lines.append(f"| 1/{n} (unconfirmed) | {e['example']} |")
            if not res["agreed"] and not res["singleton"]:
                lines.append("| — | _no claims_ |")
            lines.append("")
    return "\n".join(lines) + "\n"
