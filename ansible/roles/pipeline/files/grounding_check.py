# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Grounding (fabrication) check for LLM analysis output.

A local model can produce fluent, well-structured analysis that invents IOCs
(observed with qwen3:32b on the RE spike: a fabricated C2 domain + registry
GUID). This module cross-references every concrete IOC value the model claims
against the source input it was given. A value whose concrete artifacts do not
appear in the source (after defang normalization) is a fabrication flag.

Scope: the automated pass grounds `code_level_ioc` values only — the concrete,
fabricable strings (domains, IPs, URLs, registry keys, mutexes). Capabilities
and MITRE techniques are abstractions that rarely appear literally in source;
those are left to the human read in the scorecard.

WHAT THIS METRIC IS FOR, because it decides every judgement call below: it
answers "did the model make this up?", NOT "did the model write it the way we
expected?". Twice now the implementation has drifted into measuring the second
question and reporting the answer as if it were the first.
"""
import re

_REFANG = [
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(dot)", "."),
    ("[:]", ":"),
    ("[@]", "@"),
]


def refang(text: str) -> str:
    """Undo common IOC obfuscation WITHOUT lowercasing.

    Separated from `normalize` because literal extraction must run on refanged text
    (`evil[.]com` matches no artifact pattern; `evil.com` matches the dotted-artifact
    one) while still needing original case (the CamelCase pattern that recognises
    `CheckRemoteDebuggerPresent` cannot survive lowercasing). Extracting from raw text
    silently dropped every defanged domain — the single most fabricable IOC there is.
    """
    out = text or ""
    for fanged, plain in _REFANG:
        out = out.replace(fanged, plain)
    return out


def normalize(text: str) -> str:
    """Lowercase, refang common IOC obfuscations, and collapse whitespace."""
    return re.sub(r"\s+", " ", refang((text or "").lower())).strip()


def _ioc_value(ioc: object) -> str:
    """Pull the claim string out of an IOC entry, whatever shape the model used.

    Models do not agree on the schema: claude-sonnet-5 emits dicts
    ({"type","value","context"}), qwen3.6 emits bare strings. Assuming dicts
    raised AttributeError: 'str' object has no attribute 'get' and killed 5 of 7
    local cells mid-scoring on 2026-07-25 — after their results were written, so
    the run looked like "0 claims, 28% completion" rather than a crash.
    """
    if isinstance(ioc, dict):
        return str(ioc.get("value", "")).strip()
    if isinstance(ioc, str):
        return ioc.strip()
    return str(ioc).strip()


# Literal artifacts embedded inside a descriptive claim.
#
# The first four patterns match DELIMITED or PREFIXED evidence. On their own they
# encode one model's citation habits as the definition of a checkable claim:
# claude-sonnet-5 backticks and quotes its artifacts, qwen3.6 writes them bare. On
# 2026-07-29 that scored a raccoonstealer run at 1/4 grounded when all four claims
# were verbatim in the tool output — the mutex `MilcoSoft_#Rip_X` appeared twice,
# `CheckRemoteDebuggerPresent` 123 times. The only claim that scored was the one
# whose evidence happened to look like a Ghidra symbol.
#
# The last three match BARE evidence. Each requires enough structure to be an
# artifact rather than an English word:
#   - hex runs of 8+ chars (a decrypted-string sample, a hash fragment)
#   - identifiers containing _ or # (mutex and event names, snake_case symbols)
#   - CamelCase with 2+ humps (Win32 API names: DestroyWindow, GetObjectW)
# Ordinary prose does not match these. "Repeated" has no second hump; "Anti-Debug"
# splits on the hyphen.
_LITERAL_PATTERNS = (
    re.compile(r"`([^`]{2,})`"),
    re.compile(r'"([^"]{2,})"'),
    re.compile(r"\b(0x[0-9a-fA-F]{2,})\b"),
    re.compile(r"\b((?:FUN|DAT|LAB|SUB)_[0-9a-fA-F]{4,})\b"),
    re.compile(r"\b([0-9a-fA-F]{8,})\b"),
    # NOTE the separator run `[_#]+` and the body `[A-Za-z0-9]+` are DISJOINT. An
    # earlier version had `#` in both (`[_#][A-Za-z0-9#]+`), so a run of `##` could be
    # split between them many ways -- CodeQL py/redos, high severity, and a genuine
    # availability bug here: this scorer parses model output derived from malware, so a
    # crafted IOC string could hang the eval harness. Disjoint classes make the match
    # unambiguous and linear.
    re.compile(r"\b([A-Za-z][A-Za-z0-9]*(?:[_#]+[A-Za-z0-9]+)+)\b"),
    re.compile(r"\b([A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+)\b"),
    # Dotted artifacts: domains, IPv4, filenames. These are THE canonical fabricable
    # IOC — the module exists because qwen3:32b invented a C2 domain — and an early
    # draft of #243 missed them entirely, which would have moved invented domains from
    # `fabricated` to `unscoreable` and quietly disarmed the check. Ordinary prose does
    # not survive the 4-character floor ("e.g", "i.e", "1.0"), and "do..while" has no
    # label between its dots.
    re.compile(r"\b([A-Za-z0-9][A-Za-z0-9~%_-]*(?:\.[A-Za-z0-9~%_-]+)+)\b"),
    re.compile(r"(https?://[^\s\"'<>,)\]]+)"),
    re.compile(r"((?:[A-Za-z]:\\\\?|\\\\\\\\|HKEY_[A-Z_]+\\\\?)[^\s\"',)\]]+)"),
)

# Cap on literals checked per claim. Generous, and truncation is REPORTED rather
# than silent — the previous limit of 6 meant a claim citing ten artifacts had four
# never checked, with nothing in the output to say so.
_LITERAL_LIMIT = 12


def _extract_literals(value: str, limit: int = _LITERAL_LIMIT) -> list[str]:
    """Pull checkable literals out of a prose IOC claim.

    THE SHARED CONTRACT. `lamware_eval.consensus` matches claims across seeded runs
    using exactly these literals, so this returns a plain list and must keep doing so.
    An earlier draft of #243 changed it to a (list, truncated) tuple for the scorer's
    benefit and broke consensus with an AttributeError at a distance. Callers wanting
    the truncation flag use `_extract_literals_detail`.
    """
    return _extract_literals_detail(value, limit)[0]


def _extract_literals_detail(value: str, limit: int = _LITERAL_LIMIT) -> tuple[list[str], bool]:
    """As `_extract_literals`, plus whether the limit truncated the result.

    Models format IOCs very differently: claude-sonnet-5 emits bare artifacts
    ("~%u.tmp", "0x811c9dc5"), qwen3.6 emits descriptive signatures such as
    "XOR pattern `data[i] ^ key[i % len]` in a do..while loop in `FUN_0040b477`"
    or "Mutex/Event Name: MilcoSoft_#Rip_X". A whole sentence never appears
    verbatim in decompilation, so substring matching scored EVERY descriptive
    claim as fabricated — on 2026-07-25 that put the local arm at 0/20 grounded,
    including `FUN_0040b477`, an address four independent runs had corroborated.

    Grounding the literals inside the description scores every style fairly.
    """
    out: list[str] = []
    seen: set[str] = set()
    # Refang FIRST, keeping case: `evil[.]com` matches no pattern, `evil.com` does.
    value = refang(value)
    for pat in _LITERAL_PATTERNS:
        for m in pat.findall(value):
            tok = m.strip()
            key = tok.lower()
            # Skip fragments too short or too generic to be evidence.
            if len(tok) < 4 or key in seen:
                continue
            if len(out) >= limit:
                return _drop_subsumed(out), True
            seen.add(key)
            out.append(tok)
    return _drop_subsumed(out), False


def _drop_subsumed(literals: list[str]) -> list[str]:
    """Remove literals wholly contained in another literal from the same claim.

    The patterns overlap by design: `MilcoSoft.dll` matches both the CamelCase rule
    (`MilcoSoft`) and the dotted-artifact rule (`MilcoSoft.dll`), and `FUN_0040b477`
    also yields the bare hex run `0040b477`. Keeping both halves is redundant for
    grounding and actively wrong for `lamware_eval.consensus`, which keys claims on
    these literals: one artifact produced two keys, so a single claim agreed by two
    runs was reported as two separate agreements.

    Keeps the longest form, which is the most specific and the least likely to
    collide with unrelated text.
    """
    kept: list[str] = []
    for lit in sorted(literals, key=len, reverse=True):
        low = lit.lower()
        if not any(low in k.lower() for k in kept):
            kept.append(lit)
    # Restore the original discovery order so output stays stable and readable.
    return [lit for lit in literals if lit in kept]


def grounding_scorecard(analysis: dict, source_text: str) -> dict:
    """Score how many claimed code_level_ioc values are supported by the source.

    Every claim lands in exactly one bucket:

      grounded    — every literal it cites appears in the source
      partial     — some cited literals appear, others do not
      fabricated  — it cites literals and NONE of them appear
      unscoreable — no checkable literal could be extracted

    `unscoreable` exists because the previous implementation had no such bucket: a
    claim yielding no literals fell through to `fabricated`, so "I cannot check this"
    was recorded as "the model invented this". Combined with an extractor that only
    recognised delimited evidence, that manufactured a 0.25 grounding score for a run
    in which every claim was true.

    But unscoreable is NOT free. It counts in the denominator as ungrounded, because
    `code_level_ioc` is contractually a list of concrete, checkable artifacts, and
    excluding vague prose would let a model emit one real IOC plus nine sentences of
    hedging and score 1.0. That is the same loophole `partial` closes, and the same one
    `aggregate()` already documents for cells claiming nothing at all. Labelling is
    honest; scoring stays strict.

    `partial` exists because requiring ALL literals made one absent or mis-transcribed
    token condemn an otherwise well-evidenced claim. It is a SUB-CLASSIFICATION, not a
    lighter verdict: partial claims remain in `fabricated` so that extraction can never
    become a free pass — one invented artifact still flags the claim.

    grounded_ratio = grounded / every claim that carried a value. Only `grounded`
    counts in the numerator.
    """
    iocs = analysis.get("code_level_ioc") or analysis.get("code_level_iocs") or []
    norm_source = normalize(source_text)

    grounded = 0
    partial: list[str] = []
    fabricated: list[str] = []
    unscoreable: list[str] = []
    truncated = 0
    details: list[dict] = []

    for ioc in iocs:
        value = _ioc_value(ioc)
        if not value:
            continue

        # A claim short enough to appear verbatim is grounded outright.
        if normalize(value) in norm_source:
            grounded += 1
            details.append({"claim": value, "verdict": "grounded", "found": None, "of": None})
            continue

        literals, was_truncated = _extract_literals_detail(value)
        truncated += int(was_truncated)

        if not literals:
            unscoreable.append(value)
            details.append({"claim": value, "verdict": "unscoreable", "found": 0, "of": 0})
            continue

        found = [t for t in literals if normalize(t) in norm_source]
        detail = {"claim": value, "found": len(found), "of": len(literals),
                  "missing": [t for t in literals if t not in found][:5]}
        if len(found) == len(literals):
            grounded += 1
            detail["verdict"] = "grounded"
        else:
            # Every ungrounded-but-scoreable claim is flagged, whether it cited one
            # invented artifact among several or nothing real at all. `partial` records
            # WHICH, without softening the flag — otherwise extraction becomes a free
            # pass: bury a fabricated domain among four real symbols and score clean.
            fabricated.append(value)
            if found:
                partial.append(value)
            detail["verdict"] = "partial" if found else "fabricated"
        details.append(detail)

    # Unscoreable claims ARE in the denominator: see the docstring. Vague prose in a
    # field defined as concrete artifacts must not be a costless way to pad output.
    total = grounded + len(fabricated) + len(unscoreable)
    ratio = 1.0 if total == 0 else round(grounded / total, 3)
    return {
        # Keys the scorecard has always consumed.
        "total": total,
        "grounded": grounded,
        "fabricated": fabricated,
        "grounded_ratio": ratio,
        # Added by #243.
        "partial": partial,
        "unscoreable": unscoreable,
        "truncated_claims": truncated,
        "details": details,
    }
