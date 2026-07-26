# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Grounding (fabrication) check for single-shot LLM analysis output.

A local model can produce fluent, well-structured analysis that invents IOCs
(observed with qwen3:32b on the RE spike: a fabricated C2 domain + registry
GUID). This module cross-references every concrete IOC value the model claims
against the source input it was given. A value that does not appear in the
source (after defang normalization) is a fabrication flag.

Scope: the automated pass grounds `code_level_ioc` values only — the concrete,
fabricable strings (domains, IPs, URLs, registry keys, mutexes). Capabilities
and MITRE techniques are abstractions that rarely appear literally in source;
those are left to the human read in the scorecard.
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


def normalize(text: str) -> str:
    """Lowercase, refang common IOC obfuscations, and collapse whitespace."""
    out = (text or "").lower()
    for fanged, plain in _REFANG:
        out = out.replace(fanged, plain)
    return re.sub(r"\s+", " ", out).strip()


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


# Literal artifacts embedded inside a descriptive claim: `backticked` spans,
# "quoted" spans, hex constants, and Ghidra-style symbols.
_LITERAL_PATTERNS = (
    re.compile(r"`([^`]{2,})`"),
    re.compile(r'"([^"]{2,})"'),
    re.compile(r"\b(0x[0-9a-fA-F]{2,})\b"),
    re.compile(r"\b((?:FUN|DAT|LAB|SUB)_[0-9a-fA-F]{4,})\b"),
)


def _extract_literals(value: str, limit: int = 6) -> list[str]:
    """Pull checkable literals out of a prose IOC claim.

    Models format IOCs very differently: claude-sonnet-5 emits bare artifacts
    ("~%u.tmp", "0x811c9dc5"), qwen3.6 emits descriptive signatures such as
    "XOR pattern `data[i] ^ key[i % len]` in a do..while loop in `FUN_0040b477`".
    A whole sentence never appears verbatim in decompilation, so substring
    matching scored EVERY descriptive claim as fabricated — on 2026-07-25 that
    put the local arm at 0/20 grounded, including `FUN_0040b477`, an address
    four independent runs had corroborated. The metric was measuring IOC STYLE,
    not truthfulness.

    Grounding the literals inside the description scores both styles fairly.
    """
    out: list[str] = []
    for pat in _LITERAL_PATTERNS:
        for m in pat.findall(value):
            tok = m.strip()
            # Skip fragments too short or too generic to be evidence.
            if len(tok) >= 4 and tok not in out:
                out.append(tok)
            if len(out) >= limit:
                return out
    return out


def grounding_scorecard(analysis: dict, source_text: str) -> dict:
    """Score how many claimed code_level_ioc values appear in the source.

    Returns {total, grounded, fabricated (list of un-found values), grounded_ratio}.
    An empty/missing IOC list scores a clean 1.0 (nothing claimed = nothing to fake).
    """
    # Accept both the singular schema key and the plural the models often emit.
    iocs = analysis.get("code_level_ioc") or analysis.get("code_level_iocs") or []
    norm_source = normalize(source_text)
    fabricated: list[str] = []
    grounded = 0
    for ioc in iocs:
        value = _ioc_value(ioc)
        if not value:
            continue
        if normalize(value) in norm_source:
            grounded += 1
            continue
        # Descriptive IOCs never match verbatim — score their literals instead.
        literals = _extract_literals(value)
        if literals and all(normalize(t) in norm_source for t in literals):
            grounded += 1
        else:
            fabricated.append(value)
    total = grounded + len(fabricated)
    ratio = 1.0 if total == 0 else round(grounded / total, 3)
    return {"total": total, "grounded": grounded, "fabricated": fabricated, "grounded_ratio": ratio}
