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
        value = str(ioc.get("value", "")).strip()
        if not value:
            continue
        if normalize(value) in norm_source:
            grounded += 1
        else:
            fabricated.append(value)
    total = grounded + len(fabricated)
    ratio = 1.0 if total == 0 else round(grounded / total, 3)
    return {"total": total, "grounded": grounded, "fabricated": fabricated, "grounded_ratio": ratio}
