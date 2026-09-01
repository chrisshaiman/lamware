# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Shared builders for the single-shot LLM init payloads.

Each single-shot analysis type (.NET / Go / PowerShell) hands the interpret
container a fully-formed `ghidra_data` dict (the model's entire input). These
builders are the single source of truth for that shape, used by both the
pipeline orchestrator (run-pipeline.py) and the local-vs-cloud eval harness
(llm_ab_singleshot.py) so the evaluation tests exactly what production runs.
"""


#: What the analyser containers store at most. Their own cap, applied before the
#: report is written, and they mark the text and record `source_length` when it
#: bites (analyze-dotnet.py.j2:106 and its java/pyinstaller siblings).
#:
#: The builders below must not cut BELOW this. They used to halve it — a second,
#: silent cap that also sliced off the container's truncation marker, so the
#: model received a prefix ending mid-line that read as a whole program. On
#: quasarrat that was 50,000 characters of a 4,468,045-character decompilation:
#: 1.1%, presented as if complete (#507).
#:
#: Some cap is unavoidable — 4.4MB of C# does not fit a 131,072-token window —
#: but it belongs in one place, and it has to say when it bit.
CONTAINER_SOURCE_CAP = 100_000


def capped(text: str, limit: int, comment: str) -> str:
    """`text` cut to `limit`, marked when the cut happens.

    A prefix that does not say it is a prefix is the defect this exists to stop.
    The marker uses the target language's comment syntax so it reads as part of
    the listing rather than as corrupt source.
    """
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n{comment} ... truncated ({len(text):,} characters total) ..."


def _source_provenance(decompilation: dict) -> dict:
    """What the analyser said about the source it produced.

    `source_length` is the TRUE pre-truncation size and the container has always
    recorded it. Nothing read it, so a report could say 4,468,045 while the model
    was shown 50,000 and no consumer could tell (#507).
    """
    return {
        "source_bytes_total": decompilation.get("source_length"),
        "source_truncated_by_analyser": bool(decompilation.get("truncated")),
    }


def build_dotnet_init(dotnet_data: dict, llm_context: dict, cape_sigs: list[str]) -> dict:
    """Build the .NET (ILSpy C#) single-shot init payload."""
    decompilation = dotnet_data.get("decompilation", {})
    dotnet_source = decompilation.get("source", "")
    dotnet_classes = dotnet_data.get("classes", [])
    dotnet_strings = dotnet_data.get("strings_of_interest", [])
    extraction_source = dotnet_data.get("extraction_source")
    shown = capped(dotnet_source, CONTAINER_SOURCE_CAP, "//")
    return {
        **llm_context,
        "analysis_type": "dotnet",
        "source_language": "csharp",
        "decompiled_source": shown,
        "source_bytes_shown": len(shown),
        **_source_provenance(decompilation),
        "class_count": len(dotnet_classes),
        "classes": dotnet_classes[:50],
        "strings_of_interest": dotnet_strings,
        "analysis_success": True,
        "origin": "extraction" if extraction_source else "original",
        "extraction_context": {
            "source_dir": extraction_source["source_dir"],
            "sha256": extraction_source["sha256"],
            "cape_signatures": cape_sigs[:10],
        } if extraction_source else None,
    }


def build_go_init(go_data: dict, llm_context: dict) -> dict:
    """Build the Go (GoReSym metadata) single-shot init payload."""
    return {
        **llm_context,
        "analysis_type": "go_goresym",
        "build_info": go_data.get("build_info", {}),
        "packages": go_data.get("packages", []),
        "functions": go_data.get("functions", {}),
        "types": go_data.get("types", []),
        "strings_of_interest": go_data.get("strings_of_interest", []),
        "analysis_success": True,
    }


def build_ps_init(ps_data: dict, llm_context: dict, cape_sigs: list[str]) -> dict:
    """Build the PowerShell (decoded script) single-shot init payload."""
    return {
        **llm_context,
        "analysis_type": "powershell",
        "source_language": "powershell",
        # Marked when they bite, for the same reason the .NET source is: a
        # prefix that does not say it is a prefix reads as the whole script,
        # and a deobfuscated PowerShell payload is exactly where a reader would
        # assume they were seeing all of it (#507).
        "original_script": capped(ps_data.get("original_script", ""), 30_000, "#"),
        "decoded_layers": ps_data.get("decoded_layers", []),
        "final_decoded": capped(ps_data.get("final_decoded", ""), 50_000, "#"),
        "layer_count": ps_data.get("layer_count", 0),
        "obfuscation_techniques": ps_data.get("obfuscation_techniques", []),
        "iocs_extracted": ps_data.get("iocs_extracted", {}),
        "strings_of_interest": ps_data.get("strings_of_interest", []),
        "psdecode_success": ps_data.get("psdecode_success", False),
        "cape_extracted": ps_data.get("cape_extracted", False),
        "cape_signatures": cape_sigs[:20],
        "input_mode": ps_data.get("input_mode", "file"),
        "analysis_success": True,
    }
