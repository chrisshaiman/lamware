# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Shared builders for the single-shot LLM init payloads.

Each single-shot analysis type (.NET / Go / PowerShell) hands the interpret
container a fully-formed `ghidra_data` dict (the model's entire input). These
builders are the single source of truth for that shape, used by both the
pipeline orchestrator (run-pipeline.py) and the local-vs-cloud eval harness
(llm_ab_singleshot.py) so the evaluation tests exactly what production runs.
"""


def build_dotnet_init(dotnet_data: dict, llm_context: dict, cape_sigs: list[str]) -> dict:
    """Build the .NET (ILSpy C#) single-shot init payload."""
    dotnet_source = dotnet_data.get("decompilation", {}).get("source", "")
    dotnet_classes = dotnet_data.get("classes", [])
    dotnet_strings = dotnet_data.get("strings_of_interest", [])
    extraction_source = dotnet_data.get("extraction_source")
    return {
        **llm_context,
        "analysis_type": "dotnet",
        "source_language": "csharp",
        "decompiled_source": dotnet_source[:50000],  # cap for LLM context
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
        "original_script": ps_data.get("original_script", "")[:30000],
        "decoded_layers": ps_data.get("decoded_layers", []),
        "final_decoded": ps_data.get("final_decoded", "")[:50000],
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
