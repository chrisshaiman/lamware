# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The eval handed .NET samples an empty Ghidra dump (#505).

`run_interpret`'s first parameter is named `ghidra_result` but is really an INIT
PAYLOAD, and production builds a different one per modality (run-pipeline.py:800
onward). The eval only ever built the Ghidra one, so five of the twelve curated
samples got nothing to read: they are .NET, routed to ILSpy/de4dot by design,
with their decompiled C# sitting unread in `report["dotnet_analysis"]`.

Not a failure of the pipeline — `run-pipeline.py:630` sets
`{"triggered": True, "dotnet_routed": True, "analyzed_files": []}` deliberately.
Correct behaviour that reads exactly like a silent failure.

Native PE and .NET are TWO EXPERIMENTS and are never pooled. That is enforced by
the corpus manifests being separate files, not by this code — which only has to
build the right payload for whatever it is handed.
"""
import json

import pytest
from lamware_eval.runner import init_payload_for

DOTNET_REPORT = {
    "bazaar_family": "warzonerat",
    "ghidra": {"triggered": True, "dotnet_routed": True, "analyzed_files": []},
    "cape": {"signatures": [{"name": "injection_write_process"}]},
    "dotnet_analysis": {
        "analysis_success": True,
        "analysis_type": "dotnet_ilspy",
        "decompilation": {"source": "class Loader { void Run() { Inject(); } }"},
        "classes": ["Loader"],
        "strings_of_interest": ["http://c2.example"],
    },
}
NATIVE_REPORT = {
    "ghidra": {"triggered": True, "project_dir": "/p", "program_name": "abc",
               "analyzed_files": [{"analysis_success": True}]},
}


def test_a_dotnet_sample_is_handed_its_decompiled_source():
    """THE bug. Before this the payload was the empty Ghidra dict."""
    init, modality, source = init_payload_for(DOTNET_REPORT)
    assert modality == "dotnet"
    assert init["analysis_type"] == "dotnet"
    assert init["source_language"] == "csharp"
    assert "class Loader" in init["decompiled_source"]
    assert "class Loader" in source


def test_a_native_sample_is_unchanged():
    """The native path is the one with a result behind it (#420 stage 2). This
    change must not move it."""
    init, modality, source = init_payload_for(NATIVE_REPORT)
    assert modality == "native_pe"
    assert init is NATIVE_REPORT["ghidra"]
    assert json.loads(source) == NATIVE_REPORT["ghidra"]


def test_the_grounding_source_follows_the_modality():
    """Scoring a .NET cell against json.dumps(ghidra) would score it against an
    empty dict, so every claim it made would be a fabrication."""
    _, _, source = init_payload_for(DOTNET_REPORT)
    assert "analyzed_files" not in source, "still grounding against the Ghidra dump"
    assert "Inject()" in source


def test_a_failed_dotnet_analysis_falls_back_rather_than_shipping_nothing():
    """`analysis_success: False` means ILSpy produced nothing usable. Sending it
    anyway would hand the agent an empty C# payload, which is the same defect
    wearing a different hat."""
    report = {**DOTNET_REPORT,
              "dotnet_analysis": {"analysis_success": False, "error": "de4dot failed"}}
    init, modality, _ = init_payload_for(report)
    assert modality == "native_pe"
    assert init == report["ghidra"]


def test_the_bazaar_family_reaches_the_payload():
    """Production passes its llm_context through; the eval must not drop it, or
    the two harnesses show the agent different things."""
    init, _, _ = init_payload_for(DOTNET_REPORT)
    assert init["bazaar_family"] == "warzonerat"


def test_cape_signature_names_reach_the_extraction_context_path():
    """build_dotnet_init takes cape_sigs. Passing [] would quietly differ from
    production for any sample analysed from an extraction."""
    report = {**DOTNET_REPORT,
              "dotnet_analysis": {**DOTNET_REPORT["dotnet_analysis"],
                                  "extraction_source": {"source_dir": "/d",
                                                        "sha256": "a" * 64}}}
    init, _, _ = init_payload_for(report)
    assert init["extraction_context"]["cape_signatures"] == ["injection_write_process"]


def test_the_payload_builder_is_the_one_production_uses():
    """Imported, not reimplemented. Two copies of a payload shape that must
    match is the #380 pattern, and what would drift is what the agent sees."""
    import ast
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "runner.py").read_text(encoding="utf-8")
    imports = {n.module for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.ImportFrom)}
    assert "stages.single_shot_init" in imports, sorted(imports)


@pytest.mark.parametrize("module", ["runner.py", "rebuild.py"])
def test_both_paths_resolve_modality_the_same_way(module):
    """A re-score that assumed Ghidra would score a .NET cell against an empty
    dict and call every claim a fabrication — disagreeing with the sweep that
    produced it (#380, #496)."""
    import ast
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / module).read_text(encoding="utf-8")
    called = {n.func.id for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "init_payload_for" in called, f"{module} resolves the payload its own way"
