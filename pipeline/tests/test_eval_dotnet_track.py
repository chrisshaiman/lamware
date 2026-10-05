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
import sys

import pytest
from lamware_eval.runner import NoAnalysisData, init_payload_for

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
    """THE bug. Before this the payload was the empty Ghidra dict.

    Single-shot: the source rides in the payload. Agentic (#646, the default):
    it rides in the payload for the ORCHESTRATOR, which serves it through the
    tools and strips it before the container sees the payload."""
    init, modality, source, _read = init_payload_for(DOTNET_REPORT, dotnet_mode="single_shot")
    assert modality == "dotnet"
    assert init["analysis_type"] == "dotnet"
    assert init["source_language"] == "csharp"
    assert "class Loader" in init["decompiled_source"]
    assert "class Loader" in source

    init, modality, _source, _read = init_payload_for(DOTNET_REPORT)
    assert modality == "dotnet_agentic"
    assert init["dotnet_mode"] == "agentic"
    assert "class Loader" in init["decompiled_source"]


def test_a_native_sample_is_handed_its_analysed_file():
    """The native path hands the agent the file production's Stage 4.5 hands
    it (`select_native_target`), not the `report["ghidra"]` wrapper, which
    the container renders as an empty card (#697). The grounding text is that
    entry minus host paths (#669)."""
    init, modality, source, _read = init_payload_for(NATIVE_REPORT)
    assert modality == "native_pe"
    assert init == NATIVE_REPORT["ghidra"]["analyzed_files"][0]
    assert json.loads(source) == NATIVE_REPORT["ghidra"]["analyzed_files"][0]


def test_the_grounding_source_follows_the_modality():
    """Scoring a .NET cell against json.dumps(ghidra) would score it against an
    empty dict, so every claim it made would be a fabrication."""
    _, _, source, _read = init_payload_for(DOTNET_REPORT, dotnet_mode="single_shot")
    assert "analyzed_files" not in source, "still grounding against the Ghidra dump"
    assert "Inject()" in source


def test_the_agentic_grounding_is_what_the_agent_was_sent():
    """Agentic .NET (#646): the agent is sent a map — class and method names,
    strings — and reads bodies through tools, whose results are scored via
    tool_output_text. A body it never pulled must not ground its claims, so
    the grounding head names `Loader.Run` but not the call inside it."""
    _, _, source, _read = init_payload_for(DOTNET_REPORT)
    assert "analyzed_files" not in source, "still grounding against the Ghidra dump"
    assert "Loader" in source and "Run" in source
    assert "Inject()" not in source, "the head grounds against code the agent never read"
    assert "decompiled_source" not in json.loads(source)


def test_a_failed_dotnet_analysis_falls_back_rather_than_shipping_nothing():
    """`analysis_success: False` means ILSpy produced nothing usable. Sending it
    anyway would hand the agent an empty C# payload, which is the same defect
    wearing a different hat."""
    report = {**DOTNET_REPORT,
              "dotnet_analysis": {"analysis_success": False, "error": "de4dot failed"}}
    # Nothing in Ghidra succeeded either: production records no_analysis_data
    # and runs no agent, so the cell fails rather than measuring one (#697).
    with pytest.raises(NoAnalysisData):
        init_payload_for(report)
    # With a successful Ghidra file, production's native branch reads it.
    entry = {"analysis_success": True, "program_name": "p", "project_dir": "/p"}
    report["ghidra"] = {**report["ghidra"], "analyzed_files": [entry]}
    init, modality, _, _read = init_payload_for(report)
    assert modality == "native_pe"
    assert init == entry


def test_the_bazaar_family_is_withheld_and_recorded():
    """Production passes the MalwareBazaar family to the .NET agent as a "starting
    hypothesis". The eval withholds it (#705): a cell given the label measures recall
    of the label (ADR-019). The record says it was withheld, so the cell is honest
    about differing from production on exactly this."""
    init, _, _, read = init_payload_for(DOTNET_REPORT)
    assert "bazaar_family" not in init
    assert read["bazaar_family_withheld"] is True


def test_no_record_claims_a_withholding_that_did_not_happen():
    report = {k: v for k, v in DOTNET_REPORT.items() if k != "bazaar_family"}
    _init, _, _, read = init_payload_for(report)
    assert "bazaar_family_withheld" not in read


def test_the_family_never_reaches_the_container(tmp_path):
    """Behavioural: what run_interpret actually writes to the interpret container for
    the eval's .NET init carries no bazaar_family, so `_bazaar_context` has nothing
    to put in the prompt. A stand-in container saves the init line it receives."""
    from stages.interpret import run_interpret
    seen = tmp_path / "init.json"
    container = tmp_path / "fake-interpret"
    container.write_text(
        "#!" + sys.executable + "\n"
        "import sys, json\n"
        f"open({str(seen)!r}, 'w').write(sys.stdin.readline())\n"
        "print(json.dumps({'type': 'final', 'analysis': {}, 'model_used': 'x', "
        "'tool_calls_used': 0}), flush=True)\n")
    container.chmod(0o755)
    init, _, _, _ = init_payload_for(DOTNET_REPORT)
    run_interpret(init, tmp_path, str(container), True, 60, {}, "/nonexistent-ghidra")
    sent = json.loads(seen.read_text())
    assert sent["type"] == "init"
    assert "bazaar_family" not in sent and "bazaar_family" not in sent["ghidra_data"]
    assert "warzonerat" not in seen.read_text().lower()


def test_cape_signature_names_reach_the_extraction_context_path():
    """build_dotnet_init takes cape_sigs. Passing [] would quietly differ from
    production for any sample analysed from an extraction."""
    report = {**DOTNET_REPORT,
              "dotnet_analysis": {**DOTNET_REPORT["dotnet_analysis"],
                                  "extraction_source": {"source_dir": "/d",
                                                        "sha256": "a" * 64}}}
    init, _, _, _read = init_payload_for(report)
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
    # The .NET selector both production and the eval call (#646), which in
    # turn calls single_shot_init.build_dotnet_init for the single-shot mode.
    assert "stages.dotnet_tools" in imports, sorted(imports)
    for path in ("lamware_eval/runner.py", "run-pipeline.py"):
        tree = ast.parse((Path(__file__).resolve().parents[2] / "ansible" / "roles"
                          / "pipeline" / "files" / path).read_text(encoding="utf-8"))
        called = {n.func.id for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "build_dotnet_interpret_init" in called, f"{path} builds .NET its own way"
        assert "build_dotnet_init" not in called, f"{path} bypasses the mode selector"


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


# --- routing: a local arm must be local on BOTH paths ---


def test_a_local_arm_selects_the_local_backend_on_both_interpret_paths():
    """The interpret container reads `re_backend` for the agentic loop and
    `single_shot_backend` for .NET/Java/PowerShell/Go. Setting only the first
    sent every .NET cell to the Anthropic passthrough, which 404s for a local
    model alias — the stage2-dotnet run died 10 cells for 10.

    Invisible until an arm is BOTH local and single-shot, which is exactly what
    #505 created.
    """
    import ast
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "runner.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "run_arm")
    assigned = {t.slice.value for t in ast.walk(fn)
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                and isinstance(t.ctx, ast.Store) and isinstance(t.slice.value, str)}
    assert "re_backend" in assigned
    assert "single_shot_backend" in assigned, (
        "a local arm still reaches the cloud on the single-shot path")


def test_promotion_refuses_an_init_that_carries_the_family(tmp_path, monkeypatch):
    """The backstop: if any path to the agent stops withholding the label, the
    sample is refused at promotion, not measured on recall of it (#705)."""
    from lamware_eval import promote
    real = promote.init_payload_for

    def leaky(report, *a, **k):
        init, modality, src, read = real(report, *a, **k)
        return {**init, "bazaar_family": report["bazaar_family"]}, modality, src, read

    monkeypatch.setattr(promote, "init_payload_for", leaky)
    _leak, refusals = promote.leak_check(DOTNET_REPORT, "warzonerat", tmp_path / "warzonerat_x")
    assert any("bazaar_family" in r for r in refusals), refusals


def test_promotion_accepts_the_withheld_init(tmp_path):
    from lamware_eval.promote import leak_check
    _leak, refusals = leak_check(DOTNET_REPORT, "warzonerat", tmp_path / "warzonerat_x")
    assert not any("bazaar_family" in r for r in refusals), refusals


def test_run_arm_refuses_an_init_that_carries_the_family(tmp_path, monkeypatch):
    """The run-time backstop, for a corpus entry copied in by hand rather than
    promoted: run_arm stops before the container if the init carries the label."""
    from lamware_eval import runner
    from lamware_eval.arms import Arm
    from lamware_eval.corpus import CorpusSample
    (tmp_path / "report.json").write_text(json.dumps(DOTNET_REPORT))
    real = runner.init_payload_for

    def leaky(report, *a, **k):
        init, modality, src, read = real(report, *a, **k)
        return {**init, "bazaar_family": "warzonerat"}, modality, src, read

    started = []
    monkeypatch.setattr(runner, "init_payload_for", leaky)
    monkeypatch.setattr(runner, "make_ghidra_verifier", lambda _cmd: None)
    monkeypatch.setattr(runner, "run_interpret", lambda *a, **k: started.append(a) or {})
    sample = CorpusSample(sha256="a" * 64, mb_family="warzonerat", corpus_dir=str(tmp_path))
    arm = Arm(name="qwen@10", model="m", re_backend="local", max_tool_calls=10)
    with pytest.raises(ValueError, match="bazaar_family"):
        runner.run_arm(sample, arm, {}, "/x", "/y")
    assert started == []
