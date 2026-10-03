# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The eval measures the agentic .NET path production runs, and can A/B it (#646).

`run_arm` builds its payload with production's `build_dotnet_interpret_init`
(#667), so a .NET cell now reads the agentic payload by default and records the
`dotnet_agentic` modality. The `+ss` arms pin the previous single-shot path so
the two can be compared on the same corpus; they are separate modalities and
`aggregate` names them separately.

Grounding follows what the agent could see (#669): the map it was sent, plus the
C# it pulled through tools. The tools' audit file is `tool_calls_dotnet.json`
(named after the payload's analysis_type), and a scorer that read only
`tool_calls.json` would call every claim drawn from a tool result a fabrication.
"""
import importlib.util
import json
from pathlib import Path

import pytest
from lamware_eval import runner
from lamware_eval.arms import resolve_arm
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import aggregate

_spec = importlib.util.spec_from_file_location(
    "dotnet_formbook_shape", Path(__file__).parent / "fixtures" / "dotnet_formbook_shape.py")
shape = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shape)

SRC = shape.formbook_shaped_source()
#: A value only a tool result contains — never the map, never the report.
MUTEX = "Qx7Mutex_Karta_9921"
REPORT = {
    "ghidra": {"triggered": True, "dotnet_routed": True, "analyzed_files": []},
    "dotnet_analysis": shape.dotnet_analysis(SRC),
}
SHA = "5b4f596d" + "0" * 56


def _run_arm(tmp_path, monkeypatch, arm_name, base_cfg=None):
    cdir = tmp_path / "c"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "report.json").write_text(json.dumps(REPORT))
    seen: dict = {}

    def fake_interpret(init, out, cmd, enabled, timeout, cfg, ghidra_cmd, **kw):
        seen["init"], seen["cfg"] = init, cfg
        audit = Path(out) / "llm_audit"
        audit.mkdir(parents=True, exist_ok=True)
        name = "tool_calls_dotnet.json"
        (audit / name).write_text(json.dumps([{
            "tool": "get_method_source", "args": {"class_name": "BattleForm"},
            "result": {"source": f'string m = "{MUTEX}";'}}]))
        res = {"analysis": {"malware_family_guess": "x",
                            "code_level_iocs": [{"type": "mutex", "value": MUTEX}]},
               "usage": {}, "audit": {"tool_call_log": str(audit / name)}}
        return res

    monkeypatch.setattr(runner, "run_interpret", fake_interpret)
    monkeypatch.setattr(runner, "make_ghidra_verifier", lambda cmd: None)
    monkeypatch.setattr(runner, "_server_sampling", lambda: {})
    sample = CorpusSample(SHA, "formbook", str(cdir))
    seen["cell"] = runner.run_arm(sample, resolve_arm(arm_name), base_cfg or {},
                                  "/bin/true", "/bin/ghidra")
    seen["result"] = json.loads(
        (runner.cell_out_dir(sample, resolve_arm(arm_name)) / "result.json").read_text())
    return seen


def test_a_dotnet_cell_reads_the_agentic_payload_by_default(tmp_path, monkeypatch):
    seen = _run_arm(tmp_path, monkeypatch, "qwen@10")
    assert seen["init"]["dotnet_mode"] == "agentic"
    assert seen["cfg"]["dotnet_mode"] == "agentic"
    assert seen["cell"]["modality"] == "dotnet_agentic"
    assert seen["result"]["input"] == {"kind": "dotnet_agentic", "wrapper_routed_by":
                                       "dotnet_routed", "dotnet_mode": "agentic"}


def test_the_ss_arm_reads_the_single_shot_payload(tmp_path, monkeypatch):
    seen = _run_arm(tmp_path, monkeypatch, "qwen@10+ss")
    assert "dotnet_mode" not in seen["init"]
    assert shape.DECOY_MARK in seen["init"]["decompiled_source"]
    assert seen["cfg"]["dotnet_mode"] == "single_shot"
    assert seen["cell"]["modality"] == "dotnet"


def test_the_deployed_config_mode_applies_when_the_arm_has_none(tmp_path, monkeypatch):
    seen = _run_arm(tmp_path, monkeypatch, "qwen@10", base_cfg={"dotnet_mode": "single_shot"})
    assert seen["cell"]["modality"] == "dotnet"


def test_a_claim_read_out_of_a_dotnet_tool_result_is_grounded(tmp_path, monkeypatch):
    """The agent read MUTEX through get_method_source. Grounded only if the
    scorer reads the .NET audit file."""
    seen = _run_arm(tmp_path, monkeypatch, "qwen@10")
    cell = seen["cell"]
    assert cell["total"] >= 1
    assert MUTEX not in json.dumps(cell["fabricated"]), cell["fabricated"]
    assert cell["grounded"] == cell["total"]


def test_the_agentic_grounding_head_has_no_source_and_no_host_path(tmp_path):
    """#669 for the new modality: the head is what the agent was sent."""
    init, modality, head, _ = runner.init_payload_for(REPORT, corpus_dir=tmp_path)
    assert modality == "dotnet_agentic"
    assert shape.DECOY_MARK not in head and str(tmp_path) not in head
    assert "decompiled_source" in init, "the broker still needs it"


def test_rebuild_rescores_an_agentic_cell_against_its_tool_results(tmp_path, monkeypatch):
    """The offline re-scorer replays the recorded mode and reads the same audit."""
    from lamware_eval.rebuild import rebuild
    _run_arm(tmp_path, monkeypatch, "qwen@10")
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"samples": [
        {"sha256": SHA, "mb_family": "formbook", "corpus_dir": str(tmp_path / "c")}]}))
    _, cells = rebuild(str(manifest), "t")
    assert [c["modality"] for c in cells] == ["dotnet_agentic"]
    assert MUTEX not in json.dumps(cells[0]["fabricated"])


@pytest.mark.parametrize("name,mode,evidence,seed", [
    ("qwen@10+ss", "single_shot", "ghidra", None),
    ("qwen@10+ss+corr", "single_shot", "correlated", None),
    ("qwen@10+ss+corr:s42", "single_shot", "correlated", 42),
    ("qwen@10+corr:s42", None, "correlated", 42),
])
def test_the_ss_variants_carry_every_other_setting(name, mode, evidence, seed):
    """A `+ss` arm must differ from its base in the .NET mode ONLY, or the A/B
    measures two things at once."""
    arm, base = resolve_arm(name), resolve_arm("qwen@10")
    assert (arm.dotnet_mode, arm.evidence, arm.seed) == (mode, evidence, seed)
    assert (arm.re_backend, arm.max_tool_calls) == (base.re_backend, base.max_tool_calls)


def test_the_summary_keeps_the_two_dotnet_paths_apart():
    cells = [{"arm": "a", "modality": m, "wall_seconds": 1, "cost_usd": 0,
              "completed": True, "total": 0, "fabricated": []}
             for m in ("dotnet", "dotnet_agentic", "dotnet_agentic")]
    assert aggregate(cells)["a"]["modalities"] == "dotnet=1,dotnet_agentic=2"


# --- fallbacks and limits (review of #673) ------------------------------------------

def test_a_map_that_cannot_be_built_is_scored_as_single_shot(tmp_path, monkeypatch):
    """The sandbox fails (here: a command that exits 137, as an OOM kill does);
    the cell is the single-shot cell production would have run."""
    dead = tmp_path / "dead-sandbox"
    dead.write_text("#!/bin/sh\ncat >/dev/null\nexit 137\n")
    dead.chmod(0o755)
    seen = _run_arm(tmp_path, monkeypatch, "qwen@10",
                    base_cfg={"dotnet_tools_cmd": str(dead)})
    assert seen["cell"]["modality"] == "dotnet"
    rec = seen["result"]["input"]
    assert rec["requested_mode"] == "agentic" and "killed" in rec["agentic_failed"]


def test_the_configured_limits_reach_the_payload_and_the_replay(tmp_path, monkeypatch):
    from lamware_eval.rebuild import rebuild
    limits = {"toc_max_methods": 2}
    seen = _run_arm(tmp_path, monkeypatch, "qwen@10", base_cfg={"dotnet_tool_limits": limits})
    assert seen["init"]["table_of_contents"]["methods_listed"] == 2
    assert seen["result"]["input"]["dotnet_tool_limits"] == limits
    init, _, _, _ = runner.init_payload_for(REPORT, recorded=seen["result"]["input"])
    assert init["table_of_contents"]["methods_listed"] == 2
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"samples": [
        {"sha256": SHA, "mb_family": "formbook", "corpus_dir": str(tmp_path / "c")}]}))
    _, cells = rebuild(str(manifest), "t")
    assert [c["modality"] for c in cells] == ["dotnet_agentic"]


def test_a_replay_that_cannot_rebuild_the_map_says_so(tmp_path):
    """The re-scorer must not quietly ground an agentic cell against the
    single-shot fallback: that would change what the cell measured."""
    dead = tmp_path / "dead-sandbox"
    dead.write_text("#!/bin/sh\ncat >/dev/null\nexit 137\n")
    dead.chmod(0o755)
    with pytest.raises(ValueError, match="cannot rebuild the agentic map"):
        runner.init_payload_for(REPORT, recorded={"kind": "dotnet_agentic",
                                                  "wrapper_routed_by": "dotnet_routed"},
                                dotnet_tools_cfg={"dotnet_tools_cmd": str(dead)})
