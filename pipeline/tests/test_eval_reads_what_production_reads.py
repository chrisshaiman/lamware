# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The eval must hand the RE agent the input production hands it (#646 option (c)).

Production's Stage 4.5 reads a routed sample's unpacked payload, agentically,
when `select_payload_target` names one. The eval kept sending every .NET sample
down the wrapper's single-shot path, so formbook would have been measured on
its 97k-character C# card game while production read the "Formbook Payload".

The fixture below is the shape of a real report: `/opt/pipeline/reports/
v661_5b4f596d3cf5/report.json` on the sandbox (formbook, dotnet_routed, seven
analysed programs). `V661_INPUT` is the `llm_interpretation.input` production
wrote for it, copied from that host file on 2026-10-02. The eval's record for
the same report must equal it.
"""
import ast
import json
from pathlib import Path

import pytest
from lamware_eval import runner
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import aggregate
from lamware_eval.runner import CorpusProjectMissing, init_payload_for

RUN = "/opt/pipeline/reports/v661_5b4f596d3cf5"
FORMBOOK = "c95af141eb34bf5d68efd96a00ade1e089ebe6539473257bcba73a32a48188cd"
BIG_DLL = "d4ae5a9fae8963f9fad9b501c0a8a864b490b69f0c7be3ea5a2198ff0efe080a"
PE = "a314d7708b70a681c0a56334a04387fadee8f65ddd396c9543125a9d0ba4aaff"
CARD_GAME = "public class Blackjack { void Deal() { Assembly.Load(res); } }"

# Copied from the host report (see module docstring).
V661_INPUT = {
    "kind": "unpacked_payload",
    "program_name": FORMBOOK,
    "source": "cape_payload",
    "functions_count": 377,
    "cape_type": "Formbook Payload",
    "chosen_because": "cape_family_label",
    "wrapper_routed_by": "dotnet_routed",
}


def _af(name, sub, fns, cape_type=None, source="cape_payload", **kw):
    return {"program_name": name, "source": source, "cape_type": cape_type,
            "functions_count": fns, "analysis_success": True, "in_project": True,
            "project_dir": f"{RUN}/{sub}/project", "host_output_dir": f"{RUN}/{sub}", **kw}


def v661_report() -> dict:
    """formbook as production analysed it: canonical = the 4,064-function DLL,
    plus a 377-function "Formbook Payload" (v651 picked the DLL by count)."""
    return {
        "bazaar_family": "Formbook",
        "ghidra": {
            "triggered": True, "dotnet_routed": True,
            "project_dir": f"{RUN}/shellcode_0_unknown_d4ae5a9fae89/project",
            "program_name": BIG_DLL,
            "analyzed_files": [
                _af(PE, "pe_a314d7708b70", 163, source=None),
                {"program_name": None, "source": "cape_injection", "functions_count": 0,
                 "analysis_success": False, "in_project": None, "project_dir": None},
                _af(FORMBOOK, "shellcode_0_unknown_c95af141eb34", 377, "Formbook Payload"),
                _af("0cc29c10e8d7", "shellcode_0_unknown_0cc29c10e8d7", 4062,
                    "Unpacked PE Image: 32-bit DLL"),
                _af(BIG_DLL, "shellcode_0_unknown_d4ae5a9fae89", 4064),
            ],
        },
        "dotnet_analysis": {"analysis_success": True, "analysis_type": "dotnet_ilspy",
                            "decompilation": {"source": CARD_GAME}},
        "cape": {"signatures": [{"name": "injection_write_process"}]},
    }


@pytest.fixture
def corpus(tmp_path) -> Path:
    """A corpus dir holding a copy of every project the v661 report names."""
    d = tmp_path / "formbook_5b4f596d"
    for f in v661_report()["ghidra"]["analyzed_files"]:
        if f.get("host_output_dir"):
            (d / Path(f["host_output_dir"]).name / "project").mkdir(parents=True)
    return d


class Probe:
    """Stub for production's tri-state verifier; records what it was asked."""

    def __init__(self, answer):
        self.answer, self.asked = answer, []

    def __call__(self, project_dir, program_name):
        self.asked.append((project_dir, program_name))
        return self.answer(program_name) if callable(self.answer) else self.answer


def never(*_a):
    raise AssertionError("the verifier must not run for this report")


# --- native: unchanged ---------------------------------------------------------

NATIVE = {"ghidra": {"triggered": True, "project_dir": "/c/amadey/project",
                     "program_name": "abc",
                     "analyzed_files": [{"analysis_success": True, "program_name": "abc",
                                         "functions_count": 75, "source": "cape_payload",
                                         "cape_type": "Amadey Payload",
                                         "project_dir": "/opt/pipeline/reports/x/project"}]}}


def test_a_native_report_is_handed_exactly_what_it_was_before(tmp_path):
    """The native path has the #420 stage-2 result behind it. Same object, same
    source text, and the verifier never runs — even with a corpus dir and a
    family-labelled payload present, because no routed flag is set."""
    init, modality, source, read = init_payload_for(NATIVE, verify=never, corpus_dir=tmp_path)
    assert init is NATIVE["ghidra"]
    assert modality == "native_pe"
    assert source == json.dumps(NATIVE["ghidra"])
    assert read == {"kind": "native_pe", "wrapper_routed_by": None}


def test_run_arm_passes_a_native_report_through_unchanged(tmp_path, monkeypatch):
    """The same property one level up: what run_interpret receives."""
    seen = _run_arm(tmp_path, monkeypatch, NATIVE, verify=never)
    assert seen["init"] == NATIVE["ghidra"]
    assert seen["cell"]["modality"] == "native_pe"
    assert seen["cell"]["input"] == "native_pe"


# --- .NET with a confirmed family-labelled payload -> unpacked_payload ------------

def test_a_dotnet_loader_is_read_through_its_family_labelled_payload(corpus):
    probe = Probe(True)
    init, modality, source, read = init_payload_for(v661_report(), verify=probe,
                                                    corpus_dir=corpus)
    assert modality == "unpacked_payload"
    assert init["program_name"] == FORMBOOK
    assert read == V661_INPUT, "the eval's record differs from production's for the same report"


def test_the_verifier_is_asked_about_the_corpus_copy_never_the_run_dir(corpus):
    """The run dir is cleaned up after 7 days; the corpus copy is what the agent's
    tool calls will use (#631)."""
    probe = Probe(True)
    init, *_ = init_payload_for(v661_report(), verify=probe, corpus_dir=corpus)
    assert probe.asked == [(str(corpus / "shellcode_0_unknown_c95af141eb34" / "project"),
                            FORMBOOK)]
    assert init["project_dir"] == str(corpus / "shellcode_0_unknown_c95af141eb34" / "project")


def test_the_payload_cell_is_grounded_against_the_payload_not_the_csharp(corpus):
    """A claim is grounded only against what the agent could read. It never saw
    the C#, the other six programs, or the host paths (which carry the family
    name the corpus directory is named for)."""
    _, _, source, _ = init_payload_for(v661_report(), verify=Probe(True), corpus_dir=corpus)
    assert FORMBOOK in source
    assert "Blackjack" not in source
    assert BIG_DLL not in source
    assert RUN not in source and str(corpus) not in source


def test_the_payload_cell_is_not_handed_the_wrapper_init(corpus):
    init, *_ = init_payload_for(v661_report(), verify=Probe(True), corpus_dir=corpus)
    assert init.get("analysis_type") != "dotnet"
    assert "decompiled_source" not in init


def _routed_flags():
    from stages.ghidra import ROUTED_FLAGS
    return ROUTED_FLAGS


@pytest.mark.parametrize("flag", _routed_flags())
def test_every_routed_analyser_hands_over_its_payload_not_only_dotnet(corpus, flag):
    """Production's gate is any ROUTED_FLAGS entry. An eval that checked only
    `dotnet_routed` would read an Office or Go sample's payload nowhere."""
    r = v661_report()
    del r["ghidra"]["dotnet_routed"], r["dotnet_analysis"]
    r["ghidra"][flag] = True
    _, modality, _, read = init_payload_for(r, verify=Probe(True), corpus_dir=corpus)
    assert modality == "unpacked_payload"
    assert read["wrapper_routed_by"] == flag


# --- .NET whose payload must not be chosen -> dotnet wrapper ----------------------

def _labelled_only(**over) -> dict:
    """Only the Formbook payload loaded, and no canonical program: the case where
    a rejected payload leaves nothing but the wrapper."""
    r = v661_report()
    r["ghidra"].pop("project_dir")
    r["ghidra"].pop("program_name")
    r["ghidra"]["analyzed_files"] = [
        _af(FORMBOOK, "shellcode_0_unknown_c95af141eb34", 377, "Formbook Payload", **over)]
    return r


def _assert_wrapper(init, modality, source, read):
    assert modality == "dotnet"
    assert init["analysis_type"] == "dotnet"
    assert "Blackjack" in source
    assert read == {"kind": "dotnet", "wrapper_routed_by": "dotnet_routed"}


def test_a_payload_not_in_its_project_is_never_chosen(corpus):
    """#655: a program its project does not hold would fail every tool call.
    The verifier would say True here; `in_project: false` must win anyway."""
    _assert_wrapper(*init_payload_for(_labelled_only(in_project=False),
                                      verify=Probe(True), corpus_dir=corpus))


@pytest.mark.parametrize("verdict", [False, None], ids=["says_no", "could_not_tell"])
def test_a_payload_the_verifier_does_not_confirm_is_not_chosen(corpus, verdict):
    _assert_wrapper(*init_payload_for(_labelled_only(), verify=Probe(verdict),
                                      corpus_dir=corpus))


def test_a_rejected_label_falls_back_to_the_canonical_program_as_production_does(corpus):
    """Not to the wrapper: production's second preference is the canonical
    program run_ghidra already verified."""
    probe = Probe(lambda name: name != FORMBOOK)
    init, modality, _, read = init_payload_for(v661_report(), verify=probe, corpus_dir=corpus)
    assert modality == "unpacked_payload"
    assert init["program_name"] == BIG_DLL
    assert read["chosen_because"] == "canonical"


# --- old corpus entries -----------------------------------------------------------

def test_an_old_dotnet_corpus_entry_still_reads_its_csharp(tmp_path):
    """Every .NET entry in the corpus today predates #646: `analyzed_files: []`.
    It must keep producing the cell it always produced."""
    old = {**v661_report(), "ghidra": {"triggered": True, "dotnet_routed": True,
                                       "analyzed_files": []}}
    _assert_wrapper(*init_payload_for(old, verify=never, corpus_dir=tmp_path))


def test_an_old_format_routed_payload_resolves_to_the_single_project(tmp_path):
    """No `host_output_dir`, no `in_project`, no `cape_type`: the PE-loader
    layout, one `project/` beside report.json."""
    (tmp_path / "project").mkdir()
    old = {**v661_report(), "ghidra": {
        "triggered": True, "dotnet_routed": True,
        "project_dir": "/opt/pipeline/reports/eval-old/project", "program_name": "p1",
        "analyzed_files": [{"program_name": "p1", "functions_count": 40,
                            "analysis_success": True,
                            "project_dir": "/opt/pipeline/reports/eval-old/project"}]}}
    init, modality, _, read = init_payload_for(old, verify=Probe(True), corpus_dir=tmp_path)
    assert modality == "unpacked_payload"
    assert init["project_dir"] == str(tmp_path / "project")
    assert read["chosen_because"] == "canonical"
    assert read["cape_type"] is None and read["source"] == "dropped_pe"


def test_an_old_format_native_entry_is_unchanged(tmp_path):
    """amadey's shape: top-level project in the corpus, per-file path in a run dir."""
    old = {"ghidra": {"triggered": True, "project_dir": str(tmp_path / "project"),
                      "program_name": "p", "analyzed_files": [
                          {"analysis_success": True, "program_name": "p",
                           "project_dir": "/opt/pipeline/reports/eval-amadey/project"}]}}
    init, modality, source, _ = init_payload_for(old, verify=never, corpus_dir=tmp_path)
    assert init is old["ghidra"] and modality == "native_pe"
    assert source == json.dumps(old["ghidra"])


# --- a corpus missing the project fails loudly -----------------------------------

def test_a_corpus_without_the_chosen_project_fails_the_cell_loudly(tmp_path):
    """Neither reach into the run dir (#631) nor quietly measure the C#."""
    with pytest.raises(CorpusProjectMissing, match="shellcode_0_unknown_c95af141eb34"):
        init_payload_for(v661_report(), verify=Probe(True), corpus_dir=tmp_path)


# --- the re-scorer replays the recorded choice -----------------------------------

def test_a_recorded_payload_is_replayed_without_verifying(corpus):
    live = init_payload_for(v661_report(), verify=Probe(True), corpus_dir=corpus)
    replay = init_payload_for(v661_report(), recorded=live[3])
    assert replay[1:] == live[1:]


def test_a_cell_recorded_before_646_replays_the_wrapper_dispatch():
    _assert_wrapper(*init_payload_for(v661_report(), recorded={}))


# --- run_arm, rebuild, and the scorecard ------------------------------------------

def _run_arm(tmp_path, monkeypatch, report, verify, corpus_dir=None):
    cdir = corpus_dir or tmp_path / "c"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "report.json").write_text(json.dumps(report))
    seen: dict = {}

    def fake_interpret(init, out, *a, **kw):
        seen["init"] = init
        return {"analysis": {"malware_family_guess": "x"}, "usage": {}}
    monkeypatch.setattr(runner, "run_interpret", fake_interpret)
    monkeypatch.setattr(runner, "make_ghidra_verifier", lambda cmd: verify)
    monkeypatch.setattr(runner, "_server_sampling", lambda: {})
    sample = CorpusSample("5b4f596d" + "0" * 56, "formbook", str(cdir))
    seen["cell"] = runner.run_arm(sample, runner_arm(), {}, "/bin/true", "/bin/ghidra")
    seen["result"] = json.loads(
        (runner.cell_out_dir(sample, runner_arm()) / "result.json").read_text())
    return seen


def runner_arm():
    from lamware_eval.arms import resolve_arm
    return resolve_arm("qwen@10")


def test_run_arm_reads_the_payload_and_records_what_it_read(corpus, tmp_path, monkeypatch):
    seen = _run_arm(tmp_path, monkeypatch, v661_report(), Probe(True), corpus_dir=corpus)
    assert seen["init"]["program_name"] == FORMBOOK
    assert seen["init"]["project_dir"].startswith(str(corpus))
    assert seen["result"]["input"] == V661_INPUT
    assert seen["cell"]["modality"] == "unpacked_payload"
    assert seen["cell"]["input"].startswith(f"unpacked_payload:{FORMBOOK[:12]}")
    assert "Formbook Payload" in seen["cell"]["input"]


def test_rebuild_rescores_a_payload_cell_against_the_payload(corpus, tmp_path, monkeypatch):
    """The re-scorer has no Ghidra; it must replay, not fall back to the C#."""
    from lamware_eval.rebuild import rebuild
    _run_arm(tmp_path, monkeypatch, v661_report(), Probe(True), corpus_dir=corpus)
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"samples": [
        {"sha256": "5b4f596d" + "0" * 56, "mb_family": "formbook",
         "corpus_dir": str(corpus)}]}))
    _, cells = rebuild(str(manifest), "t")
    assert [c["modality"] for c in cells] == ["unpacked_payload"]
    assert cells[0]["input_detail"] == V661_INPUT


def test_the_summary_says_when_an_arm_pools_modalities():
    cells = [{"arm": "a", "modality": m, "wall_seconds": 1, "cost_usd": 0,
              "completed": True, "total": 0, "fabricated": []}
             for m in ("dotnet", "unpacked_payload", "unpacked_payload")]
    assert aggregate(cells)["a"]["modalities"] == "dotnet=1,unpacked_payload=2"


# --- imported, not reimplemented (structural) -------------------------------------

def test_the_dispatch_uses_productions_own_functions():
    """Structural, because no behavioural test can tell an import from a faithful
    copy until the copy drifts (#380). The behavioural tests above pin what the
    functions do; this pins that they are production's."""
    src = Path(runner.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    from_ghidra = {a.name for n in ast.walk(tree)
                   if isinstance(n, ast.ImportFrom) and n.module == "stages.ghidra"
                   for a in n.names}
    assert {"select_payload_target", "ROUTED_FLAGS", "make_ghidra_verifier"} <= from_ghidra
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assigned = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
                for t in n.targets if isinstance(t, ast.Name)}
    assert not {"select_payload_target", "make_ghidra_verifier"} & defined
    assert "ROUTED_FLAGS" not in assigned
