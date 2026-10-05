# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A native-PE eval cell must start from the card production's agent starts from (#697).

Observed on the host (2026-10-04): the first request of every native eval cell
was byte-identical across amadey, rhadamanthys and emotet. The eval handed the
agent `report["ghidra"]` — the wrapper (`analyzed_files`, `program_name`,
`project_dir`) — and `build_initial_message` reads `sha256`, `imports`,
`strings_of_interest` and `decompiled_functions` at the TOP level of its input,
where only an `analyzed_files[i]` entry has them. Every native cell opened on
"SHA256: unknown ... Analyze this binary". Production's Stage 4.5 sends
`select_native_target(ghidra_data)`, the file entry.

Behavioural: the first message is rendered by the real `build_initial_message`,
imported from the container script, from what `init_payload_for` returns.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from lamware_eval import runner
from lamware_eval.corpus import CorpusSample
from lamware_eval.metrics import input_label
from lamware_eval.runner import NoAnalysisData, init_payload_for
from stages.ghidra import native_input_record, select_native_target
from stages.interpret import without_host_paths

SCRIPT = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "interpret"
          / "files" / "interpret-ghidra.py")

RUN = "/opt/pipeline/reports/r_amadey_573e6860"
ORIGINAL = "a" * 64
CANONICAL = "c" * 64
IMPORT = "WININET.DLL::InternetOpenUrlA"
STRING = "http://c2.invalid/gate.php"
FUNCTION = "FUN_00401a2c"


def _file(name, sub, fns, **kw):
    return {"program_name": name, "sha256": name, "functions_count": fns,
            "analysis_success": True, "in_project": True, "source": None,
            "project_dir": f"{RUN}/{sub}/project", "host_output_dir": f"{RUN}/{sub}",
            "entry_point": "entry", "imports": [], "strings_of_interest": [],
            "decompiled_functions": [], **kw}


def native_report() -> dict:
    """A native report in the post-#649 shape: the submitted sample FIRST in the
    list, the canonical (ranked, verified) program second. List position and
    canonical disagree, so a selector that read position would be caught."""
    return {"ghidra": {
        "triggered": True, "original_sample_included": True,
        "project_dir": f"{RUN}/shellcode_0_unknown_cccccccccccc/project",
        "program_name": CANONICAL,
        "analyzed_files": [
            _file(ORIGINAL, "pe_aaaaaaaaaaaa", 12, imports=["KERNEL32.DLL::ExitProcess"]),
            _file(CANONICAL, "shellcode_0_unknown_cccccccccccc", 377,
                  source="cape_payload", cape_type="Amadey Payload",
                  imports=[IMPORT, "KERNEL32.DLL::VirtualAlloc"],
                  strings_of_interest=[STRING],
                  decompiled_functions=[{"name": FUNCTION, "address": "00401a2c",
                                         "pseudocode": "void FUN_00401a2c(void) {}"}]),
        ],
    }}


@pytest.fixture
def corpus(tmp_path) -> Path:
    d = tmp_path / "amadey_573e6860"
    for f in native_report()["ghidra"]["analyzed_files"]:
        (d / Path(f["host_output_dir"]).name / "project").mkdir(parents=True)
    return d


@pytest.fixture(scope="module")
def build_initial_message():
    """The container's own renderer. Imported, not re-stated: the defect was a
    mismatch between what the eval sent and what THIS function reads."""
    name = "_interpret_ghidra_697"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
        yield lambda payload: mod.build_initial_message(payload, mod.DEFAULT_CONFIG)
    finally:
        sys.modules.pop(name, None)


def test_the_native_first_message_carries_the_card(corpus, build_initial_message):
    """THE bug. Mutation-tested: with the native branch reverted to returning
    `report["ghidra"]`, this renders `SHA256: \\`unknown\\`` and fails."""
    init, modality, _, _ = init_payload_for(native_report(), corpus_dir=corpus)
    assert modality == "native_pe"
    # What run_interpret actually ships to the container (host paths removed).
    msg = build_initial_message(without_host_paths(init))
    assert f"SHA256: `{CANONICAL}`" in msg, msg[:400]
    assert IMPORT in msg
    assert STRING in msg
    assert FUNCTION in msg
    assert "unknown" not in msg.split("## Imports")[0]


def test_the_wrapper_renders_blind(build_initial_message):
    """Control: proves the renderer distinguishes the two inputs, so the test
    above is not passing on a message that would carry the card anyway."""
    msg = build_initial_message(without_host_paths(native_report()["ghidra"]))
    assert "SHA256: `unknown`" in msg
    assert IMPORT not in msg and STRING not in msg


def test_the_eval_sends_what_production_stage_4_5_sends(corpus):
    """Same report, same selector output. Production hands `run_interpret`
    `select_native_target(ghidra_data)[0]`; the eval hands it the same entry,
    with only `project_dir` rebased onto the corpus copy."""
    report = native_report()
    prod_target, prod_reason = select_native_target(report["ghidra"])
    assert prod_target["program_name"] == CANONICAL and prod_reason == "canonical"

    init, _, source, read = init_payload_for(report)
    assert init == prod_target, "without a corpus dir the init is production's entry"

    init, _, source, read = init_payload_for(report, corpus_dir=corpus)
    assert {k: v for k, v in init.items() if k != "project_dir"} == \
        {k: v for k, v in prod_target.items() if k != "project_dir"}
    assert init["project_dir"] == str(corpus / "shellcode_0_unknown_cccccccccccc" / "project")
    assert json.loads(source) == without_host_paths(prod_target)
    assert read == {**native_input_record(report["ghidra"], prod_target, prod_reason),
                    "kind": "native_pe", "wrapper_routed_by": None}
    assert read["chosen_because"] == "canonical"


def test_the_grounding_is_the_entry_not_every_analysed_file(corpus):
    """The agent saw one file's card. The other file's import must not ground
    a claim (the wrapper grounded against every analysed file)."""
    _, _, source, _ = init_payload_for(native_report(), corpus_dir=corpus)
    assert IMPORT in source
    assert "KERNEL32.DLL::ExitProcess" not in source


def test_a_report_without_a_canonical_match_records_the_fallback(corpus):
    report = native_report()
    report["ghidra"]["program_name"] = "not-in-the-list"
    init, _, _, read = init_payload_for(report, corpus_dir=corpus)
    assert init["program_name"] == ORIGINAL
    assert read["chosen_because"] == "first_success_fallback"
    assert read["source"] == "original_sample"
    assert input_label(read) == f"native_pe:{ORIGINAL[:12]} (unlabelled, first_success_fallback)"


def test_no_successful_file_fails_the_cell_as_production_skips_it():
    """Stage 4.5 records no_analysis_data and sends nothing; the eval must not
    measure an agent on a sample production never interprets."""
    report = native_report()
    for f in report["ghidra"]["analyzed_files"]:
        f["analysis_success"] = False
    with pytest.raises(NoAnalysisData, match="no_analysis_data"):
        init_payload_for(report)


def test_the_legacy_corpus_layout_keeps_its_working_project(tmp_path):
    """A hand-refreshed corpus entry: the top-level project points into the
    corpus (#631), the per-file host_output_dir names a run dir never copied.
    The canonical file's project is the top-level one."""
    report = native_report()
    report["ghidra"]["project_dir"] = str(tmp_path / "project")
    (tmp_path / "project").mkdir()
    init, _, _, _ = init_payload_for(report, corpus_dir=tmp_path)
    assert init["program_name"] == CANONICAL
    assert init["project_dir"] == str(tmp_path / "project")


def test_an_n_a_injection_address_subdir_finds_its_corpus_project(tmp_path):
    """latrodectus_d22c9656 and salat_d26bc055 on the host: the loader wrote
    `shellcode_0_N/A/` (address "N/A"), the top-level project_dir points at the
    run directory, and the corpus copy is `shellcode_0_N/A/project`. Matching on
    the last component alone looked for `A/project` and failed the cell."""
    report = native_report()
    canon = report["ghidra"]["analyzed_files"][1]
    canon["host_output_dir"] = f"{RUN}/shellcode_0_N/A"
    canon["project_dir"] = f"{RUN}/shellcode_0_N/A/project"
    report["ghidra"]["project_dir"] = canon["project_dir"]
    (tmp_path / "shellcode_0_N" / "A" / "project").mkdir(parents=True)
    (tmp_path / "pe_aaaaaaaaaaaa" / "project").mkdir(parents=True)
    init, _, _, read = init_payload_for(report, corpus_dir=tmp_path)
    assert read["chosen_because"] == "canonical"
    assert init["project_dir"] == str(tmp_path / "shellcode_0_N" / "A" / "project")


def test_a_missing_multi_part_project_still_refuses(tmp_path):
    """The wider match must not turn a genuinely absent copy into a pass."""
    report = native_report()
    canon = report["ghidra"]["analyzed_files"][1]
    canon["host_output_dir"] = f"{RUN}/shellcode_0_N/A"
    report["ghidra"]["project_dir"] = f"{RUN}/shellcode_0_N/A/project"
    with pytest.raises(runner.CorpusProjectMissing):
        init_payload_for(report, corpus_dir=tmp_path)


def test_run_arm_sends_the_entry_and_rebuild_replays_it(corpus, tmp_path, monkeypatch):
    (corpus / "report.json").write_text(json.dumps(native_report()))
    seen = {}

    def fake_interpret(init, out, *a, **kw):
        seen["init"] = init
        return {"analysis": {"malware_family_guess": "x"}, "usage": {}}
    monkeypatch.setattr(runner, "run_interpret", fake_interpret)
    monkeypatch.setattr(runner, "make_ghidra_verifier", lambda cmd: None)
    monkeypatch.setattr(runner, "_server_sampling", lambda: {})
    from lamware_eval.arms import resolve_arm
    sample = CorpusSample("573e6860" + "0" * 56, "amadey", str(corpus))
    cell = runner.run_arm(sample, resolve_arm("qwen@10"), {}, "/bin/true", "/bin/true")
    assert seen["init"]["sha256"] == CANONICAL
    assert seen["init"]["project_dir"].startswith(str(corpus))
    assert cell["input"].startswith(f"native_pe:{CANONICAL[:12]}")

    from lamware_eval.rebuild import rebuild
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps({"samples": [
        {"sha256": sample.sha256, "mb_family": "amadey", "corpus_dir": str(corpus)}]}))
    _, cells = rebuild(str(manifest), "t")
    assert [c["modality"] for c in cells] == ["native_pe"]
    assert cells[0]["input_detail"]["program_name"] == CANONICAL


def test_a_cell_recorded_before_697_replays_the_wrapper_it_was_sent():
    """Those cells were sent the wrapper; re-scoring them must not pretend
    otherwise. They measured a blind-start agent and need a re-baseline."""
    report = native_report()
    for recorded in ({}, {"kind": "native_pe", "wrapper_routed_by": None}):
        init, modality, source, read = init_payload_for(report, recorded=recorded)
        assert init is report["ghidra"] and modality == "native_pe"
        assert read == {"kind": "native_pe", "wrapper_routed_by": None}


def test_promotion_refuses_a_sample_production_would_not_interpret(tmp_path):
    """promote.leak_check calls init_payload_for; a sample with no successful
    file is refused rather than promoted and measured blind."""
    from lamware_eval.promote import leak_check
    report = native_report()
    for f in report["ghidra"]["analyzed_files"]:
        f["analysis_success"] = False
    _leak, refusals = leak_check(report, "amadey", tmp_path / "amadey_573e6860")
    assert any("would read nothing" in r for r in refusals), refusals
