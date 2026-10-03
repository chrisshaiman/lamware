# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Promoting a report into the eval corpus copies what the eval reads, and only that.

The corpus was grown by hand on the host until now, and the hand copy broke it
three ways the other corpus tests remember: a report copied without its project,
pointing at a run dir the cleanup cron later deleted (#631); a pre-#490 project
whose canonical program was not in it; and a label leak (#634). Since #648/#655 a
report has one project per program, so the old two-item copy is also the wrong
shape. These tests build a report dir in that shape and promote it for real.
"""
import json
import os
from pathlib import Path

import pytest
from lamware_eval import promote as P
from lamware_eval.arms import Arm
from lamware_eval.corpus import load_corpus

SHA = "5b4f596d3cf54c94c57934ccc75e31d7f5999df9abb1b77ff6f8cff007da8d74"
PE = "a314d7708b70a681c0a56334a04387fadee8f65ddd396c9543125a9d0ba4aaff"
SC = "d4ae5a9fae8963f9fad9b501c0a8a864b490b69f0c7be3ea5a2198ff0efe080a"
LOST = "8c38731c203b0743c040a8d986b5ef8bb8bb4a8b550cb99cb70e953fd8012398"


def _project(root: Path, *names: str) -> Path:
    """A per-program dir holding a Ghidra project whose index lists `names`."""
    idata = root / "project" / "analysis.rep" / "idata"
    idata.mkdir(parents=True)
    lines = ["VERSION=1", "/"] + [f"  0000000{i}:{n}:7f00{i}" for i, n in enumerate(names)]
    (idata / "~index.dat").write_text("\n".join(lines + ["NEXT-ID:9", "MD5:x"]) + "\n")
    (root / "project" / "analysis.gpr").write_text("")
    (idata / "00").mkdir()
    (idata / "00" / "00000000.prp").write_bytes(b"program bytes")
    return root


@pytest.fixture
def report_dir(tmp_path) -> Path:
    """The shape of /opt/pipeline/reports/v661_5b4f596d3cf5 on 2026-10-02, reduced."""
    rd = tmp_path / "reports" / "v661_5b4f596d3cf5"
    rd.mkdir(parents=True)
    pe_dir = _project(rd / f"pe_{PE[:12]}", PE)
    sc_dir = _project(rd / f"shellcode_0_unknown_{SC[:12]}", SC)
    lost_dir = _project(rd / f"shellcode_0_unknown_{LOST[:12]}", "something-else")
    (rd / "cape_injections").mkdir()
    (rd / "cape_injections" / "inject.bin").write_bytes(b"\x90")
    (rd / "vol_vadinfo").mkdir()
    report = {
        "triage": {"hashes": {"sha256": SHA}},
        "sample": f"/opt/pipeline/eval-samples/{SHA}.bin",
        "cape": {"signatures": [{"name": "injection_rwx"}],
                 "injection_buffers": [{"path": str(rd / "cape_injections" / "inject.bin")}]},
        "volatility": {"vad_dump_dir": str(rd / "vol_vadinfo")},
        "ghidra": {
            "triggered": True,
            "project_dir": str(sc_dir / "project"),
            "program_name": SC,
            "analyzed_files": [
                {"program_name": PE, "analysis_success": True, "in_project": True,
                 "functions_count": 163, "project_dir": str(pe_dir / "project"),
                 "host_output_dir": str(pe_dir)},
                {"program_name": SC, "analysis_success": True, "in_project": True,
                 "functions_count": 4064, "project_dir": str(sc_dir / "project"),
                 "host_output_dir": str(sc_dir)},
                # The pipeline already knows this one is lost (#655): not promoted.
                {"program_name": LOST, "analysis_success": True, "in_project": False,
                 "functions_count": 7, "project_dir": str(lost_dir / "project"),
                 "host_output_dir": str(lost_dir)},
                {"program_name": None, "analysis_success": False, "source": "cape_injection"},
            ],
        },
        "llm_interpretation": {
            "input": {"kind": "unpacked_payload", "program_name": SC},
            "audit": {"tool_call_log": str(rd / "llm_audit" / "tool_calls.json")},
            "analysis": {"malware_family_guess": "Formbook"},
        },
    }
    (rd / "report.json").write_text(json.dumps(report))
    return rd


def _promote(rd: Path, tmp_path: Path, **kw):
    kw.setdefault("family", "formbook")
    return P.promote(rd, corpus_root=tmp_path / "eval-corpus",
                     manifest=tmp_path / "corpus.json", **kw)


def _strings(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def test_promotion_lays_out_one_project_per_program(report_dir, tmp_path):
    r = _promote(report_dir, tmp_path)
    dest = tmp_path / "eval-corpus" / "formbook_5b4f596d"
    assert r.dest == dest
    assert sorted(p.name for p in dest.iterdir()) == [
        "pe_a314d7708b70", "report.json", "shellcode_0_unknown_d4ae5a9fae89"]
    for sub, prog in ((f"pe_{PE[:12]}", PE), (f"shellcode_0_unknown_{SC[:12]}", SC)):
        assert P._project_programs(dest / sub / "project") == {prog}
    assert {p.name for p in r.programs} == {PE, SC}


def test_no_path_into_the_old_report_dir_survives(report_dir, tmp_path):
    r = _promote(report_dir, tmp_path)
    text = (r.dest / "report.json").read_text()
    assert str(report_dir) not in text
    report = json.loads(text)
    g = report["ghidra"]
    assert g["project_dir"] == str(r.dest / f"shellcode_0_unknown_{SC[:12]}" / "project")
    pe = g["analyzed_files"][0]
    assert pe["project_dir"] == str(r.dest / f"pe_{PE[:12]}" / "project")
    assert pe["host_output_dir"] == str(r.dest / f"pe_{PE[:12]}")
    # Every rewritten path must exist: a path into the corpus that does not
    # resolve is the #631 failure with a new prefix.
    for s in _strings(report):
        if s.startswith(str(r.dest)):
            assert Path(s).exists(), s
    # What was not copied is nulled and accounted for, not pointed at nothing.
    assert report["cape"]["injection_buffers"][0]["path"] is None
    assert report["volatility"]["vad_dump_dir"] is None
    assert report["llm_interpretation"]["audit"]["tool_call_log"] is None
    assert report["_corpus_promotion"]["unpromoted"][".volatility.vad_dump_dir"] == "vol_vadinfo"
    # The program pipeline knew was lost keeps a path to nowhere: nulled too.
    assert g["analyzed_files"][2]["project_dir"] is None


def test_a_program_missing_from_its_index_aborts(report_dir, tmp_path):
    # in_project says true, the index says otherwise: #490's exact shape.
    idx = report_dir / f"pe_{PE[:12]}" / "project" / "analysis.rep" / "idata" / "~index.dat"
    idx.write_text(idx.read_text().replace(PE, "some-other-program"))
    with pytest.raises(P.PromotionError, match="missing from their project index"):
        _promote(report_dir, tmp_path)
    assert not (tmp_path / "eval-corpus" / "formbook_5b4f596d").exists()
    assert not (tmp_path / "corpus.json").exists()


def test_the_program_production_read_must_be_promotable(report_dir, tmp_path):
    report = json.loads((report_dir / "report.json").read_text())
    report["llm_interpretation"]["input"]["program_name"] = LOST
    (report_dir / "report.json").write_text(json.dumps(report))
    with pytest.raises(P.PromotionError, match="production's agent read"):
        _promote(report_dir, tmp_path)


def test_a_report_whose_evidence_names_its_family_is_refused(report_dir, tmp_path):
    report = json.loads((report_dir / "report.json").read_text())
    report["cape"]["signatures"].append({"name": "formbook_c2", "description": "Formbook"})
    (report_dir / "report.json").write_text(json.dumps(report))
    with pytest.raises(P.PromotionError, match="evidence names the family"):
        _promote(report_dir, tmp_path)
    assert not (tmp_path / "eval-corpus" / "formbook_5b4f596d").exists()
    # The same report under a different label is not a leak.
    assert _promote(report_dir, tmp_path, family="xloader").leak is False


def test_an_existing_corpus_dir_is_never_overwritten_and_replace_archives(report_dir, tmp_path):
    first = _promote(report_dir, tmp_path)
    (first.dest / "eval").mkdir()
    (first.dest / "eval" / "cell.json").write_text("{}")
    with pytest.raises(P.PromotionError, match="--replace"):
        _promote(report_dir, tmp_path)

    import datetime as dt
    when = dt.datetime(2026, 10, 2, 1, 2, 3, tzinfo=dt.UTC)
    second = _promote(report_dir, tmp_path, replace=True, now=when)
    archived = tmp_path / "eval-corpus" / "archive" / "formbook_5b4f596d.20261002T010203Z"
    assert second.archived == archived
    assert (archived / "eval" / "cell.json").exists(), "the old corpus dir was not kept"
    assert (second.dest / "report.json").exists()
    assert not (second.dest / "eval").exists()


def test_a_symlink_in_a_project_is_not_followed(report_dir, tmp_path):
    secret = tmp_path / "host-secret"
    secret.write_text("root:x:0:0")
    link = report_dir / f"pe_{PE[:12]}" / "project" / "analysis.rep" / "passwd"
    link.symlink_to(secret)
    with pytest.raises(P.PromotionError, match="refusing to follow symlink"):
        _promote(report_dir, tmp_path)
    corpus = tmp_path / "eval-corpus"
    copied = [p for p in corpus.rglob("*") if p.is_file()] if corpus.exists() else []
    assert not any(p.read_bytes() == secret.read_bytes() for p in copied), copied
    assert not (corpus / "formbook_5b4f596d").exists()
    assert not [p for p in corpus.iterdir() if p.name.startswith(".promote-")], \
        "a refused promotion left its staging dir behind"


def test_a_symlinked_project_directory_is_not_followed(report_dir, tmp_path):
    outside = _project(tmp_path / "outside", PE)
    pe = report_dir / f"pe_{PE[:12]}"
    import shutil
    shutil.rmtree(pe / "project")
    (pe / "project").symlink_to(outside / "project")
    with pytest.raises(P.PromotionError, match="refusing to follow symlink"):
        _promote(report_dir, tmp_path)


def test_dry_run_writes_nothing(report_dir, tmp_path):
    r = _promote(report_dir, tmp_path, dry_run=True)
    assert r.dry_run and {p.name for p in r.programs} == {PE, SC}
    assert not (tmp_path / "eval-corpus" / "formbook_5b4f596d").exists()
    assert not (tmp_path / "corpus.json").exists()


def test_manifest_entry_is_added_then_updated_in_place(report_dir, tmp_path):
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps({"_selection": {"why": "kept"}, "samples": [
        {"sha256": SHA, "mb_family": "old", "corpus_dir": "/x", "role": "positive"}]}))
    _promote(report_dir, tmp_path)
    data = json.loads(manifest.read_text())
    assert data["_selection"] == {"why": "kept"}
    (entry,) = data["samples"]
    assert entry["mb_family"] == "formbook" and entry["role"] == "positive"
    (sample,) = load_corpus(str(manifest))
    assert sample.corpus_dir == str(tmp_path / "eval-corpus" / "formbook_5b4f596d")
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".corpus.json.")]


def test_the_runner_reads_the_promoted_report(report_dir, tmp_path, monkeypatch):
    """run_arm, given the manifest entry, must hand the tool broker a project that
    exists in the corpus and holds the program it names."""
    from lamware_eval import runner
    _promote(report_dir, tmp_path)
    (sample,) = load_corpus(str(tmp_path / "corpus.json"))

    report = json.loads((Path(sample.corpus_dir) / "report.json").read_text())
    init, modality, _, _ = runner.init_payload_for(report)
    assert modality == "native_pe"
    assert Path(init["project_dir"]).is_relative_to(sample.corpus_dir)
    assert init["program_name"] in P._project_programs(Path(init["project_dir"]))

    seen = {}

    def fake_interpret(init, out, *a, **k):
        seen["init"] = init
        return {"analysis": {}, "usage": {}}

    monkeypatch.setattr(runner, "run_interpret", fake_interpret)
    runner.run_arm(sample, Arm("t", "claude-sonnet-5", None, 1), {}, "/bin/true", "/bin/true")
    assert seen["init"]["project_dir"] == init["project_dir"]
    assert seen["init"]["program_name"] == SC


def test_the_cli_refuses_with_a_nonzero_exit(report_dir, tmp_path, capsys):
    rc = P.main([str(report_dir), "--family", "Form/book",
                 "--corpus-root", str(tmp_path / "c")])
    assert rc == 1 and "REFUSED" in capsys.readouterr().err
    # `$` matches before a trailing newline; the family becomes a directory name.
    rc = P.main([str(report_dir), "--family", "formbook\n",
                 "--corpus-root", str(tmp_path / "c")])
    assert rc == 1 and "REFUSED" in capsys.readouterr().err
    rc = P.main([str(report_dir), "--family", "formbook", "--corpus-root",
                 str(tmp_path / "c"), "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0 and "paths rewritten: " in out and "leak check (#634): clean" in out
    assert not os.path.exists(tmp_path / "c" / "formbook_5b4f596d")


def test_a_surviving_old_path_refuses_the_promotion(report_dir, tmp_path):
    """A sibling dir sharing the run's name as a prefix is not inside it, so it
    is neither rewritten nor nulled, and it still names the old run. The final
    sweep has to catch it rather than let it into the corpus."""
    report = json.loads((report_dir / "report.json").read_text())
    report["pcap_analysis"] = {"note": f"see {report_dir}_rerun/pcap"}
    (report_dir / "report.json").write_text(json.dumps(report))
    with pytest.raises(P.PromotionError, match="survive the rewrite"):
        _promote(report_dir, tmp_path)


def test_a_family_labelled_payload_is_recorded_not_refused():
    """#670, owner's choice: a program the agent may read that carries CAPE's
    family label ("Formbook Payload") is promoted and FLAGGED, so the scorecard
    can report clean and labelled cells separately. Refusing or redacting it
    would hide what production actually reads."""
    from lamware_eval.promote import agent_input_names_family
    labelled = {"ghidra": {"analyzed_files": [
        {"program_name": "c95af141", "cape_type": "Formbook Payload",
         "process": "cape_Formbook Payload", "host_output_dir": "/x/formbook_5b4f/p"}]}}
    plain = {"ghidra": {"analyzed_files": [
        {"program_name": "573e6860", "cape_type": None, "process": "cape_unknown"}]}}
    assert agent_input_names_family(labelled, "formbook") is True
    assert agent_input_names_family(plain, "amadey") is False
    # A family named only inside a host path is #669's problem, not a label the
    # agent sees: without_host_paths strips it before this check looks.
    pathonly = {"ghidra": {"analyzed_files": [
        {"program_name": "x", "project_dir": "/opt/pipeline/eval-corpus/emotet_591d/p/project",
         "host_output_dir": "/opt/pipeline/eval-corpus/emotet_591d/p"}]}}
    assert agent_input_names_family(pathonly, "emotet") is False
