# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Repairing the pre-#490 canonical pairing without repeating #405.

#492 fixed selection at report time; the reports already on disk keep the bad
pairing. This repairs the field in place, which means editing `report.json` —
the exact operation #405 filed a bug about doing carelessly.

So the tests below spend more effort on what the tool must NOT do than on what
it does:

  * never edit on an inconclusive probe — a maybe is not evidence
  * never invent a pairing when nothing opens
  * never write without a backup
  * never write at all unless asked
"""
import json
from pathlib import Path

import pytest

FILES = (Path(__file__).resolve().parents[2]
         / "ansible" / "roles" / "pipeline" / "files")

ABSENT = "890a9fdf8216f97142c6f96545cc2e1026dcef80b81c947d63cf28932f0d5697"
PRESENT = "91ed576cc595105bc63f853bb46a7218a6f106cc3f9c9634b2a8e309186e1a88"


@pytest.fixture
def mod():
    import repair_ghidra_pairing
    return repair_ghidra_pairing


def _report(corpus: Path, task_dir="/opt/pipeline/reports/postdns-1"):
    """A report shaped like the real broken ones: the canonical names the
    18143-function analysis, and the project holds the 11252-function one."""
    return {
        "ghidra": {
            "triggered": True,
            "project_dir": str(corpus / "project"),
            "program_name": ABSENT,
            "analyzed_files": [
                {"analysis_success": True, "program_name": PRESENT,
                 "functions_count": 11252, "host_output_dir": task_dir},
                {"analysis_success": True, "program_name": ABSENT,
                 "functions_count": 18143, "host_output_dir": task_dir},
            ],
        }
    }


def _verifier(openable, inconclusive=()):
    def verify(project, program):
        if program in inconclusive:
            return None
        return program in openable
    return verify


# --- diagnosis ---


def test_a_broken_pairing_is_repaired_to_the_program_that_opens(tmp_path, mod):
    r = _report(tmp_path)
    out = mod.diagnose(r, tmp_path / "report.json", _verifier({PRESENT}))
    assert out["status"] == "repaired"
    assert out["new"][1] == PRESENT
    assert out["functions"] == 11252


def test_a_working_pairing_is_left_alone(tmp_path, mod):
    r = _report(tmp_path)
    out = mod.diagnose(r, tmp_path / "report.json", _verifier({ABSENT, PRESENT}))
    assert out["status"] == "ok"


def test_nothing_openable_is_not_repaired_into_a_guess(tmp_path, mod):
    """Inventing a pairing would be a worse answer than the true one, and the
    true one is "this report needs re-analysis"."""
    r = _report(tmp_path)
    out = mod.diagnose(r, tmp_path / "report.json", _verifier(set()))
    assert out["status"] == "unopenable"
    assert "new" not in out


def test_an_inconclusive_probe_never_triggers_an_edit(tmp_path, mod):
    """A probe that could not answer is not evidence the stored pairing is
    wrong. Editing on a maybe is worse than the defect being repaired."""
    r = _report(tmp_path)
    out = mod.diagnose(r, tmp_path / "report.json",
                       _verifier(set(), inconclusive={ABSENT, PRESENT}))
    assert out["status"] == "unverified"
    assert "new" not in out


def test_the_best_openable_candidate_wins_not_merely_a_different_one(tmp_path, mod):
    r = _report(tmp_path)
    r["ghidra"]["analyzed_files"].append(
        {"analysis_success": True, "program_name": "tiny", "functions_count": 3,
         "host_output_dir": "/opt/pipeline/reports/postdns-1"})
    out = mod.diagnose(r, tmp_path / "report.json", _verifier({PRESENT, "tiny"}))
    assert out["new"][1] == PRESENT


def test_a_report_without_ghidra_is_not_touched(tmp_path, mod):
    assert mod.diagnose({}, tmp_path / "report.json",
                        _verifier({PRESENT}))["status"] == "no_ghidra"
    assert mod.diagnose({"ghidra": {"triggered": False}}, tmp_path / "report.json",
                        _verifier({PRESENT}))["status"] == "no_ghidra"


def test_failed_analyses_are_not_candidates(tmp_path, mod):
    r = _report(tmp_path)
    for af in r["ghidra"]["analyzed_files"]:
        af["analysis_success"] = False
    assert mod.diagnose(r, tmp_path / "report.json",
                        _verifier({PRESENT}))["status"] == "unopenable"


# --- where it looks for the project ---


def test_the_project_beside_the_report_is_tried_first(tmp_path, mod):
    """A corpus entry carries a copy of the project next to report.json, while
    host_output_dir still names a task directory cleanup.sh deletes after 7
    days. Trying the neighbour first is what lets a corpus sample repair at
    all once the original is gone."""
    af = {"host_output_dir": "/opt/pipeline/reports/postdns-1"}
    paths = mod.candidate_projects(tmp_path / "report.json", af, "/stored/project")
    assert paths[0] == str(tmp_path / "project")
    assert "/opt/pipeline/reports/postdns-1/project" in paths
    assert "/stored/project" in paths


def test_candidate_paths_are_not_repeated(tmp_path, mod):
    af = {"host_output_dir": str(tmp_path)}
    paths = mod.candidate_projects(tmp_path / "report.json", af,
                                   str(tmp_path / "project"))
    assert len(paths) == len(set(paths)) == 1


def test_a_pairing_is_found_in_a_sibling_project_the_stored_path_missed(tmp_path, mod):
    """The program opens, just not where the report said it was."""
    task = tmp_path / "task"
    r = _report(tmp_path, task_dir=str(task))
    r["ghidra"]["project_dir"] = "/gone/project"

    def verify(project, program):
        return project == str(task / "project") and program == PRESENT

    out = mod.diagnose(r, tmp_path / "report.json", verify)
    assert out["status"] == "repaired"
    assert out["new"] == (str(task / "project"), PRESENT)


# --- writing ---


def test_the_original_is_backed_up_before_anything_is_written(tmp_path, mod):
    path = tmp_path / "report.json"
    original = _report(tmp_path)
    path.write_text(json.dumps(original))
    result = mod.diagnose(json.loads(path.read_text()), path, _verifier({PRESENT}))

    backup = mod.apply_repair(path, json.loads(path.read_text()), result)
    assert backup.exists()
    assert json.loads(backup.read_text())["ghidra"]["program_name"] == ABSENT
    assert json.loads(path.read_text())["ghidra"]["program_name"] == PRESENT


def test_a_second_run_does_not_overwrite_the_first_backup(tmp_path, mod):
    """Running it twice must not leave the backup holding an already-repaired
    report — that is the same "no way to tell what it destroyed" as #405."""
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(tmp_path)))
    result = mod.diagnose(json.loads(path.read_text()), path, _verifier({PRESENT}))
    mod.apply_repair(path, json.loads(path.read_text()), result)
    mod.apply_repair(path, json.loads(path.read_text()), result)
    backup = path.with_suffix(".json.pre-490")
    assert json.loads(backup.read_text())["ghidra"]["program_name"] == ABSENT


def test_the_report_records_what_was_done_to_it(tmp_path, mod):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(tmp_path)))
    result = mod.diagnose(json.loads(path.read_text()), path, _verifier({PRESENT}))
    mod.apply_repair(path, json.loads(path.read_text()), result)

    warnings = json.loads(path.read_text())["ghidra"]["analysis_warnings"]
    joined = " ".join(warnings)
    assert "#490" in joined
    assert ABSENT[:16] in joined and PRESENT[:16] in joined


def test_the_warning_is_not_duplicated_on_a_repeat_run(tmp_path, mod):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(tmp_path)))
    for _ in range(3):
        r = json.loads(path.read_text())
        result = mod.diagnose(r, path, _verifier({PRESENT}))
        if result["status"] == "repaired":
            mod.apply_repair(path, r, result)
    warnings = json.loads(path.read_text())["ghidra"]["analysis_warnings"]
    assert len([w for w in warnings if "#490" in w]) == 1


def test_a_dry_run_writes_nothing(tmp_path, mod, capsys, monkeypatch):
    path = tmp_path / "report.json"
    before = json.dumps(_report(tmp_path))
    path.write_text(before)
    monkeypatch.setattr(mod, "make_ghidra_verifier",
                        lambda cmd, **kw: _verifier({PRESENT}))
    monkeypatch.setattr("sys.argv", ["repair", str(path)])

    assert mod.main() == 0
    assert path.read_text() == before, "dry run modified the report"
    assert not path.with_suffix(".json.pre-490").exists()
    out = capsys.readouterr().out
    assert "would repair" in out
    assert "--apply" in out


def test_apply_writes_and_says_so(tmp_path, mod, capsys, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(tmp_path)))
    monkeypatch.setattr(mod, "make_ghidra_verifier",
                        lambda cmd, **kw: _verifier({PRESENT}))
    monkeypatch.setattr("sys.argv", ["repair", "--apply", str(path)])

    assert mod.main() == 0
    assert json.loads(path.read_text())["ghidra"]["program_name"] == PRESENT
    assert "REPAIRED" in capsys.readouterr().out


def test_an_unreadable_report_does_not_stop_the_others(tmp_path, mod, capsys,
                                                       monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    good = good_dir / "report.json"
    good.write_text(json.dumps(_report(good_dir)))
    monkeypatch.setattr(mod, "make_ghidra_verifier",
                        lambda cmd, **kw: _verifier({PRESENT}))
    monkeypatch.setattr("sys.argv", ["repair", "--apply", str(bad), str(good)])

    assert mod.main() == 0
    assert json.loads(good.read_text())["ghidra"]["program_name"] == PRESENT
    assert "read-fail" in capsys.readouterr().out
