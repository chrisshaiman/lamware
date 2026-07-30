# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""#245: re-running an arm must not blend two runs' evidence, or destroy the first.

Cell paths are keyed only by (sample, arm), so a re-run lands on top of the previous run.
`result.json` and the trail were simply overwritten — but `llm_audit/results/NNNN.json` is
numbered PER TOOL CALL and never cleared, so a SHORTER second run left the first run's
higher-numbered files behind.

That is worse than data loss, because `tool_output_text` greps exactly those files to
decide whether a claim is grounded. A claim could be scored against evidence produced by a
different run, and nothing anywhere would say so. It is not a hypothetical: the corrected
scorecard flags `MilcoSoft.dll` as fabricated on one cell for a string known to exist on
that sample.

The forensic angle is the other half. On 2026-07-29 a re-run destroyed the previous run's
#197 trail while a question about that run was still open, making it permanently
unanswerable. The trail has a test proving it survives SIGKILL; it did not survive a
re-run, which is the far more common event.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from lamware_eval.runner import ARCHIVE_DIR, archive_previous_cell  # noqa: E402


def _make_cell(root: Path, *, results: list[str], marker: str) -> Path:
    """A cell as a completed run leaves it."""
    cell = root / "eval" / "qwen_10_s42"
    (cell / "llm_audit" / "results").mkdir(parents=True, exist_ok=True)
    (cell / "result.json").write_text(json.dumps({"marker": marker}))
    (cell / "llm_audit" / "tool_calls.json").write_text(json.dumps([{"result": marker}]))
    (cell / "llm_audit" / "tool_calls.trail.jsonl").write_text('{"event":"tool"}\n')
    for name in results:
        (cell / "llm_audit" / "results" / name).write_text(json.dumps({"from": marker}))
    return cell


def test_a_shorter_rerun_cannot_inherit_the_previous_runs_tool_output(tmp_path):
    """THE BUG. Run 1 makes 21 tool calls, run 2 makes 3.

    Without archiving, 0004..0021 from run 1 remain in the directory the grounding scorer
    reads, and run 2 gets credit for evidence it never saw.
    """
    cell = _make_cell(tmp_path, results=[f"{i:04d}.json" for i in range(1, 22)],
                      marker="RUN_ONE")
    assert len(list((cell / "llm_audit" / "results").iterdir())) == 21

    archive_previous_cell(cell)
    cell.mkdir(parents=True, exist_ok=True)          # what run_arm does next
    _make_cell(tmp_path, results=["0001.json", "0002.json", "0003.json"], marker="RUN_TWO")

    survivors = sorted(p.name for p in (cell / "llm_audit" / "results").iterdir())
    assert survivors == ["0001.json", "0002.json", "0003.json"], (
        f"run one's artifacts leaked into run two: {survivors}")
    for p in (cell / "llm_audit" / "results").iterdir():
        assert json.loads(p.read_text())["from"] == "RUN_TWO"


def test_the_previous_run_is_kept_not_deleted(tmp_path):
    """A forensic trail the next run erases is not forensic."""
    cell = _make_cell(tmp_path, results=["0001.json"], marker="RUN_ONE")
    dest = archive_previous_cell(cell)
    assert dest is not None and dest.exists()
    assert json.loads((dest / "result.json").read_text())["marker"] == "RUN_ONE"
    assert (dest / "llm_audit" / "tool_calls.trail.jsonl").exists(), (
        "the #197 trail must be preserved — losing it is what motivated this")
    assert not cell.exists(), "the live cell must be gone so the next run starts clean"


def test_the_archive_is_named_for_the_run_it_holds(tmp_path):
    """Named from the archived run's OWN mtime, so it is self-describing without
    threading the current label through the runner."""
    cell = _make_cell(tmp_path, results=["0001.json"], marker="RUN_ONE")
    when = time.mktime((2026, 7, 29, 23, 48, 35, 0, 0, -1))
    import os
    os.utime(cell / "result.json", (when, when))
    dest = archive_previous_cell(cell)
    assert dest.name == "qwen_10_s42__20260729-234835", dest.name
    assert dest.parent.name == ARCHIVE_DIR


def test_no_previous_cell_is_a_no_op(tmp_path):
    assert archive_previous_cell(tmp_path / "eval" / "nothing_here") is None


def test_an_empty_cell_directory_is_not_archived(tmp_path):
    """An interrupted run can leave an empty dir; archiving it would litter."""
    empty = tmp_path / "eval" / "qwen_10_s42"
    empty.mkdir(parents=True)
    assert archive_previous_cell(empty) is None


def test_a_same_second_rerun_does_not_explode(tmp_path):
    """Two archives can collide on the timestamp; the newer copy wins rather than
    raising and killing the sweep."""
    cell = _make_cell(tmp_path, results=["0001.json"], marker="RUN_ONE")
    first = archive_previous_cell(cell)
    cell = _make_cell(tmp_path, results=["0001.json"], marker="RUN_TWO")
    import os
    st = (first.stat().st_mtime, first.stat().st_mtime)
    os.utime(cell / "result.json", st)
    second = archive_previous_cell(cell)
    assert second == first
    assert json.loads((second / "result.json").read_text())["marker"] == "RUN_TWO"


def test_rebuild_ignores_the_archive():
    """`rebuild` walks `<corpus>/eval/*`; without a skip it would treat archived runs as
    live arms and double-report superseded cells."""
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "rebuild.py").read_text(encoding="utf-8")
    assert 'arm_dir.name.startswith("_")' in src, (
        "rebuild must skip the archive directory or old runs reappear in the scorecard")


def test_runner_archives_before_it_writes():
    """Order is the whole point: archiving after the run would archive run two."""
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "lamware_eval" / "runner.py").read_text(encoding="utf-8")
    body = src[src.index("def run_arm("):]
    archive_at = body.index("archive_previous_cell(out)")
    mkdir_at = body.index("out.mkdir(")
    run_at = body.index("run_interpret(")
    assert archive_at < mkdir_at < run_at, (
        "the previous cell must be moved aside before the new run creates or writes anything")
