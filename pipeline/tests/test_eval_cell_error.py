# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A re-scored cell must report the same failure the live sweep did.

`rebuild` passed `analysis["parse_note"]` as `compose_cell`'s `error` argument.
The live sweep builds it from the run's actual error, with the container's
stderr tail appended:

    err = res.get("error") or analysis.get("error")
    if err and stderr_tail: err = f"{err} | container stderr: ..."

`res` is in scope in `rebuild` — it is read from `result.json` a few lines
above — so both sources were available and simply unused. The two paths
therefore disagreed about the same cell:

    run failed, container stderr present:
      live    -> 'container exited without final result | container stderr: ...'
      rebuild -> 'recovered JSON from a markdown fence'

    run timed out, no parse note:
      live    -> 'CAPE task timed out'
      rebuild -> None

`compose_cell` stores the value verbatim and the scorecard renders it as a
column, so a re-score showed a benign parse note where the failure cause
belongs, or blanked the column entirely. `parse_note` is already carried as the
`parse_failed` metric, so it was double-reported in the wrong field while the
real error was dropped.

The comment directly above that call says the tool metrics are shared with the
live path "so a re-score cannot disagree with the sweep that produced the cell
(#380)". The composition is now shared for the same reason.
"""
import ast
from pathlib import Path

from lamware_eval.metrics import cell_error

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval"
RUNNER = (EVAL / "runner.py").read_text(encoding="utf-8")
REBUILD = (EVAL / "rebuild.py").read_text(encoding="utf-8")


def test_a_real_failure_survives_a_rescore():
    """THE bug. The cause must not be replaced by an unrelated note."""
    res = {"error": "container exited without final result",
           "container_stderr": "ghidra: OutOfMemoryError",
           "analysis": {"parse_note": "recovered JSON from a markdown fence"}}
    out = cell_error(res, res["analysis"])
    assert "container exited without final result" in out
    assert "OutOfMemoryError" in out
    assert "markdown fence" not in out, "the parse note displaced the failure cause"


def test_a_failure_without_a_parse_note_is_not_blanked():
    """The worse half: no parse_note meant the error column went empty."""
    assert cell_error({"error": "CAPE task timed out"}, {}) == "CAPE task timed out"


def test_a_parse_note_alone_is_not_an_error():
    """A run that recovered its JSON succeeded. Reporting that as the cell's
    error marks a good run failed — the false positive in the other direction."""
    assert cell_error({}, {"parse_note": "recovered JSON from a markdown fence"}) is None


def test_a_clean_run_has_no_error():
    assert cell_error({}, {}) is None


def test_the_analysis_error_is_used_when_the_result_has_none():
    assert cell_error({}, {"error": "model returned no JSON"}) == "model returned no JSON"


def test_stderr_is_not_appended_without_an_error():
    """stderr on a successful run is noise, not a failure."""
    assert cell_error({"container_stderr": "warning: deprecated flag"}, {}) is None


def test_stderr_is_bounded():
    """The tail is capped at 1500 chars; an unbounded dump would push the real
    message off the scorecard."""
    out = cell_error({"error": "boom", "container_stderr": "x" * 5000}, {})
    assert len(out) < 1700


def test_both_paths_call_the_shared_helper():
    """Structural: reintroducing a private composition in either path is how the
    two disagreed in the first place."""
    for name, src in (("runner", RUNNER), ("rebuild", REBUILD)):
        assert "cell_error(res, analysis)" in src, f"{name} composes its own error"
    assert 'parse_note' not in _error_argument(REBUILD), (
        "rebuild passes parse_note as the cell error again")


def _error_argument(src: str) -> str:
    """Just the `error` positional of rebuild's compose_cell call.

    Scoped past the metrics dict on purpose: `parse_failed` legitimately reads
    parse_note, and a naive search over the whole call matches that and fails.
    """
    start = src.index("compose_cell(")
    metrics_end = src.index("**_tool_call_metrics(arm_dir)}", start)
    return src[metrics_end:src.index("ghidra_warnings=", metrics_end)]


def test_parse_note_is_still_reported_as_a_metric():
    """It is real information — just not an error. It must not be lost in the
    move, only relabelled."""
    assert '"parse_failed": bool(analysis.get("parse_note"))' in REBUILD


def test_the_modules_still_parse():
    ast.parse(RUNNER)
    ast.parse(REBUILD)
