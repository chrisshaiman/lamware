# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""`completed` must not count an unparseable answer as a success (#380).

The 29-sample MOTIF sweep reported `completed_rate: 1.0` while two cells — the
two LARGEST samples, 3,603 and 3,502 functions — returned model output that
could not be parsed as JSON.

When that happens the raw text is preserved in `narrative` and a `parse_note` is
set. Crucially `enabled` is still True, there is no `error`, and `analysis` is a
non-empty dict, so the live check

    enabled is True and not err and bool(analysis)

held on all three counts. The failure was structurally invisible to the metric
covering it — the same shape as #367 (`analysis_success` on an empty analysis)
and #370 (silent import truncation).

It also existed twice: `rebuild.py` re-scores persisted cells offline and
carried its own copy that DID check `parse_note`, so re-scoring a sweep gave a
different answer than the sweep. Both copies are now one function.
"""
import ast
import json
from pathlib import Path

import pytest
from lamware_eval.metrics import aggregate, compose_cell
from llm_ab_re import analysis_completed, extract_metrics

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"


def result(**over) -> dict:
    """A successful run_interpret result, overridable."""
    base = {
        "enabled": True,
        "error": None,
        "tool_calls_used": 10,
        "duration_seconds": 400.0,
        "analysis": {"malware_family_guess": "unknown", "capabilities": ["x"],
                     "code_level_iocs": []},
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# The definition
# ---------------------------------------------------------------------------

def test_a_good_run_is_completed():
    """Positive control. Without it, `return False` passes everything below."""
    assert analysis_completed(result()) is True


def test_THE_regression_a_parse_failure_is_not_completed():
    """The exact shape from the MOTIF sweep: enabled, no error, non-empty
    analysis, and an answer that could not be parsed."""
    r = result(analysis={
        "malware_family_guess": "unknown",
        "capabilities": [],
        "narrative": "raw model text that was not JSON",
        "parse_note": "Failed to parse structured JSON from model response; "
                      "raw text preserved in narrative.",
    })
    assert r["enabled"] is True and not r["error"] and bool(r["analysis"]), (
        "the fixture must satisfy every OLD condition, or it does not reproduce "
        "the bug")
    assert analysis_completed(r) is False


@pytest.mark.parametrize("over,why", [
    ({"enabled": False}, "disabled"),
    ({"error": "container died"}, "errored"),
    ({"analysis": {}}, "no analysis"),
    ({"analysis": {"error": "model refused"}}, "analysis-level error"),
])
def test_the_other_failure_modes_still_count_as_incomplete(over, why):
    assert analysis_completed(result(**over)) is False, why


def test_extract_metrics_reports_the_parse_failure_separately():
    """'Finished but unparseable' is neither success nor error. Folding it into
    either loses the signal that mattered most in the sweep."""
    m = extract_metrics(result(analysis={"narrative": "x", "parse_note": "nope"}))
    assert m["completed"] is False
    assert m["parse_failed"] is True
    ok = extract_metrics(result())
    assert ok["completed"] is True and ok["parse_failed"] is False


# ---------------------------------------------------------------------------
# One definition, not two
# ---------------------------------------------------------------------------

def test_rebuild_uses_the_shared_definition_not_its_own_copy():
    """Cross-copy drift guard. rebuild.py's private copy checked parse_note
    while the live path did not, so re-scoring a sweep disagreed with it."""
    src = (FILES / "lamware_eval" / "rebuild.py").read_text(encoding="utf-8")
    # Matched by parse rather than by exact line: the import grew a second name
    # in #316 and a literal-string assertion failed on correct code.
    imported = [n.name for node in ast.walk(ast.parse(src))
                if isinstance(node, ast.ImportFrom) and node.module == "llm_ab_re"
                for n in node.names]
    assert "analysis_completed" in imported, (
        f"rebuild.py does not import the shared definition; imports {imported}")
    assert "analysis_completed(res)" in src
    assert 'not analysis.get("parse_note")' not in src.split("def rebuild")[1], (
        "rebuild.py has re-grown its own copy of the completed definition")


def test_only_one_place_defines_completed():
    """Any second `completed = ...and...` expression is a copy waiting to drift."""
    hits = []
    for p in list((FILES / "lamware_eval").glob("*.py")) + [FILES / "llm_ab_re.py"]:
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            s = line.strip()
            if s.startswith("completed = ") and "analysis_completed" not in s:
                hits.append(f"{p.name}:{i}: {s}")
    assert not hits, f"completed is computed outside the shared function: {hits}"


def test_the_live_and_offline_scorers_agree_on_the_same_cell():
    """The property the two copies violated: same input, same verdict."""
    for r in (result(), result(analysis={"narrative": "x", "parse_note": "n"}),
              result(enabled=False), result(error="boom")):
        live = extract_metrics(r)["completed"]
        offline = analysis_completed(r)   # what rebuild.py now calls
        assert live == offline, f"scorers disagree on {r!r}: {live} vs {offline}"


# ---------------------------------------------------------------------------
# It reaches the scorecard
# ---------------------------------------------------------------------------

def test_parse_failures_are_aggregated_and_visible():
    """A number nobody can see is not a fix. This is the column that would have
    shown 2 instead of a clean 1.0."""
    from lamware_eval.corpus import CorpusSample
    s = CorpusSample("a" * 64, "trickbot", "/tmp/x")
    cells = [
        compose_cell("qwen@10", s, {"code_level_iocs": []}, "src", None, 400.0, 0.0,
                     extract_metrics(result()), None),
        compose_cell("qwen@10", s, {"narrative": "x"}, "src", None, 400.0, 0.0,
                     extract_metrics(result(analysis={"narrative": "x",
                                                      "parse_note": "n"})), None),
    ]
    agg = aggregate(cells)["qwen@10"]
    assert agg["parse_failures"] == 1, agg
    assert agg["completed_rate"] == 0.5, agg


def test_the_scorecard_renders_the_column():
    src = (FILES / "lamware_eval" / "scorecard.py").read_text(encoding="utf-8")
    assert '"parse_failures"' in src, "summary table omits parse_failures"
    assert '"parse_failed"' in src, "per-cell table omits parse_failed"
    assert json.dumps(True)  # keep the json import honest
