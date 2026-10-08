# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A process tree the guest made deep must not cost the report or the row (#702).

#701 made Volatility's parse fail closed at the decoder's limit, 4,998
processes deep. A tree that parses broke two later consumers much sooner.
Measured on origin/main 6025344, Python 3.12.13, with a pstree chain placed at
``report["volatility"]["plugins"]["pstree"]`` (first failing depth, processes):

    db_ingest._Cleaner (recursive _dirty/_clean)   247  RecursionError; the
                                                        blanket except rolled the
                                                        analysis back: no row
    write_json_atomic (json.dump indent=2)         495  RecursionError; no
                                                        report.json, and
                                                        ingest_to_db (after it)
                                                        never ran
    json.dumps compact / psycopg2 Json.dumps     4,997  RecursionError
    json.loads of the plugin's stdout            4,999  (the #701 limit)

So 4,997 and 4,998 parse but cannot be serialised by anything in the standard
library, which is why the fix bounds the report's depth
(lamware_pipeline.report_depth) rather than falling back to a compact dump.

These tests drive the REAL write_report -> write_json_atomic, and the REAL
ingest_to_db through the recording connection from
test_db_ingest_malformed_reports. Depths 300 and 600 straddle the two old
failure points; 50,000 is ten times past anything json.loads could hand the
pipeline, to show the bound has no depth of its own.

The Cape readers (stages/cape.py) are covered at the end: a Cape report.json
too deep or with a too-long integer made json.load raise RecursionError or
ValueError, which both readers let out.
"""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
import math
from pathlib import Path

import db_ingest
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from lamware_pipeline.report_depth import MARKER, MAX_REPORT_DEPTH, bound_report_depth
from stages import cape
from test_db_ingest_malformed_reports import BASE_REPORT, binding_violations, run_ingest

RUN_PIPELINE = (Path(__file__).resolve().parents[2]
                / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py")

DEPTHS = [300, 600, 50_000]

# Guest-chosen text; must never appear in a recorded failure or section name.
MARKER_TEXT = "SAMPLE_CHOSEN_702"


@pytest.fixture(scope="module")
def rp():
    spec = importlib.util.spec_from_file_location("run_pipeline_702", RUN_PIPELINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def chain(depth: int) -> dict:
    """One pstree root with ``depth`` processes in a single parent->child chain."""
    node = {"PID": depth, "PPID": depth - 1, "ImageFileName": "c.exe", "__children": []}
    for pid in range(depth - 1, 0, -1):
        node = {"PID": pid, "PPID": pid - 1, "ImageFileName": "c.exe", "__children": [node]}
    return node


def deep_report(depth: int) -> dict:
    report = copy.deepcopy(BASE_REPORT)
    vol = report.setdefault("volatility", {})
    vol.setdefault("plugins", {})["pstree"] = [chain(depth)]
    return report


def max_depth(value) -> int:
    """Container levels below ``value`` (the root is level 0). Iterative."""
    best, stack = 0, [(value, 0)]
    while stack:
        node, level = stack.pop()
        best = max(best, level)
        children = node.values() if isinstance(node, dict) else node
        stack.extend((c, level + 1) for c in children if isinstance(c, (dict, list)))
    return best


def kept_chain_length(report: dict) -> int:
    """How many processes of the chain are still in the report."""
    n, rows = 0, report["volatility"]["plugins"]["pstree"]
    while isinstance(rows, list) and rows:
        n += 1
        rows = rows[0]["__children"]
    return n


# ---------------------------------------------------------------------------
# The failure, on the standard library alone (guards on the guards)
# ---------------------------------------------------------------------------

def test_the_indented_dump_fails_at_600_and_the_compact_one_at_4998():
    """What the fix has to get round. If a future Python lifts these limits the
    bound is merely unnecessary; if these stop raising for another reason, the
    tests below stop proving anything about the write."""
    with pytest.raises(RecursionError):
        json.dumps(deep_report(600), indent=2)
    with pytest.raises(RecursionError):
        json.dumps(deep_report(4998))


def test_the_old_recursive_cleaner_fails_at_300():
    with pytest.raises(RecursionError):
        _reference_dirty(deep_report(300), True)


# ---------------------------------------------------------------------------
# report.json: the real write_report -> write_json_atomic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_tree_is_written_bounded_and_says_so(rp, tmp_path, depth):
    report = deep_report(depth)
    path = rp.write_report("task-702", report, tmp_path)

    written = json.loads(path.read_text())
    assert max_depth(written) <= MAX_REPORT_DEPTH
    record = written["depth_truncated"]
    assert record["max_depth"] == MAX_REPORT_DEPTH
    [section] = record["sections"]
    assert section["section"] == "volatility.plugins.pstree"
    assert section["subtrees_removed"] == 1
    # The chain sits 3 levels down (volatility, plugins, pstree); each process
    # is two levels (row, __children). Its deepest container is the last row.
    # Process p's row is at level 2p + 2 (volatility, plugins, pstree, then
    # row and __children per process); the deepest container is the last
    # process's empty __children, one below its row.
    assert section["deepest_level"] == 2 * depth + 3
    # Every process whose row fits under the bound is kept, in order, and the
    # first __children past it is the marker.
    kept = (MAX_REPORT_DEPTH - 2) // 2
    assert kept_chain_length(written) == kept
    row = written["volatility"]["plugins"]["pstree"][0]
    for pid in range(1, kept):
        assert row["PID"] == pid
        row = row["__children"][0]
    assert row["PID"] == kept and row["__children"] == MARKER
    # In place: the dict the database is given next is the one in the file.
    assert report == written


def test_a_real_report_is_written_exactly_as_before(rp, tmp_path):
    """No depth to cut: no record, and the bytes are json.dump's indent=2."""
    report = copy.deepcopy(BASE_REPORT)
    path = rp.write_report("task-702", report, tmp_path)
    assert "depth_truncated" not in report
    assert path.read_text() == json.dumps(BASE_REPORT, indent=2, default=str)


def test_a_second_write_does_not_cut_again(rp, tmp_path):
    report = deep_report(600)
    rp.write_report("task-702", report, tmp_path)
    once = copy.deepcopy(report)
    rp.write_report("task-702", report, tmp_path)
    assert report == once


# ---------------------------------------------------------------------------
# The database row: the real ingest_to_db, recording connection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_tree_still_gets_its_row(capsys, depth):
    """ingest_to_db given the unbounded report (as any caller but run-pipeline
    would): the row is written, report_json is bounded and carries the record,
    and the cut is named in _ingest_warnings."""
    run = run_ingest(deep_report(depth), capsys)
    assert run.result, run.out
    assert run.conn.committed and not run.conn.rolled_back
    assert binding_violations(run.calls) == []
    stored = run.stored_report()
    assert max_depth(stored) <= MAX_REPORT_DEPTH
    assert stored["depth_truncated"]["sections"][0]["section"] == "volatility.plugins.pstree"
    [warnings] = [p.adapted["_ingest_warnings"] for _text, params in run.calls
                  for p in params
                  if isinstance(getattr(p, "adapted", None), dict)
                  and "_ingest_warnings" in p.adapted]
    assert any("nested deeper than 128 levels" in w and "volatility.plugins.pstree" in w
               for w in warnings)


def test_a_report_already_bounded_by_the_write_ingests_without_a_warning(rp, tmp_path, capsys):
    report = deep_report(600)
    rp.write_report("task-702", report, tmp_path)
    run = run_ingest(report, capsys)
    assert run.result
    assert not any("nested deeper than" in out for out in run.out.splitlines())


# ---------------------------------------------------------------------------
# _Cleaner: iterative on its own, not only behind the bound
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("depth", DEPTHS)
def test_the_cleaner_reaches_a_nul_at_any_depth(depth):
    import psycopg2.extras
    report = deep_report(depth)
    row = report["volatility"]["plugins"]["pstree"][0]
    while row["__children"]:
        row = row["__children"][0]
    row["ImageFileName"] = "a\x00b.exe"
    row["score"] = math.nan

    cleaner = db_ingest._Cleaner()
    out = cleaner.param(psycopg2.extras.Json(report))
    assert cleaner.nul == 1 and cleaner.non_finite == 1
    row = out.adapted["volatility"]["plugins"]["pstree"][0]
    while row["__children"]:
        row = row["__children"][0]
    assert row["ImageFileName"] == "ab.exe" and row["score"] is None
    # The caller's report is not modified.
    row = report["volatility"]["plugins"]["pstree"][0]
    while row["__children"]:
        row = row["__children"][0]
    assert row["ImageFileName"] == "a\x00b.exe"


def _reference_dirty(value, in_json):
    """db_ingest._Cleaner._dirty as it was before #702, for comparison."""
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, float):
        return in_json and not math.isfinite(value)
    if isinstance(value, dict):
        return any(_reference_dirty(k, in_json) or _reference_dirty(v, in_json)
                   for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_reference_dirty(v, in_json) for v in value)
    return False


class _ReferenceCleaner:
    """db_ingest._Cleaner._clean as it was before #702, for comparison."""

    def __init__(self):
        self.nul = 0
        self.non_finite = 0

    def clean(self, value, in_json):
        if isinstance(value, str):
            if "\x00" in value:
                self.nul += 1
                return value.replace("\x00", "")
            return value
        if isinstance(value, float) and in_json and not math.isfinite(value):
            self.non_finite += 1
            return None
        if isinstance(value, dict):
            return {self.clean(k, in_json): self.clean(v, in_json) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(self.clean(v, in_json) for v in value)
        return value


_leaf = st.one_of(st.none(), st.booleans(), st.integers(),
                  st.floats(allow_nan=True, allow_infinity=True),
                  st.sampled_from(["", "a", "a\x00", "\x00a", "b"]))
_tree = st.recursive(
    _leaf,
    lambda kids: st.one_of(
        st.lists(kids, max_size=4),
        st.lists(kids, max_size=3).map(tuple),
        # Keys that collide once cleaned ("a\x00" and "a"): which value wins
        # depends on the order the two are built in.
        st.dictionaries(st.sampled_from(["a", "a\x00", "\x00a", "b", "k"]), kids, max_size=4),
    ),
    max_leaves=25,
)


@settings(max_examples=400, deadline=None)
@given(_tree, st.booleans())
def test_the_iterative_cleaner_matches_the_recursive_one(value, in_json):
    ref = _ReferenceCleaner()
    expected = ref.clean(value, in_json)
    cleaner = db_ingest._Cleaner()
    got = cleaner._clean(value, in_json)
    assert repr(got) == repr(expected)   # repr: NaN != NaN, and tuple vs list
    assert (cleaner.nul, cleaner.non_finite) == (ref.nul, ref.non_finite)
    assert cleaner._dirty(value, in_json) == _reference_dirty(value, in_json)


# ---------------------------------------------------------------------------
# The bound itself
# ---------------------------------------------------------------------------

def test_the_bound_is_iterative_far_past_the_recursion_limit():
    report = {"x": []}
    node = report["x"]
    for _ in range(200_000):
        nxt: list = []
        node.append(nxt)
        node = nxt
    record = bound_report_depth(report)
    assert max_depth(report) == MAX_REPORT_DEPTH
    # The section is the first three steps of the path; an array step is "[]".
    assert record["sections"] == [{"section": "x.[].[]", "subtrees_removed": 1,
                                   "deepest_level": 200_001}]


def test_a_guest_chosen_key_is_not_copied_into_the_record():
    report = {"cape": {"extracted_configs": {f"{MARKER_TEXT} ‮": chain(100)}}}
    record = bound_report_depth(report)
    assert MARKER_TEXT not in json.dumps(record)
    assert record["sections"][0]["section"] == "cape.extracted_configs.?"


def test_a_tuple_holding_a_cut_becomes_a_list():
    report = {"a": ({"b": [[]]},)}
    record = bound_report_depth(report, max_depth=3)
    assert report["a"] == ({"b": [MARKER]},)
    assert record["sections"] == [{"section": "a.[].b", "subtrees_removed": 1,
                                   "deepest_level": 4}]
    # The tuple itself at the bound: rebuilt as a list in its parent.
    report = {"a": [[({"b": 1}, [], 7)]]}
    record = bound_report_depth(report, max_depth=3)
    assert report["a"] == [[[MARKER, MARKER, 7]]]
    assert record["sections"] == [{"section": "a.[].[]", "subtrees_removed": 2,
                                   "deepest_level": 4}]


def test_a_second_cut_adds_to_the_record():
    report = {"v": [[[[]]]]}
    bound_report_depth(report, max_depth=3)
    report["v"][0][0][0] = [[]]   # deeper data arriving after the first bound
    bound_report_depth(report, max_depth=3)
    assert report["depth_truncated"]["sections"] == [
        {"section": "v.[].[]", "subtrees_removed": 2, "deepest_level": 5}]


def test_a_report_that_is_not_an_object_is_left_alone():
    assert bound_report_depth([[[]]], max_depth=1) is None


# ---------------------------------------------------------------------------
# run-pipeline bounds before anything after Volatility serialises the report
# ---------------------------------------------------------------------------

def test_the_report_is_bounded_before_correlation_interpret_and_summary():
    """Structural, because run_pipeline cannot be driven end to end here.

    run_summarize json.dumps the whole report outside any handler, and that
    raises from 4,997 levels, which a pstree that parsed can reach. What can
    be observed without the host is the order of the calls in run_pipeline:
    the bound must come after the Volatility stage writes report["volatility"]
    and before the first consumer of the whole report.
    """
    tree = ast.parse(RUN_PIPELINE.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name == "run_pipeline")

    def calls(name):
        return sorted(n.lineno for n in ast.walk(fn) if isinstance(n, ast.Call)
                      and isinstance(n.func, ast.Name) and n.func.id == name)

    def assigns_volatility():
        return [n.lineno for n in ast.walk(fn) if isinstance(n, ast.Assign)
                for t in n.targets if isinstance(t, ast.Subscript)
                and isinstance(t.slice, ast.Constant) and t.slice.value == "volatility"]

    bounds = calls("bound_and_log_depth")
    assert bounds, "run_pipeline no longer bounds the report"
    first_bound = bounds[0]
    assert max(assigns_volatility()) < first_bound
    for consumer in ("cross_correlate", "run_interpret", "run_summarize",
                     "evidence_for_interpret"):
        assert calls(consumer), consumer
        assert first_bound < min(calls(consumer)), consumer


def test_a_bounded_report_survives_the_summary_dump():
    """The behavioural half of the above: a tree that parses (4,998) cannot be
    json.dumps-ed whole, and can once bounded."""
    report = deep_report(4998)
    with pytest.raises(RecursionError):
        json.dumps({"type": "summarize", "report": report}, default=str)
    bound_report_depth(report)
    json.dumps({"type": "summarize", "report": report}, default=str)


# ---------------------------------------------------------------------------
# Cape's report.json: both readers record the failure instead of raising
# ---------------------------------------------------------------------------

CAPE_ROOT = "/opt/CAPEv2/storage/analyses/"


@pytest.fixture
def cape_report(monkeypatch, tmp_path):
    """Write Cape's report.json for task 702 under tmp_path, and point the
    readers' hard-coded storage path there."""
    real_path = Path

    def fake_path(p, *rest):
        s = str(p)
        if s.startswith(CAPE_ROOT):
            return real_path(tmp_path, s[len(CAPE_ROOT):], *rest)
        return real_path(p, *rest)

    monkeypatch.setattr(cape, "Path", fake_path)
    target = tmp_path / "702" / "reports" / "report.json"
    target.parent.mkdir(parents=True)

    def write(text: str):
        target.write_text(text)
    return write


def deep_cape_json(levels: int) -> str:
    return ('{"signatures": [{"name": "s", "data": ' + "[" * levels + "]" * levels
            + '}], "note": "' + MARKER_TEXT + '"}')


HUGE_INT = '{"signatures": [{"name": "s", "severity": ' + "9" * 5000 + '}]}'

UNREADABLE = [
    pytest.param(deep_cape_json(20_000), "RecursionError", id="too-deep"),
    pytest.param(HUGE_INT, "ValueError", id="5000-digit-int"),
    pytest.param('[{"' + MARKER_TEXT + '": 1}]', "not an object", id="not-an-object"),
    pytest.param('{"' + MARKER_TEXT, "JSONDecodeError", id="truncated"),
]


def test_the_unreadable_inputs_do_raise_from_json_load():
    """Guard on the guard: each input raises what its case says it does."""
    with pytest.raises(RecursionError):
        json.loads(deep_cape_json(20_000))
    with pytest.raises(ValueError, match="digits"):
        json.loads(HUGE_INT)


@pytest.mark.parametrize("text,why", UNREADABLE)
def test_extract_cape_intel_records_an_unreadable_report(cape_report, text, why):
    cape_report(text)
    intel = cape.extract_cape_intel({"id": 702})
    assert set(intel) == {"error"}
    assert why in intel["error"]
    assert MARKER_TEXT not in intel["error"]


@pytest.mark.parametrize("text,why", UNREADABLE)
def test_get_cape_signatures_returns_none_for_an_unreadable_report(cape_report, capsys,
                                                                    text, why):
    cape_report(text)
    assert cape.get_cape_signatures({"id": 702}) == []
    err = capsys.readouterr().err
    assert why in err and MARKER_TEXT not in err


def test_an_exception_message_is_never_recorded(cape_report, monkeypatch, capsys):
    """Only the type is recorded. The decoder's own messages do not quote the
    document today, so the inputs above cannot show this; a decoder (or a
    future json.load replacement) whose message did would leak guest text
    into the report and the log."""
    cape_report("{}")

    def raising(_f):
        raise ValueError(f"bad value near {MARKER_TEXT}")
    monkeypatch.setattr(cape.json, "load", raising)
    intel = cape.extract_cape_intel({"id": 702})
    assert cape.get_cape_signatures({"id": 702}) == []
    recorded = intel["error"] + capsys.readouterr().err
    assert "ValueError" in recorded and MARKER_TEXT not in recorded


@pytest.mark.parametrize("signatures", [None, "x", {"name": "s"}, [1, "s", None]])
def test_get_cape_signatures_skips_wrong_shapes(cape_report, signatures):
    cape_report(json.dumps({"signatures": signatures}))
    assert cape.get_cape_signatures({"id": 702}) == []


def test_a_readable_report_is_still_read(cape_report):
    cape_report(json.dumps({"signatures": [{"name": "injection_rwx", "severity": 3}]}))
    assert cape.get_cape_signatures({"id": 702}) == ["injection_rwx"]
    intel = cape.extract_cape_intel({"id": 702})
    assert intel["signatures"] == [{"name": "injection_rwx", "severity": 3,
                                    "description": ""}]

