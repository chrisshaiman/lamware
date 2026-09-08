# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A dead stage must not read as a finding (#576).

For five days every containerized stage was broken and run-pipeline exited 0,
printing:

    Summary:
      Triage:     0 YARA matches

"0 YARA matches" is a sentence about the sample. The truth was that triage never
ran. The two are indistinguishable downstream because every consumer reads
`.get("triage", {})`, which is an empty dict either way, so the pipeline
degraded quietly in three places:

  * derive_package_from_triage falls through to "" -> Cape gets package=auto
  * derive_filename has no file type to work from
  * the guest-clock anti-evasion has no pe_compile_timestamp to offset from

Ten corpus runs were reported successful that way, and the submission change
alone invalidated the comparison they were run for.
"""
import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"

spec = importlib.util.spec_from_file_location("_triage", FILES / "stages" / "triage.py")
triage = importlib.util.module_from_spec(spec)
sys.modules["_triage"] = triage
spec.loader.exec_module(triage)

RUN_PIPELINE = (FILES / "run-pipeline.py").read_text(encoding="utf-8")
TREE = ast.parse(RUN_PIPELINE)


# --- the predicate itself -------------------------------------------------

def test_a_failed_triage_is_reported_as_failed():
    for payload in ({"error": "triage failed"},
                    {"error": "triage timeout"},
                    {"error": "invalid triage output"}):
        assert triage.triage_error(payload), f"{payload} not recognised as a failure"


def test_a_successful_triage_is_not():
    """The empty-but-successful case is the one that must NOT trip it: a sample
    with no YARA matches is a legitimate result."""
    assert triage.triage_error({"triage": {"yara_matches": []}}) is None
    assert triage.triage_error({}) is None


def test_an_empty_error_string_is_not_a_failure():
    assert triage.triage_error({"error": ""}) is None


def test_the_dead_and_the_empty_triage_are_distinguishable():
    """This is the whole bug: both produce {} for every downstream consumer."""
    dead = {"error": "triage failed", "stderr": "cannot retrieve cmd line"}
    empty = {"triage": {"yara_matches": [], "file_type": ""}}
    assert triage.derive_package_from_triage(dead) == triage.derive_package_from_triage(empty), \
        "package derivation still cannot tell them apart -- which is why the caller must ask"
    assert bool(triage.triage_error(dead)) != bool(triage.triage_error(empty))


# --- the caller acting on it ---------------------------------------------

def _func(name: str) -> ast.AST:
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"no function {name}")


def test_the_pipeline_asks_whether_triage_ran():
    calls = [n for n in ast.walk(TREE)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "triage_error"]
    assert calls, "run-pipeline never calls triage_error; the failure stays invisible"


def test_a_failure_is_recorded_where_the_summary_can_see_it():
    """Anchored on the recording CALL, not on the identifier appearing
    somewhere: main() also reads stage_failures, so a bare substring search
    still passed after deleting the write -- verified by mutation."""
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"):
            src = ast.get_source_segment(RUN_PIPELINE, node) or ""
            if "stage_failures" in src and "triage" in src:
                return
    raise AssertionError("nothing records the triage failure into stage_failures")


def test_main_exits_non_zero_when_a_stage_failed():
    """Parsed, not grepped: there must be a sys.exit inside a branch guarded by
    `failures`. A string search would pass on the sys.exit(1) that already
    existed for a missing input file."""
    main = _func("main")
    found = False
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        test_names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if "failures" not in test_names:
            continue
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "exit"):
                found = True
    assert found, "main() does not exit non-zero on a failed stage"


def test_the_summary_stops_claiming_zero_yara_matches_when_triage_died():
    """The exact misleading line, and it must sit in the ELSE of a branch that
    tests the failure.

    Searching for an If containing both "YARA matches" and "FAILED" anywhere in
    its source passed even with the conditional deleted -- an enclosing block
    held both. So this walks parents and checks the guarding condition."""
    main = _func("main")
    parent = {}
    for node in ast.walk(main):
        for child in ast.iter_child_nodes(node):
            parent[child] = node

    target = None
    for node in ast.walk(main):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and "YARA matches" in node.value:
            target = node
            break
    assert target is not None, "the YARA-matches line is gone entirely"

    cur = target
    while cur in parent:
        cur = parent[cur]
        if isinstance(cur, ast.If):
            names = {n.id for n in ast.walk(cur.test) if isinstance(n, ast.Name)}
            if "failures" in names:
                return
    raise AssertionError(
        "the YARA-matches line is not guarded by the stage-failure check; it "
        "will print '0 YARA matches' again when triage is dead")
