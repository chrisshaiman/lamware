# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The anomalous-parent insight reads the whole process tree, not its roots (#687).

Volatility 3's windows.pstree returns the ROOTS of the process tree; every other
process sits in some row's `__children`. extract_volatility_insights iterated
the top-level list only. Measured on the 13 host reports with pstree output
(2026-10-04, read-only): 4-8 roots of 13-225 processes each, nesting up to 9
deep, and the insight's own rule finds 0 anomalous pairs among the roots and 2
in the whole trees — both a svchost.exe whose parent is the sample's own child
(rednat_179dcccf0614 and v648_179dcccf0614). Neither report carried the insight.

Fixture: `fixtures/volatility_pstree_nested_rednat_179dcccf.json` is the real
pstree of rednat_179dcccf0614 with only PID, PPID, ImageFileName and
`__children` kept, the sample's image name replaced by "sample.exe", and
services.exe's childless svchost.exe rows cut to three (140 of 222 processes).
Every other name is the generic Windows image name the report carried.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import time
from pathlib import Path

from stages.volatility import extract_volatility_insights

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REAL_TREE = json.loads(
    (FIXTURES / "volatility_pstree_nested_rednat_179dcccf.json").read_text(encoding="utf-8"))


def insights(plugins, warnings=None) -> dict:
    with contextlib.redirect_stdout(io.StringIO()):
        return extract_volatility_insights(plugins, warnings=warnings)


def proc(pid: int, ppid: int, name: str, *children: dict) -> dict:
    return {"PID": pid, "PPID": ppid, "ImageFileName": name, "__children": list(children)}


def _count(rows: list[dict]) -> int:
    n, stack = 0, list(rows)
    while stack:
        row = stack.pop()
        n += 1
        stack.extend(row["__children"])
    return n


# ---------------------------------------------------------------------------
# The real tree
# ---------------------------------------------------------------------------

def test_the_fixture_is_the_shape_the_host_reports_have():
    """Guard on the fixture: if it were flat, every test below would pass on
    the code that reads only the top level."""
    assert len(REAL_TREE) == 6
    assert _count(REAL_TREE) == 140
    # The anomalous svchost.exe is seven levels below its root.
    path, row = [], {"__children": REAL_TREE}
    for pid in (692, 836, 1496, 1996, 5772, 8576, 7568, 6720):
        row = next(c for c in row["__children"] if c["PID"] == pid)
        path.append(row["ImageFileName"])
    assert path == ["wininit.exe", "services.exe", "svchost.exe", "python.exe",
                    "python.exe", "sample.exe", "sample.exe", "svchost.exe"]


def test_the_real_tree_reports_the_pair_its_rule_finds():
    """Exactly the pair the rule finds in the whole tree, and nothing for the
    nested processes that have their expected parents (services.exe under
    wininit.exe, svchost.exe under services.exe, lsass.exe under wininit.exe,
    explorer.exe under userinit.exe, smss.exe under System)."""
    warnings: list[str] = []
    found = insights({"pstree": REAL_TREE}, warnings)
    assert found["anomalous_parents"] == [{
        "pid": 6720, "process": "svchost.exe", "parent_pid": 7568,
        "parent_process": "sample.exe", "expected_parents": ["services.exe"],
    }]
    assert warnings == []


def test_the_roots_alone_hold_no_anomalous_pair():
    """What the top-level-only reader saw of the same tree: nothing. The roots
    are System, csrss.exe x3, wininit.exe and winlogon.exe, and the parents of
    the last five exited before the dump (their PPIDs match no process)."""
    roots = [{**r, "__children": []} for r in REAL_TREE]
    assert "anomalous_parents" not in insights({"pstree": roots})


# ---------------------------------------------------------------------------
# Constructed trees
# ---------------------------------------------------------------------------

def test_an_anomalous_pair_below_the_top_level_is_reported():
    """The pair is a grandchild of the only root, so a reader of roots never
    sees either process (fails on origin/main ac1767f)."""
    tree = [proc(10, 1, "explorer.exe",
                 proc(20, 10, "winword.exe",
                      proc(30, 20, "svchost.exe")))]
    assert insights({"pstree": tree})["anomalous_parents"] == [{
        "pid": 30, "process": "svchost.exe", "parent_pid": 20,
        "parent_process": "winword.exe", "expected_parents": ["services.exe"],
    }]


def test_the_parent_is_found_across_subtrees_by_ppid():
    """The rule matches a parent by PPID over every process, as it did over the
    roots: a child whose PPID names a process in another subtree is judged
    against that process."""
    tree = [proc(10, 1, "cmd.exe"),
            proc(20, 99, "explorer.exe", proc(30, 10, "lsass.exe"))]
    found = insights({"pstree": tree})["anomalous_parents"]
    assert [(a["pid"], a["parent_process"]) for a in found] == [(30, "cmd.exe")]


def test_a_reused_pid_names_the_first_process_in_tree_order():
    """Two rows with one PID (not seen on the host; PIDs are reused once a
    process exits) resolve as the scan this replaces did: the first match,
    now in pre-order. Last-match would judge svchost.exe against cmd.exe."""
    tree = [proc(1, 0, "wininit.exe", proc(7, 1, "services.exe")),
            proc(7, 0, "cmd.exe"),
            proc(2, 0, "b.exe", proc(30, 7, "svchost.exe"))]
    assert "anomalous_parents" not in insights({"pstree": tree})


def test_pairs_are_reported_in_tree_order():
    """Pre-order: a root, then its subtree, then the next root."""
    tree = [proc(1, 0, "a.exe", proc(2, 1, "svchost.exe"), proc(3, 1, "lsass.exe")),
            proc(4, 0, "b.exe", proc(5, 4, "smss.exe"))]
    assert [a["pid"] for a in insights({"pstree": tree})["anomalous_parents"]] == [2, 3, 5]


def test_a_10000_deep_chain_is_walked_without_recursion_in_bounded_time():
    """Depth is the guest's to choose. Every svchost.exe but the first has a
    svchost.exe parent, so all 9,999 pairs must be reported."""
    depth = 10_000
    root = proc(1, 0, "svchost.exe")
    node = root
    for pid in range(2, depth + 1):
        child = proc(pid, pid - 1, "svchost.exe")
        node["__children"].append(child)
        node = child
    started = time.monotonic()
    warnings: list[str] = []
    found = insights({"pstree": [root]}, warnings)
    elapsed = time.monotonic() - started
    assert len(found["anomalous_parents"]) == depth - 1
    assert found["anomalous_parents"][-1]["pid"] == depth
    assert warnings == []
    # A hang guard, not a complexity proof: on a flat 10,000-row chain the old
    # O(n^2) scan took 0.61s and the dict lookup 0.01s on the dev machine.
    assert elapsed < 1.0, f"{elapsed:.2f}s for {depth} processes"


# ---------------------------------------------------------------------------
# Malformed nesting: named, skipped, the rest still read
# ---------------------------------------------------------------------------

def test_a_child_that_is_not_an_object_costs_only_itself():
    tree = [proc(10, 1, "explorer.exe", 5, proc(30, 10, "svchost.exe"))]
    warnings: list[str] = []
    found = insights({"pstree": tree}, warnings)
    assert warnings == ["pstree[0].__children[depth 1, 0]: expected object, got integer"
                        " — row skipped"]
    assert [a["pid"] for a in found["anomalous_parents"]] == [30]


def test_children_that_are_not_an_array_cost_only_that_subtree():
    tree = [proc(10, 1, "explorer.exe", proc(30, 10, "svchost.exe")),
            {**proc(40, 1, "cmd.exe"), "__children": {"PID": 41}}]
    warnings: list[str] = []
    found = insights({"pstree": tree}, warnings)
    assert warnings == ["pstree[1].__children: expected array, got object — not read"]
    assert [a["pid"] for a in found["anomalous_parents"]] == [30]


def test_a_nested_field_of_the_wrong_type_is_named_by_its_root_and_depth():
    """The path of a nested row is bounded whatever the depth, and carries no
    plugin text."""
    tree = [proc(10, 1, "explorer.exe",
                 proc(20, 10, "cmd.exe", {"PID": 30, "PPID": 20, "ImageFileName": 7}),
                 proc(31, 10, "svchost.exe"))]
    warnings: list[str] = []
    found = insights({"pstree": tree}, warnings)
    assert warnings == ["pstree[0].__children[depth 2, 0].ImageFileName: expected string,"
                        " got integer — not read"]
    assert [a["pid"] for a in found["anomalous_parents"]] == [31]


def test_null_or_absent_children_are_a_leaf():
    tree = [{"PID": 10, "PPID": 1, "ImageFileName": "explorer.exe", "__children": None},
            {"PID": 30, "PPID": 10, "ImageFileName": "svchost.exe"}]
    warnings: list[str] = []
    found = insights({"pstree": tree}, warnings)
    assert warnings == []
    assert [a["pid"] for a in found["anomalous_parents"]] == [30]


def test_the_walk_does_not_modify_the_plugin_output():
    """The report writes volatility.plugins.pstree after the insights are read."""
    before = copy.deepcopy(REAL_TREE)
    insights({"pstree": REAL_TREE})
    assert REAL_TREE == before
