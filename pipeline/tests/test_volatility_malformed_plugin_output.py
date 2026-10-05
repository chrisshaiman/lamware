# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A malformed Volatility row must not cost the analysis its memory forensics (#171).

Plugin output describes the guest: process names, command lines, DLL paths and
handle names are whatever the sample made them. `extract_volatility_insights`
and `filter_malfind_json` read it with `entry.get("Args", "").lower()`, and
`dict.get(k, default)` returns the default only when k is ABSENT. Reproduced on
origin/main (fef552a) by calling both functions:

    extract_volatility_insights(None)                 AttributeError  :747
    {"cmdline": [None]}                               AttributeError  :759
    {"cmdline": [{"Args": 5}]}                        AttributeError  :764
    {"handles": [{"Type": "Mutant", "Name": 5}]}      AttributeError  :822
    {"handles": [{..., "Process": [1]}]}              TypeError       :847 (unhashable)
    {"dlllist": [{"Path": 5}]}                        AttributeError  :880
    {"pstree": [{"ImageFileName": None}]}             AttributeError  :920
    filter_malfind_json([None])                       AttributeError  :235
    malfind row with "Hexdump": None                  AttributeError  :277
    malfind row with "PID": [1]                       TypeError       :294

and the same at every row of netscan/handles/dlllist/pstree that is not an
object: 94 of 321 probes raised. Nothing in run_volatility catches it and
run-pipeline catches only TimeoutError around it, so the raise discarded every
plugin's output after the plugins had run (test_run_volatility_keeps_its_plugins
below drives that path).

Base fixture: `fixtures/volatility_plugins_rm630.json`. Its STRUCTURE is the
real host report rm630_591d32aeae05 (plugins, row keys, which values are null,
value types, PIDs, VAD bounds, pstree nesting, which handles share a mutex),
with rows subsampled. Every string is synthetic or a generic Windows name,
chosen so each row lands in the insight category its real value did. The real
run had no netscan, no suspicious command line and no top-level anomalous
parent, so a few rows are added for those branches (the netscan section, three
cmdlines with PIDs 9001-9003, two pstree roots with PIDs 9100-9101).

The golden, `fixtures/volatility_plugins_rm630.golden.json`, was produced by
the origin/main code from that fixture, before this change.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import re
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from stages import volatility
from stages.volatility import _Row, extract_volatility_insights, filter_malfind_json

FIXTURES = Path(__file__).resolve().parent / "fixtures"
PLUGINS = json.loads((FIXTURES / "volatility_plugins_rm630.json").read_text(encoding="utf-8"))
GOLDEN = json.loads((FIXTURES / "volatility_plugins_rm630.golden.json").read_text(encoding="utf-8"))

# pipeline_malfind_* in ansible/roles/pipeline/defaults/main.yml
MALFIND = dict(malfind_min_size=256, malfind_max_size=10485760, malfind_min_score=2,
               malfind_max_candidates=5,
               malfind_benign_processes=["csrss.exe", "smss.exe", "MsMpEng.exe",
                                         "fontdrvhost.exe"])

# What a warning may look like. Built only from plugin names, our key names and
# indices: a warning that carried a value would carry guest-chosen text.
WARNING = re.compile(
    r"(plugins|[a-z]+(\[\d+\])?(\.[A-Za-z ()]+)?): expected (object|array|string|integer), "
    r"got \w+ — (not read|row skipped)")


def insights(plugins, warnings=None) -> dict:
    with contextlib.redirect_stdout(io.StringIO()):
        return extract_volatility_insights(plugins, warnings=warnings)


def malfind(rows, warnings=None, **overrides) -> tuple[list[dict], set]:
    kw = {**MALFIND, "cape_injection_pids": [972], **overrides}
    with contextlib.redirect_stdout(io.StringIO()):
        return filter_malfind_json(rows, warnings=warnings, **kw)


# ---------------------------------------------------------------------------
# A well-formed output: exactly what it produced before
# ---------------------------------------------------------------------------

def test_a_well_formed_output_produces_the_insights_it_did_before():
    """The "no data dropped" half: every insight, field for field, as origin/main
    produced from the same rows."""
    warnings: list[str] = []
    # Compared as stored: unique_processes was list(set(...)) and was compared
    # sorted here; it is sorted at the source now (#689), so the order is part
    # of what must not change.
    assert insights(PLUGINS, warnings) == GOLDEN["insights"]
    assert warnings == []


def test_a_well_formed_malfind_selects_what_it_did_before():
    warnings: list[str] = []
    selected, pids = malfind(PLUGINS["malfind"], warnings)
    assert selected == GOLDEN["malfind_selected"]
    assert sorted(pids) == GOLDEN["malfind_target_pids"]
    assert warnings == []


def test_the_golden_reaches_every_insight():
    """Guard on the guard: a golden that never reached a branch would pass
    whatever that branch now does."""
    assert set(GOLDEN["insights"]) == {
        "suspicious_cmdlines", "active_connections", "mutexes", "mutex_summary",
        "suspicious_files", "suspicious_dlls", "anomalous_parents"}
    assert all(GOLDEN["insights"][k] for k in GOLDEN["insights"])
    assert GOLDEN["malfind_selected"] and any(
        r.get("cape_confirmed") for r in GOLDEN["malfind_selected"])
    # A null copied through (netscan State/Owner) is in the golden, so a reader
    # that turned null into "" would fail the equality above.
    assert any(c["state"] is None and c["process"] is None
               for c in GOLDEN["insights"]["active_connections"])


# ---------------------------------------------------------------------------
# Each reproduced crash: no raise, the bad part named, the rest still read
# ---------------------------------------------------------------------------

GOOD_CMD = {"PID": 7, "Process": "cmd.exe", "Args": "cmd.exe /c whoami"}
GOOD_CONN = {"PID": 7, "Owner": "x.exe", "ForeignAddr": "192.0.2.1", "ForeignPort": 80,
             "LocalPort": 5000, "State": "ESTABLISHED"}
GOOD_MUTEX = {"PID": 7, "Process": "x.exe", "Type": "Mutant", "Name": "\\BaseNamedObjects\\m1"}
GOOD_FILE = {"PID": 7, "Process": "x.exe", "Type": "File",
             "Name": "\\Device\\HarddiskVolume3\\Users\\u\\AppData\\Local\\Temp\\a.exe"}
GOOD_DLL = {"PID": 7, "Process": "x.exe", "Path": "C:\\Users\\u\\AppData\\Roaming\\a.dll"}
GOOD_TREE = [{"PID": 1, "PPID": 2, "ImageFileName": "svchost.exe"},
             {"PID": 2, "PPID": 0, "ImageFileName": "explorer.exe"}]


@pytest.mark.parametrize("plugins, warning, kept", [
    # origin/main line each raised on, in the comment
    ({"cmdline": [None, GOOD_CMD]},                                # :759
     "cmdline[0]: expected object, got null — row skipped", "suspicious_cmdlines"),
    ({"cmdline": [{**GOOD_CMD, "Args": 5}, GOOD_CMD]},             # :764
     "cmdline[0].Args: expected string, got integer — not read", "suspicious_cmdlines"),
    ({"netscan": ["x", GOOD_CONN]},                                # :782
     "netscan[0]: expected object, got string — row skipped", "active_connections"),
    ({"netscan": [GOOD_CONN, {**GOOD_CONN, "ForeignAddr": ["192.0.2.2"]}]},
     "netscan[1].ForeignAddr: expected string, got array — not read", "active_connections"),
    ({"handles": [[1], GOOD_MUTEX]},                               # :811
     "handles[0]: expected object, got array — row skipped", "mutexes"),
    ({"handles": [{**GOOD_MUTEX, "Name": 5}, GOOD_MUTEX]},         # :822
     "handles[0].Name: expected string, got integer — not read", "mutexes"),
    ({"handles": [{**GOOD_FILE, "Name": 1.5}, GOOD_FILE]},         # :831
     "handles[0].Name: expected string, got number — not read", "suspicious_files"),
    ({"handles": [{**GOOD_MUTEX, "Process": [1]}, GOOD_MUTEX]},    # :847
     "handles[0].Process: expected string, got array — not read", "mutexes"),
    ({"dlllist": [{**GOOD_DLL, "Path": 5}, GOOD_DLL]},             # :880
     "dlllist[0].Path: expected string, got integer — not read", "suspicious_dlls"),
    ({"dlllist": [True, GOOD_DLL]},                                # :872
     "dlllist[0]: expected object, got boolean — row skipped", "suspicious_dlls"),
    ({"pstree": [*GOOD_TREE, 5]},                                  # :920
     "pstree[2]: expected object, got integer — row skipped", "anomalous_parents"),
    ({"pstree": [*GOOD_TREE, {"PID": 3, "PPID": 2, "ImageFileName": {"a": 1}}]},
     "pstree[2].ImageFileName: expected string, got object — not read",
     "anomalous_parents"),
    ({"cmdline": "not a list", "dlllist": [GOOD_DLL]},
     "cmdline: expected array, got string — not read", "suspicious_dlls"),
])
def test_a_malformed_row_costs_only_that_row(plugins, warning, kept):
    warnings: list[str] = []
    found = insights(plugins, warnings)
    assert warning in warnings
    assert found[kept], f"the well-formed row's {kept} was lost with the bad one"


def test_a_row_without_a_pid_is_nobodys_parent():
    """The parent lookup matched on .get("PID"), so a row with no PID matched
    no PPID — not PPID 0, which an absent PID reads as in the insight itself."""
    tree = [{"PID": 5, "PPID": 0, "ImageFileName": "svchost.exe"},
            {"PPID": 4, "ImageFileName": "explorer.exe"}]
    assert "anomalous_parents" not in insights({"pstree": tree})


def test_a_null_image_name_no_longer_raises():
    """:920 raised on null too: the parent lookup lower()s every name."""
    tree = [*GOOD_TREE, {"PID": 3, "PPID": 2, "ImageFileName": None}]
    warnings: list[str] = []
    found = insights({"pstree": tree}, warnings)
    assert found["anomalous_parents"][0]["parent_process"] == "explorer.exe"
    assert warnings == []   # null is "no value", not a wrong type


@pytest.mark.parametrize("plugins", [None, "x", [], 5])
def test_plugins_that_are_not_an_object_yield_no_insights(plugins):
    """:747 — the first line of the function raised on all four."""
    warnings: list[str] = []
    assert insights(plugins, warnings) == {}
    assert warnings and warnings[0].startswith("plugins: expected object")


def test_a_failed_plugin_is_not_a_malformed_one():
    """run_single_plugin writes {"error": ...} for a failed plugin, and an absent
    plugin did not run. Both are recorded elsewhere; neither is a parse warning."""
    warnings: list[str] = []
    assert insights({"cmdline": {"error": "timeout (300s)"}, "netscan": None}, warnings) == {}
    assert warnings == []


GOOD_REGION = {"PID": 972, "Process": "svchost.exe", "Start VPN": 0x10000, "End VPN": 0x10fff,
               "Protection": "PAGE_EXECUTE_READWRITE", "File output": "Disabled",
               "Hexdump": "e8 00 00 00 00 5d 48 83 ec 28 4c 8b 4d 00 11 22"}


@pytest.mark.parametrize("bad, warning", [
    (None, "malfind[0]: expected object, got null — row skipped"),                  # :235
    ({**GOOD_REGION, "Process": 5},
     "malfind[0].Process: expected string, got integer — not read"),                 # :266
    ({**GOOD_REGION, "Hexdump": ["e8"]},
     "malfind[0].Hexdump: expected string, got array — not read"),                   # :277
    ({**GOOD_REGION, "PID": [1]},
     "malfind[0].PID: expected integer, got array — not read"),                      # :294
    ({**GOOD_REGION, "Start VPN": "0x10000"},
     "malfind[0].Start VPN: expected integer, got string — not read"),
])
def test_a_malformed_malfind_region_costs_only_that_region(bad, warning):
    # Different bytes and address, so dedup cannot merge it with the bad one.
    good = {**GOOD_REGION, "Start VPN": 0x20000, "End VPN": 0x20fff,
            "Hexdump": "fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b"}
    warnings: list[str] = []
    selected, pids = malfind([bad, good], warnings)
    assert warning in warnings
    assert 972 in pids
    assert "0x20000" in [r["start_vpn"] for r in selected]


@pytest.mark.parametrize("field", ["Process", "Hexdump"])
def test_a_null_malfind_field_takes_the_default(field):
    """Null raised at :266/:277 (.lower()/.split() on None). Null is not a wrong
    type, so there is no warning; Process falls back to "unknown" as an absent
    one always did, and a region with no hexdump has nothing to score."""
    warnings: list[str] = []
    selected, _ = malfind([{**GOOD_REGION, field: None}], warnings)
    assert warnings == []
    if field == "Process":
        assert selected[0]["process"] == "unknown"
    else:
        assert selected == []


def test_a_wrong_typed_file_output_becomes_empty():
    """run-pipeline joins file_output onto the dump dir (`dir / file_output`);
    an int there raised TypeError in Stage 3.5, after this function returned."""
    warnings: list[str] = []
    selected, _ = malfind([{**GOOD_REGION, "File output": 5}], warnings)
    assert selected[0]["file_output"] == ""
    assert "malfind[0].File output: expected string, got integer — not read" in warnings


def test_a_boolean_is_not_a_pid_or_an_address():
    warnings: list[str] = []
    row = _Row({"PID": True, "Start VPN": False}, "malfind[0]", warnings)
    assert row.integer("PID", 0) == 0
    assert row.integer("Start VPN", None) is None
    assert len(warnings) == 2


def test_absent_null_and_wrong_are_three_different_things():
    warnings: list[str] = []
    row = _Row({"a": None, "b": 5, "c": "s"}, "p[0]", warnings)
    assert row.text("missing", "d") == "d"           # absent: the default
    assert row.text("a", "d") is None                # null, copied: stays null
    assert row.text("a", "d", nullable=False) == "d"  # null, operated on: default
    assert row.text("b", "d") == "d"                 # wrong: default + warning
    assert row.text("c", "d") == "s"
    assert warnings == ["p[0].b: expected string, got integer — not read"]


# ---------------------------------------------------------------------------
# The stage: a malformed row no longer discards every plugin's output
# ---------------------------------------------------------------------------

def _run_stage(plugins: dict, tmp_path: Path) -> dict:
    """run_volatility with the plugins answered from `plugins` instead of a
    container, and a dump path that exists for get_memory_dump_path but not on
    disk, so no targeted dump runs."""
    def fake_plugin(dump_path, plugin, output_dir, volatility_cmd, extra_args=None):
        return copy.deepcopy(plugins[plugin.replace("windows.", "")])

    with mock.patch.object(volatility, "get_memory_dump_path",
                           return_value=tmp_path / "memory.dmp"), \
            mock.patch.object(volatility, "run_single_plugin", side_effect=fake_plugin), \
            contextlib.redirect_stdout(io.StringIO()):
        return volatility.run_volatility(
            {"id": 1, "status": "reported"}, tmp_path,
            volatility_cmd="/bin/true", volatility_triggers=[],
            volatility_standard_plugins=[f"windows.{p}" for p in sorted(plugins)],
            volatility_extra_plugins={}, malfind_enabled=True,
            get_cape_signatures_fn=lambda cape: [], memory_dump_requested=True,
            cape_injection_pids=None, cape_has_injection_buffers=False,
            parallel_workers=2, **MALFIND)


def test_run_volatility_keeps_its_plugins_when_a_row_is_malformed(tmp_path):
    plugins = copy.deepcopy(PLUGINS)
    plugins["cmdline"].insert(0, None)
    plugins["dlllist"][3]["Path"] = 5
    plugins["malfind"][0]["Hexdump"] = 7
    result = _run_stage(plugins, tmp_path)

    assert set(result["plugins"]) == set(PLUGINS)
    assert result["insights"]["suspicious_cmdlines"]
    assert sorted(result["parse_warnings"]) == [
        "cmdline[0]: expected object, got null — row skipped",
        "dlllist[3].Path: expected string, got integer — not read",
        "malfind[0].Hexdump: expected string, got integer — not read",
    ]
    assert result["_malfind_selected"]


def test_run_volatility_on_a_well_formed_output_records_no_parse_warnings(tmp_path):
    result = _run_stage(PLUGINS, tmp_path)
    assert "parse_warnings" not in result
    assert result["insights"] == GOLDEN["insights"]


def test_parse_warnings_are_bounded(tmp_path):
    plugins = copy.deepcopy(PLUGINS)
    plugins["handles"] = [None] * 5000
    result = _run_stage(plugins, tmp_path)
    assert len(result["parse_warnings"]) == volatility._MAX_PARSE_WARNINGS + 1
    assert result["parse_warnings"][-1] == f"... and {5000 - volatility._MAX_PARSE_WARNINGS} more"


# ---------------------------------------------------------------------------
# Fuzz: any field the readers touch, in any row, replaced by any value
# ---------------------------------------------------------------------------

READ_FIELDS = {
    "cmdline": ["PID", "Process", "Args"],
    "netscan": ["ForeignAddr", "ForeignPort", "LocalPort", "State", "Owner", "PID"],
    "handles": ["Type", "Name", "PID", "Process"],
    "dlllist": ["Path", "PID", "Process"],
    "pstree": ["ImageFileName", "PPID", "PID"],
    "malfind": ["PID", "Process", "Start VPN", "End VPN", "Protection", "File output",
                "Hexdump"],
}
# (plugin, row) and (plugin, row, key) paths into the fixture, plus whole
# plugins: the fuzzer reaches every read, not only the fields of row 0.
PATHS = ([(p,) for p in READ_FIELDS]
         + [(p, i) for p in READ_FIELDS for i in range(len(PLUGINS[p]))]
         + [(p, i, k) for p, keys in READ_FIELDS.items()
            for i in range(len(PLUGINS[p])) for k in keys])



def _hot_rows() -> set[tuple[str, int]]:
    """Rows whose values reach the golden output. Most of the fixture's rows
    contribute nothing (a handle of type Event, a System32 DLL), so a path drawn
    uniformly rarely reaches the code that copies a value into an insight."""
    g = GOLDEN["insights"]
    out_values = {
        "cmdline": {c["cmdline"] for c in g["suspicious_cmdlines"]},
        "netscan": {c["foreign_addr"] for c in g["active_connections"]},
        "handles": {m["mutex"] for m in g["mutexes"]} | {f["path"] for f in g["suspicious_files"]},
        "dlllist": {d["dll_path"] for d in g["suspicious_dlls"]},
        "pstree": {a["process"] for a in g["anomalous_parents"]}
        | {a["parent_process"] for a in g["anomalous_parents"]},
        "malfind": {r["start_vpn"] for r in GOLDEN["malfind_selected"]},
    }
    key = {"cmdline": "Args", "netscan": "ForeignAddr", "handles": "Name", "dlllist": "Path",
           "pstree": "ImageFileName", "malfind": "Start VPN"}
    hot = set()
    for name, values in out_values.items():
        for i, row in enumerate(PLUGINS[name]):
            v = row.get(key[name])
            v = f"0x{v:x}" if name == "malfind" else (v.lower() if name == "pstree" else v)
            if v in values:
                hot.add((name, i))
    return hot


HOT = _hot_rows()
HOT_PATHS = [p for p in PATHS if len(p) >= 2 and (p[0], p[1]) in HOT]

_awkward = st.sampled_from([
    None, "", "x", 0, -1, 1.5, True, False, [], ["x"], [None], {}, {"x": 1},
    2**64, float("inf"), "\\BaseNamedObjects\\SM0:x", "cmd.exe /c x",
])
_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=12),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=6), children, max_size=4),
    max_leaves=12,
)
_mutation = st.tuples(st.sampled_from(PATHS) | st.sampled_from(HOT_PATHS), st.booleans(),
                      _awkward | _json)


def test_the_fuzzer_reaches_rows_that_produce_insights():
    """Guard on the guard: before HOT_PATHS, a reader that let a boolean PID into
    an insight survived 500 fuzz examples, because no drawn path reached a row
    that produces one (observed while mutation-testing this file)."""
    assert {name for name, _ in HOT} == set(READ_FIELDS)
    assert len(HOT_PATHS) > 100


def _apply(plugins: dict, path: tuple, delete: bool, value) -> None:
    node = plugins
    for key in path[:-1]:
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return  # an earlier mutation replaced an ancestor
    if isinstance(node, dict) and delete:
        node.pop(path[-1], None)
    elif isinstance(node, dict) or (isinstance(node, list) and isinstance(path[-1], int)
                                    and path[-1] < len(node)):
        node[path[-1]] = value


def _well_typed(found: dict) -> None:
    """Every insight field has the type a consumer expects (or the null a
    well-formed output could already carry)."""
    json.dumps(found)
    for c in found.get("suspicious_cmdlines", []):
        assert isinstance(c["cmdline"], str) and isinstance(c["pattern"], str)
        assert c["pid"] is None or type(c["pid"]) is int
    for c in found.get("active_connections", []):
        assert isinstance(c["foreign_addr"], str)
        for k in ("pid", "foreign_port", "local_port"):
            assert c[k] is None or type(c[k]) is int
        for k in ("process", "state"):
            assert c[k] is None or isinstance(c[k], str)
    for m in found.get("mutexes", []):
        assert isinstance(m["mutex"], str)
        assert all(p is None or isinstance(p, str) for p in m["unique_processes"])
    for f in found.get("suspicious_files", []):
        assert isinstance(f["path"], str)
    for d in found.get("suspicious_dlls", []):
        assert isinstance(d["dll_path"], str)
    for a in found.get("anomalous_parents", []):
        assert isinstance(a["process"], str) and isinstance(a["parent_process"], str)


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(mutations=st.lists(_mutation, min_size=1, max_size=4))
def test_no_wrong_typed_value_raises(mutations):
    """Totality, typed output, and warnings that carry no plugin text."""
    plugins = copy.deepcopy(PLUGINS)
    for path, delete, value in mutations:
        _apply(plugins, path, delete, value)
    warnings: list[str] = []
    found = insights(plugins, warnings)
    selected, pids = malfind(plugins.get("malfind"), warnings)

    _well_typed(found)
    for r in selected:
        assert type(r["pid"]) is int and isinstance(r["process"], str)
        assert isinstance(r["file_output"], str) or r["file_output"] is None
    assert all(type(p) is int for p in pids)
    bad = [w for w in warnings if not WARNING.fullmatch(w)]
    assert not bad, bad
    # A row replaced by a non-object is always named.
    for path, delete, value in mutations:
        if (len(path) == 2 and not delete and not isinstance(value, dict)
                and isinstance(plugins.get(path[0]), list) and path[1] < len(plugins[path[0]])
                and plugins[path[0]][path[1]] is value):
            assert f"{path[0]}[{path[1]}]: expected object, got " in "\n".join(warnings)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(mutations=st.lists(st.tuples(st.sampled_from([p for p in PATHS if len(p) >= 2
                                                     and p[0] in ("cmdline", "netscan")]),
                                    st.booleans(), _awkward | _json),
                          min_size=1, max_size=3))
def test_a_wrong_typed_row_costs_at_most_that_row(mutations):
    """The other rows are still read. cmdline and netscan have no dedup or cap,
    so their insights from the untouched rows must all survive: compare against
    the same plugins with the touched rows deleted outright."""
    plugins = copy.deepcopy(PLUGINS)
    touched: dict[str, set[int]] = {"cmdline": set(), "netscan": set()}
    for path, delete, value in mutations:
        _apply(plugins, path, delete, value)
        touched[path[0]].add(path[1])
    without = {name: [r for i, r in enumerate(PLUGINS[name]) if i not in touched[name]]
               for name in touched}
    expected = insights(without)
    found = insights(plugins)
    for key in ("suspicious_cmdlines", "active_connections"):
        for entry in expected.get(key, []):
            assert entry in found.get(key, []), (key, entry)
