# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A malformed Cape or Volatility value must not cost the run its correlation (#686).

The rules read guest-described data — Volatility plugin rows, Cape's process
command lines and injection buffers — with `.get(...)` chains, and
`dict.get(k, default)` returns the default only when k is ABSENT. Probing every
path of a well-formed report with None, "", str, int, float, bool, list and
dict (and deleting each key), 212 of 663 probes raised out of cross_correlate on
origin/main (ac1767f). The distinct sites, in origin/main line numbers:

    volatility = None                       AttributeError rule_dropped_file_loaded:309
    cape = None                             AttributeError _gather_vad_samples:203
    cape.injection_buffers = "x"            AttributeError _gather_vad_samples:204
    dlllist = [1, ...]                      AttributeError rule_dropped_file_loaded:323
    cmdline = [1, ...]                      AttributeError rule_cmdline_spoofing:498
    malfind = [1, ...]                      AttributeError rule_injection_corroborated:920
    injection_buffers[0].path = 5           TypeError      _within_allowed_root:43
    cape.process_cmdlines = ["x"]           AttributeError rule_cmdline_spoofing:504
    volatility.plugins = "x"                AttributeError _gather_vad_samples:193
    dlllist[i].Path = 5                     AttributeError _normalise_win_path:295
    cape.status = []                        TypeError      _cape_unavailable_reason:1037
    injection_buffers[0].target_pid = []    TypeError      rule_injection_corroborated:928
    process_cmdlines[pid] = 5 / [1] / ["x"] _split_cmdline:453 / :456, rule_cmdline_spoofing:526
    cmdline[i].Args = 5                     TypeError      _split_cmdline:453
    malfind[i].PID = []                     TypeError      rule_injection_corroborated:922
    vadinfo[i].PID = []                     TypeError      _gather_vad_string_hits:827
    vadinfo[i].PID = "1364" (mixed types)   TypeError      _gather_vad_string_hits:835
    extracted_configs C2 = "http://[::1"    ValueError     _add:639 (urlsplit)
    volatility.vad_dump_dir = 5             TypeError      _within_allowed_root:43

What the caller did with it: run-pipeline calls cross_correlate with nothing
around it (run_pipeline, and run_replay's correlate stage), before report.json
is first written. So the raise ended the run after Cape, Volatility and Ghidra
had finished, and lost all of it — not only the correlation, and not only the
RE agent's evidence that #680 feeds from it.

Each case below drives the real entrypoint on the trimmed real fixture
(fixtures/correlation_v655.py), on which every rule fires.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import re
from pathlib import Path
from unittest import mock

import lamware_pipeline.correlation_rules as cr
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

_spec = importlib.util.spec_from_file_location(
    "correlation_v655", Path(__file__).parent / "fixtures" / "correlation_v655.py")
fx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fx)

ALL_TYPES = {"dropped_file_loaded", "shellcode_self_modified", "cmdline_spoofing",
             "c2_live_in_memory", "injection_corroborated"}
PLUGINS = fx.REPORT["volatility"]["plugins"]
# Indices into the fixture, chosen so a mutation hits a row that is NOT the one
# a finding comes from — the point is that the rest still correlates.
LOADED_PATH = next(r["Path"] for r in PLUGINS["dlllist"] if isinstance(r.get("Path"), str))
OTHER_DLL = next(i for i, r in enumerate(PLUGINS["dlllist"])
                 if isinstance(r.get("Path"), str) and r["Path"] != LOADED_PATH)
MALFIND_1364 = next(i for i, r in enumerate(PLUGINS["malfind"]) if r["PID"] == 1364)
DUMPED_VAD = next(i for i, r in enumerate(PLUGINS["vadinfo"]) if fx._dump_name(r["File output"]))
# A Cape command line whose PID also has one in Volatility, other than the
# spoofed one and the benign-flag one: only a pair with both sides present
# reached the code that raised.
_VOL_ARGS = {str(r["PID"]) for r in PLUGINS["cmdline"] if isinstance(r.get("Args"), str)}
CMD_INDEX, CMD_PID = next((i, pid) for i, pid in enumerate(fx.REPORT["cape"]["process_cmdlines"])
                          if pid in _VOL_ARGS
                          and pid not in (fx.SPOOFED_PID, fx.BENIGN_FLAGS_PID))
CMDLINE_ROW = next(i for i, r in enumerate(PLUGINS["cmdline"]) if str(r["PID"]) == CMD_PID)


def _run(report: dict, storage: str, reports: str) -> tuple[list[dict], list[str]]:
    with mock.patch.object(cr, "_CAPE_STORAGE_ROOT", storage), \
            mock.patch.object(cr, "_PIPELINE_REPORTS_ROOT", reports):
        findings = cr.cross_correlate(report)
    return findings, report["correlation_warnings"]


@pytest.fixture
def fixture_report(tmp_path):
    report, storage, reports = fx.materialise(tmp_path)
    return report, storage, reports, tmp_path


# ---------------------------------------------------------------------------
# Well-formed input: exactly what origin/main produced
# ---------------------------------------------------------------------------

def test_a_well_formed_report_correlates_exactly_as_before(fixture_report):
    report, storage, reports, root = fixture_report
    findings, warnings = _run(report, storage, reports)
    got = fx.comparable(findings, warnings, root)
    assert got["findings"] == fx.GOLDEN["findings"]
    assert got["correlation_warnings"] == fx.GOLDEN["correlation_warnings"]


def test_the_golden_reaches_every_rule():
    """Guard on the guard: a golden in which a rule never fired would pass
    whatever that rule now does with its rows."""
    assert {f["type"] for f in fx.GOLDEN["findings"]} == ALL_TYPES


def test_the_golden_spoof_is_the_synthetic_one_not_the_benign_flags():
    """#696: the host's `-secured -Embedding` pair is in the fixture and must not
    be in the golden; the spoof that keeps the rule covered is the added one."""
    spoofs = {f["pid"] for f in fx.GOLDEN["findings"] if f["type"] == "cmdline_spoofing"}
    assert spoofs == {fx.SPOOFED_PID}
    cape = fx.REPORT["cape"]["process_cmdlines"][fx.BENIGN_FLAGS_PID].lower()
    assert "-secured" in cape and "-embedding" in cape, "the benign pair left the fixture"
    assert fx.GOLDEN["_produced_by"].startswith("origin/main")


def test_the_report_is_left_as_before(fixture_report):
    """Beyond the return value: the inputs are popped and nothing else is added."""
    report, storage, reports, _ = fixture_report
    before = set(report)
    _run(report, storage, reports)
    assert set(report) - before == {"correlation_warnings"}


# ---------------------------------------------------------------------------
# Each reproduced crash: no raise, the bad value named, the rest still correlated
# ---------------------------------------------------------------------------

def _set(*path, value):
    def mutate(report):
        node = report
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return mutate


def _prepend(plugin, value):
    def mutate(report):
        report["volatility"]["plugins"][plugin].insert(0, value)
    return mutate


def _also_c2(report):
    report["cape"]["extracted_configs"][0]["Family"]["C2"].insert(0, "http://[::1")


V, P, C = "volatility", "plugins", "cape"
CASES = [
    # (id, mutation, finding types that must survive, warning it must carry)
    ("volatility-null", _set(V, value=None), {"c2_live_in_memory"}, None),
    ("volatility-string", _set(V, value="x"), {"c2_live_in_memory"},
     "volatility: expected object, got string — not read"),
    ("cape-null", _set(C, value=None), set(), None),
    ("cape-array", _set(C, value=[]), set(), "cape: expected object, got array — not read"),
    ("injection_buffers-string", _set(C, "injection_buffers", value="x"),
     {"dropped_file_loaded", "cmdline_spoofing", "c2_live_in_memory"},
     "cape.injection_buffers: expected array, got string — not read"),
    ("dlllist-row-int", _prepend("dlllist", 1), ALL_TYPES,
     "dlllist[0]: expected object, got integer — row skipped"),
    ("cmdline-row-int", _prepend("cmdline", 1), ALL_TYPES,
     "cmdline[0]: expected object, got integer — row skipped"),
    ("malfind-row-int", _prepend("malfind", 1), ALL_TYPES,
     "malfind[0]: expected object, got integer — row skipped"),
    ("buffer-path-int", _set(C, "injection_buffers", 1, "path", value=5),
     ALL_TYPES,   # buffer 0 is the self-modified one
     "cape.injection_buffers[1].path: expected string, got integer — not read"),
    ("process_cmdlines-array", _set(C, "process_cmdlines", value=["x"]),
     ALL_TYPES - {"cmdline_spoofing"},
     "cape.process_cmdlines: expected object, got array — not read"),
    ("plugins-string", _set(V, P, value="x"), {"c2_live_in_memory"}, None),
    ("dll-path-int", _set(V, P, "dlllist", OTHER_DLL, "Path", value=5), ALL_TYPES,
     f"dlllist[{OTHER_DLL}].Path: expected string, got integer — not read"),
    ("cape-status-array", _set(C, "status", value=[]), ALL_TYPES, None),
    ("buffer-target_pid-array", _set(C, "injection_buffers", 1, "target_pid", value=[]),
     ALL_TYPES, "cape.injection_buffers[1].target_pid: expected integer, got array — not read"),
    ("cape-cmdline-int", _set(C, "process_cmdlines", CMD_PID, value=5), ALL_TYPES,
     f"cape.process_cmdlines[{CMD_INDEX}]: expected string, got integer — not read"),
    ("cape-cmdline-list-of-int", _set(C, "process_cmdlines", CMD_PID, value=[1]), ALL_TYPES,
     f"cape.process_cmdlines[{CMD_INDEX}]: expected string, got array — not read"),
    ("cape-cmdline-list-of-str", _set(C, "process_cmdlines", CMD_PID, value=["x"]), ALL_TYPES,
     f"cape.process_cmdlines[{CMD_INDEX}]: expected string, got array — not read"),
    ("cmdline-args-int", _set(V, P, "cmdline", CMDLINE_ROW, "Args", value=5), ALL_TYPES,
     f"cmdline[{CMDLINE_ROW}].Args: expected string, got integer — not read"),
    ("malfind-pid-array", _set(V, P, "malfind", MALFIND_1364, "PID", value=[]), ALL_TYPES,
     f"malfind[{MALFIND_1364}].PID: expected integer, got array — not read"),
    ("vadinfo-pid-array", _set(V, P, "vadinfo", DUMPED_VAD, "PID", value=[]), ALL_TYPES,
     f"vadinfo[{DUMPED_VAD}].PID: expected integer, got array — not read"),
    ("vadinfo-pid-string", _set(V, P, "vadinfo", DUMPED_VAD, "PID", value="1364"), ALL_TYPES,
     f"vadinfo[{DUMPED_VAD}].PID: expected integer, got string — not read"),
    ("c2-unparseable-url", _also_c2, ALL_TYPES, None),
    ("vad_dump_dir-int", _set(V, "vad_dump_dir", value=5),
     ALL_TYPES - {"shellcode_self_modified"},
     "volatility.vad_dump_dir: expected string, got integer — not read"),
]


@pytest.mark.parametrize("mutate, kept, warning", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_a_malformed_value_costs_only_its_row(fixture_report, mutate, kept, warning):
    report, storage, reports, _ = fixture_report
    mutate(report)
    findings, warnings = _run(report, storage, reports)   # origin/main raised here
    assert kept <= {f["type"] for f in findings}
    # Every guard of last resort stayed quiet: the readers caught the shape.
    assert not [w for w in warnings if w.startswith(
        ("Correlation rule", "Correlation input '", "Correlation coverage check failed"))], \
        warnings
    if warning is not None:
        malformed = [w for w in warnings if w.startswith("Correlation input malformed")]
        assert len(malformed) == 1 and warning in malformed[0], warnings


def test_the_cases_raised_on_origin_main():
    """Guard on the reproduction: each case above is one origin/main raised on.
    The module as it stood before #686 is rebuilt from git so the claim is
    checked, not remembered. Skipped outside a git checkout."""
    import subprocess
    root = Path(__file__).resolve().parents[2]
    try:
        src = subprocess.run(
            ["git", "-C", str(root), "show", "ac1767f:pipeline/lamware_pipeline/correlation_rules.py"],
            capture_output=True, text=True, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("origin/main source not available")
    old = type(cr)("old_correlation_rules")
    exec(compile(src, "old_correlation_rules.py", "exec"), old.__dict__)  # noqa: S102 — our own file at a pinned commit
    survived = []
    for case_id, mutate, _kept, _warning in CASES:
        with pytest.MonkeyPatch.context() as mp:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                report, storage, reports = fx.materialise(Path(tmp))
                mutate(report)
                mp.setattr(old, "_CAPE_STORAGE_ROOT", storage)
                mp.setattr(old, "_PIPELINE_REPORTS_ROOT", reports)
                try:
                    old.cross_correlate(report)
                except Exception:  # noqa: BLE001 — any raise is the reproduction
                    continue
                survived.append(case_id)
    assert survived == [], f"not a reproduction: {survived}"


def test_a_malformed_warning_carries_no_value_from_the_report(fixture_report):
    report, storage, reports, _ = fixture_report
    report["volatility"]["plugins"]["dlllist"][OTHER_DLL]["Path"] = ["SENTINEL-guest-text"]
    report["cape"]["process_cmdlines"][CMD_PID] = {"SENTINEL-guest-text": 1}
    _, warnings = _run(report, storage, reports)
    assert "SENTINEL" not in json.dumps(warnings)


def test_many_malformed_values_are_one_bounded_warning(fixture_report):
    """The interpret prompt shows six warnings at 220 characters. Fifty bad rows
    must not push the rule-level warnings out of it."""
    report, storage, reports, _ = fixture_report
    report["volatility"]["plugins"]["cmdline"][:0] = [None] * 50
    _, warnings = _run(report, storage, reports)
    malformed = [w for w in warnings if w.startswith("Correlation input malformed")]
    assert len(malformed) == 1
    assert "50 value(s) not read" in malformed[0] and "and 47 more" in malformed[0]
    assert len(malformed[0]) < 500   # db_ingest clips each entry at 500


def test_the_same_bad_value_read_by_several_steps_is_counted_once(fixture_report):
    """injection_buffers is read by four steps; one bad field is one value."""
    report, storage, reports, _ = fixture_report
    report["cape"]["injection_buffers"][1]["target_pid"] = []
    _, warnings = _run(report, storage, reports)
    malformed = [w for w in warnings if w.startswith("Correlation input malformed")]
    assert "1 value(s) not read" in malformed[0]


# ---------------------------------------------------------------------------
# One rule, one step: whatever still raises costs only itself
# ---------------------------------------------------------------------------

def _boom(*_a, **_k):
    raise RuntimeError("SENTINEL-guest-text")


def test_a_rule_that_raises_costs_only_its_own_findings(fixture_report, monkeypatch):
    report, storage, reports, _ = fixture_report
    rules = list(cr._RULES)
    rules[rules.index(cr.rule_cmdline_spoofing)] = _named(_boom, "rule_cmdline_spoofing")
    monkeypatch.setattr(cr, "_RULES", rules)
    findings, warnings = _run(report, storage, reports)
    assert {f["type"] for f in findings} == ALL_TYPES - {"cmdline_spoofing"}
    assert ("Correlation rule rule_cmdline_spoofing failed (RuntimeError) — its findings "
            "are missing, so their absence is not a clean result") in warnings
    assert "SENTINEL" not in json.dumps(warnings)   # the type, never the message


def _named(fn, name):
    def wrapper(*a, **k):
        return fn(*a, **k)
    wrapper.__name__ = name
    return wrapper


@pytest.mark.parametrize("step, gatherer, lost", [
    ("buffer_samples", "_gather_buffer_samples", "shellcode_self_modified"),
    ("vad_samples", "_gather_vad_samples", "shellcode_self_modified"),
    ("dropped_files", "_gather_dropped_files", "dropped_file_loaded"),
    ("c2_indicators", "_cape_c2_string_indicators", "c2_live_in_memory"),
])
def test_an_enrichment_step_that_raises_costs_only_what_it_gathers(
        fixture_report, monkeypatch, step, gatherer, lost):
    report, storage, reports, _ = fixture_report
    monkeypatch.setattr(cr, gatherer, _boom)
    findings, warnings = _run(report, storage, reports)
    assert {f["type"] for f in findings} == ALL_TYPES - {lost}
    assert any(w.startswith(f"Correlation input '{step}' could not be gathered (RuntimeError)")
               for w in warnings), warnings
    assert "SENTINEL" not in json.dumps(warnings)


def test_a_coverage_check_that_raises_still_returns_the_findings(fixture_report, monkeypatch):
    report, storage, reports, _ = fixture_report
    monkeypatch.setattr(cr, "correlation_warnings", _boom)
    findings, warnings = _run(report, storage, reports)
    assert {f["type"] for f in findings} == ALL_TYPES
    assert warnings[0].startswith("Correlation coverage check failed (RuntimeError)")
    assert "_correlation_inputs" not in report


def test_a_direct_caller_without_a_failures_list_still_sees_the_raise(monkeypatch):
    """evaluate_rules(report) has always propagated; swallowing with nobody to
    report to would be the silent degradation #411 forbids."""
    monkeypatch.setattr(cr, "_RULES", [_boom])
    with pytest.raises(RuntimeError):
        cr.evaluate_rules({})


# ---------------------------------------------------------------------------
# The caller: run-pipeline's correlate stage carries on
# ---------------------------------------------------------------------------

RUN_PIPELINE = (Path(__file__).resolve().parents[2]
                / "ansible/roles/pipeline/files/run-pipeline.py")


def test_replay_correlate_survives_a_bad_row_and_a_failing_rule(fixture_report, monkeypatch):
    """run_replay's correlate stage calls cross_correlate with nothing around
    it, exactly as run_pipeline does before Stage 4.5. Driven for real, with a
    malformed row AND a rule that raises: the replay report is still written,
    carrying the other rules' findings and both warnings."""
    report, storage, reports, _ = fixture_report
    spec = importlib.util.spec_from_file_location("run_pipeline_686", RUN_PIPELINE)
    rp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rp)

    report["volatility"]["plugins"]["cmdline"].insert(0, None)
    task_dir = Path(reports) / report["task_id"]
    original = task_dir / "report.json"
    original.write_text(json.dumps(report))

    rules = list(cr._RULES)
    rules[rules.index(cr.rule_injection_corroborated)] = _named(_boom, "rule_injection_corroborated")
    monkeypatch.setattr(cr, "_RULES", rules)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", storage)
    monkeypatch.setattr(cr, "_PIPELINE_REPORTS_ROOT", reports)
    monkeypatch.setattr(rp, "REPORTS_DIR", Path(reports))
    monkeypatch.setattr(rp, "add_file_logging", lambda _d: None)
    assert rp.cross_correlate is cr.cross_correlate   # the real entrypoint, not a stub

    out = rp.run_replay(original, stages=["correlate"])

    written = [p for p in task_dir.glob("report*.json") if p != original]
    assert len(written) == 1
    saved = json.loads(written[0].read_text())
    assert {f["type"] for f in saved["cross_correlations"]} == ALL_TYPES - {"injection_corroborated"}
    assert any(w.startswith("Correlation rule rule_injection_corroborated failed")
               for w in saved["correlation_warnings"])
    assert any("cmdline[0]: expected object, got null — row skipped" in w
               for w in saved["correlation_warnings"])
    assert out["cross_correlations"] == saved["cross_correlations"]


# ---------------------------------------------------------------------------
# Fuzz: any value the rules touch, anywhere in the fixture, replaced or removed
# ---------------------------------------------------------------------------

READ_FIELDS = {
    "dlllist": ["Path", "PID", "Process"],
    "cmdline": ["PID", "Args"],
    "malfind": ["PID"],
    "vadinfo": ["PID", "Start VPN", "End VPN", "File output"],
}
BUFFER_FIELDS = ["target_pid", "injection_address", "path"]
PATHS = (
    [(V,), (C,), (V, P), (V, "vad_dump_dir"), (V, "triggered"), (V, "error"),
     (C, "injection_buffers"), (C, "process_cmdlines"), (C, "status"), (C, "task_id"),
     (C, "extracted_configs"), (C, "error")]
    + [(V, P, p) for p in READ_FIELDS]
    + [(V, P, p, i) for p in READ_FIELDS for i in range(len(PLUGINS[p]))]
    + [(V, P, p, i, k) for p, keys in READ_FIELDS.items()
       for i in range(len(PLUGINS[p])) for k in keys]
    + [(C, "injection_buffers", i, k) for i in range(2) for k in BUFFER_FIELDS]
    + [(C, "injection_buffers", i) for i in range(2)]
    + [(C, "process_cmdlines", pid) for pid in fx.REPORT["cape"]["process_cmdlines"]]
)
# The rows findings come from: a path drawn uniformly over ~1000 rarely lands
# on one, and those are where a wrong type would reach the output.
HOT_PATHS = (
    [(V, P, "dlllist", i, k) for i, r in enumerate(PLUGINS["dlllist"])
     if r.get("Path") == LOADED_PATH for k in READ_FIELDS["dlllist"]]
    + [(V, P, "cmdline", i, k) for i, r in enumerate(PLUGINS["cmdline"])
       if str(r["PID"]) in (fx.SPOOFED_PID, fx.BENIGN_FLAGS_PID) for k in READ_FIELDS["cmdline"]]
    + [(V, P, "malfind", i, "PID") for i, r in enumerate(PLUGINS["malfind"]) if r["PID"] == 1364]
    + [(V, P, "vadinfo", i, k) for i, r in enumerate(PLUGINS["vadinfo"])
       if fx._dump_name(r["File output"]) for k in READ_FIELDS["vadinfo"]]
    + [(C, "injection_buffers", i, k) for i in range(2) for k in BUFFER_FIELDS]
    + [(C, "process_cmdlines", fx.SPOOFED_PID), (C, "process_cmdlines", fx.BENIGN_FLAGS_PID)]
)

_awkward = st.sampled_from([
    None, "", "x", 0, -1, 1.5, True, False, [], ["x"], [None], [[1]], {}, {"x": 1},
    2**64, float("inf"), "http://[::1", "SENTINEL-guest-text", "0xZZ",
])
_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=12),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=6), children, max_size=4),
    max_leaves=12,
)
_mutation = st.tuples(st.sampled_from(PATHS) | st.sampled_from(HOT_PATHS), st.booleans(),
                      _awkward | _json)


def test_the_fuzzer_reaches_rows_that_produce_findings():
    """Guard on the guard (the lesson of #685's fuzz): the hot paths exist."""
    assert len([p for p in HOT_PATHS if p[2:3] == ("dlllist",)]) >= 3
    assert any(p[2:3] == ("cmdline",) for p in HOT_PATHS)
    assert len([p for p in HOT_PATHS if p[2:3] == ("malfind",)]) >= 10
    assert any(p[2:3] == ("vadinfo",) for p in HOT_PATHS)


def _apply(report: dict, path: tuple, delete: bool, value) -> None:
    node = report
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


_OURS = re.compile(
    r"Correlation input malformed: \d+ value\(s\) not read \("
    r"((cape|volatility)(\.[a-z_]+)?|[a-z_.]+(\[\d+\])?(\.[A-Za-z _]+)?)"
    r": expected (object|array|string|integer), got \w+ — (not read|row skipped)")


@pytest.fixture(scope="module")
def fuzz_root(tmp_path_factory):
    root = tmp_path_factory.mktemp("fuzz686")
    report, storage, reports = fx.materialise(root)
    return report, storage, reports


@settings(max_examples=500, deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
@given(mutations=st.lists(_mutation, min_size=1, max_size=4))
def test_no_wrong_typed_value_raises(fuzz_root, mutations):
    """Totality, well-typed findings, and no rule ever needing its try: the
    readers catch every shape, so "Correlation rule ... failed" would mean one
    got past them."""
    base, storage, reports = fuzz_root
    report = copy.deepcopy(base)
    for path, delete, value in mutations:
        _apply(report, path, delete, value)
    findings, warnings = _run(report, storage, reports)

    json.dumps(findings)
    for f in findings:
        assert f["type"] in ALL_TYPES and isinstance(f["title"], str)
        assert isinstance(f["detail"], str) and f["sources"] == ["Cape", "Volatility"]
        if "pid" in f:
            assert f["pid"] is None or type(f["pid"]) in (int, str)
    assert all(isinstance(w, str) for w in warnings)
    ours = [w for w in warnings if w.startswith("Correlation")]
    assert not [w for w in ours if w.startswith(
        ("Correlation rule", "Correlation input '", "Correlation coverage check failed"))], ours
    for w in ours:
        if w.startswith("Correlation input malformed"):
            assert _OURS.match(w), w
            assert "SENTINEL" not in w
    assert "_correlation_inputs" not in report
