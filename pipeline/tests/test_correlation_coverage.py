# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A correlation rule that could not run must not read as a rule that found nothing.

Every rule guards its Volatility input with `isinstance(..., list)`, because a
plugin that failed hands back `{"error": ...}` from `run_single_plugin` and must
not be iterated. The guard is right; what it returned was not distinguishable
from a clean result. `run-pipeline` then logged the merged outcome as
"No cross-tool findings detected", which is a claim about the sample it had not
established.

The path is ordinary, not exotic: `malfind` runs under a 120s cap whose own
comment says "partial results acceptable", so on a large dump a timeout is an
expected outcome. Both injection rules go quiet, and the report says the sample
was checked for injection and came back clean.

Same rule as `PayloadAccessError` (lamware_shared.cape_payloads) and the Ghidra
`analysis_warnings` surface (#315/#367): "I could not look" is its own answer.
"""
import re
from pathlib import Path

import lamware_pipeline.correlation_rules as cr
from lamware_pipeline.correlation import correlation_warnings as reexported
from lamware_pipeline.correlation_rules import (
    _PLUGIN_CONSUMERS,
    correlation_warnings,
    cross_correlate,
)

SOURCE = Path(cr.__file__).read_text(encoding="utf-8")

# Matches the accessor every rule uses: .get("plugins", {}).get("<name>", ...)
_PLUGIN_READ = re.compile(r'\.get\("plugins",\s*\{\}\)\.get\("([a-z_]+)"')


def _plugins(**kw):
    return {"volatility": {"plugins": dict(kw)}}


# --- the contract: declared consumers must match what the rules actually read ---

def test_every_plugin_a_rule_reads_is_declared():
    """The failure this prevents: a new rule reads a new plugin, that plugin
    fails in production, and its silence goes unreported because nothing
    declared that anything depended on it."""
    read_in_source = set(_PLUGIN_READ.findall(SOURCE))
    assert read_in_source, "accessor pattern stopped matching — update _PLUGIN_READ"
    undeclared = read_in_source - set(_PLUGIN_CONSUMERS)
    assert not undeclared, (
        f"correlation rules read Volatility plugin(s) {sorted(undeclared)} that "
        f"_PLUGIN_CONSUMERS does not declare, so their failure would be silent"
    )


def test_no_declared_consumer_is_stale():
    """The mirror: a plugin declared but no longer read produces a warning about
    a rule that does not exist."""
    read_in_source = set(_PLUGIN_READ.findall(SOURCE))
    stale = set(_PLUGIN_CONSUMERS) - read_in_source
    assert not stale, f"_PLUGIN_CONSUMERS declares unread plugin(s): {sorted(stale)}"


# --- degraded input is reported, not merged into "clean" ---

def test_timed_out_malfind_is_reported_not_silent():
    report = _plugins(malfind={"error": "timeout (120s)"}, dlllist=[], cmdline=[], netscan=[])
    warnings = correlation_warnings(report)
    assert len(warnings) == 1
    assert "malfind" in warnings[0]
    assert "timeout (120s)" in warnings[0]


def test_plugin_that_never_ran_is_reported():
    report = _plugins(dlllist=[], cmdline=[], netscan=[])   # malfind absent
    warnings = correlation_warnings(report)
    assert len(warnings) == 1
    assert "malfind" in warnings[0] and "not run" in warnings[0]


def test_all_plugins_healthy_produces_no_warnings():
    report = _plugins(malfind=[], dlllist=[], cmdline=[], netscan=[])
    assert correlation_warnings(report) == []


def test_every_declared_plugin_is_individually_detected():
    """Each entry earns its place — none is dead weight that never fires."""
    for name in _PLUGIN_CONSUMERS:
        healthy = {n: [] for n in _PLUGIN_CONSUMERS}
        healthy.pop(name)
        warnings = correlation_warnings(_plugins(**healthy))
        assert len(warnings) == 1 and name in warnings[0], f"{name} not detected"


def test_unexpected_output_shape_is_reported():
    report = _plugins(malfind="not a list", dlllist=[], cmdline=[], netscan=[])
    warnings = correlation_warnings(report)
    assert len(warnings) == 1 and "unexpected str output" in warnings[0]


# --- absent stages are not degradation ---

def test_volatility_not_triggered_is_not_a_correlation_warning():
    """Volatility is signature-gated. A sample that never reached it is a reported
    pipeline state, not a correlation rule silently failing."""
    assert correlation_warnings({}) == []
    assert correlation_warnings({"volatility": {}}) == []
    assert correlation_warnings(
        {"volatility": {"triggered": False, "reason": "no trigger signatures"}}) == []


def test_whole_stage_timeout_warns_for_every_rule():
    """run-pipeline writes {"triggered": True, "error": "timeout (45 min)"} when the
    stage blows its 45-minute budget. That dict has no "plugins" key, so the
    per-plugin path cannot see it — and it is the severest case, since every rule
    is blind at once rather than one."""
    report = {"volatility": {"triggered": True, "error": "timeout (45 min)"}}
    warnings = correlation_warnings(report)
    assert len(warnings) == len(_PLUGIN_CONSUMERS)
    assert all("timeout (45 min)" in w for w in warnings)
    for description in _PLUGIN_CONSUMERS.values():
        assert any(description in w for w in warnings)


def test_stage_error_without_triggered_flag_still_warns():
    assert len(correlation_warnings({"volatility": {"error": "container died"}})) == len(
        _PLUGIN_CONSUMERS)


# --- the entrypoint publishes it ---

def test_cross_correlate_publishes_warnings_onto_the_report():
    report = _plugins(malfind={"error": "timeout (120s)"}, dlllist=[], cmdline=[], netscan=[])
    findings = cross_correlate(report)
    assert findings == []
    assert len(report["correlation_warnings"]) == 1
    assert "malfind" in report["correlation_warnings"][0]


def test_cross_correlate_sets_empty_warnings_when_healthy():
    """The key is always present, so a consumer can tell "checked, clean" from
    "never populated" without treating a missing key as either."""
    report = _plugins(malfind=[], dlllist=[], cmdline=[], netscan=[])
    cross_correlate(report)
    assert report["correlation_warnings"] == []


# --- the Cape half of rule_dropped_file_loaded gets the same treatment ---

def test_an_unreadable_cape_manifest_is_reported_not_silent(tmp_path, monkeypatch):
    """rule_dropped_file_loaded was blind on every run for a reason no plugin
    check could catch: its Cape input listed `<task>/dropped/`, a directory
    CAPEv2 does not create. Volatility was healthy, so nothing warned, and the
    rule's silence read as "no dropped file was loaded"."""
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(tmp_path / "storage"))
    report = _plugins(malfind=[], dlllist=[], cmdline=[], netscan=[])
    report["cape"] = {"task_id": 7}
    cross_correlate(report)
    assert len(report["correlation_warnings"]) == 1
    warning = report["correlation_warnings"][0]
    assert "Cape dropped-file manifest unavailable" in warning
    assert _PLUGIN_CONSUMERS["dlllist"] in warning


def test_a_readable_manifest_produces_no_cape_warning(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    (root / "7").mkdir(parents=True)
    (root / "7" / "files.json").write_text("", encoding="utf-8")
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    report = _plugins(malfind=[], dlllist=[], cmdline=[], netscan=[])
    report["cape"] = {"task_id": 7}
    cross_correlate(report)
    assert report["correlation_warnings"] == []


def test_a_dead_dlllist_does_not_also_warn_about_the_manifest(tmp_path, monkeypatch):
    """One blind rule, one warning. When dlllist itself failed, the rule could
    not have run whatever the manifest said."""
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(tmp_path / "storage"))
    report = _plugins(malfind=[], dlllist={"error": "timeout"}, cmdline=[], netscan=[])
    report["cape"] = {"task_id": 7}
    cross_correlate(report)
    assert len(report["correlation_warnings"]) == 1
    assert "Volatility dlllist unavailable" in report["correlation_warnings"][0]


def test_helper_is_reexported_from_correlation_module():
    assert reexported is correlation_warnings
