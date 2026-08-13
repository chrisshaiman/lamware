# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

"""Tests for investigation agent tool definitions and implementations.

Tools that touch a DB or subprocess are not tested here — those require a live
deployment. This file covers pure-Python logic: _pin_finding, _cape_task_id,
_get_api_traces, _get_pcap_summary, and TOOL_DEFINITIONS structural sanity.

Loading strategy: stub out the heavy imports (sqlalchemy, sqlmodel, app.config)
via sys.modules before exec'ing tools.py, so we don't need the full FastAPI
stack or a DB connection.
"""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests._module_stubs import restore, snapshot

# ---------------------------------------------------------------------------
# Stub external dependencies before loading tools.py
# ---------------------------------------------------------------------------

# Restored once tools.py has been exec'd — a leaked stub is visible to every test
# module pytest collects afterwards. See _module_stubs.py.
_STUBBED_NAMES = ("sqlalchemy", "sqlmodel", "app", "app.config")
_SAVED_MODULES = snapshot(_STUBBED_NAMES)

# sqlalchemy stub — force-assigned so this file's exec always sees it,
# regardless of collection order.
_sa = types.ModuleType("sqlalchemy")
_sa.text = MagicMock()  # type: ignore[attr-defined]
sys.modules["sqlalchemy"] = _sa

# sqlmodel stub — force-assigned.  Includes col/select so that if the router
# test collects after this file the router's setdefault still provides those
# attributes; but the router test also force-assigns its own richer stub, so
# the order doesn't matter.
_sm = types.ModuleType("sqlmodel")
_sm.Session = MagicMock()  # type: ignore[attr-defined]
_sm.col = MagicMock()  # type: ignore[attr-defined]
_sm.select = MagicMock()  # type: ignore[attr-defined]
sys.modules["sqlmodel"] = _sm

# app.config stub — provide a settings object with the fields tools.py reads.
# All numeric/string attributes that any exec'd module compares against are
# set to concrete values so that whichever stub wins a later setdefault the
# comparison still works.
_cfg_pkg = types.ModuleType("app")
_cfg_mod = types.ModuleType("app.config")

_settings = MagicMock()
_settings.sandbox_cmd = "/usr/local/bin/run-sandbox"
_settings.ghidra_cmd = "/usr/local/bin/run-ghidra"
_settings.sandbox_timeout_seconds = 30
_settings.sandbox_memory_mb = 256
_settings.sandbox_max_script_bytes = 10240
_settings.litellm_url = "http://127.0.0.1:4000"
_settings.litellm_key = "sk-test"
_settings.investigation_max_tool_calls_per_turn = 10
_settings.investigation_max_turns = 50
_settings.investigation_cost_alert_usd = 2.0
_cfg_mod.settings = _settings  # type: ignore[attr-defined]
sys.modules.setdefault("app", _cfg_pkg)
sys.modules["app.config"] = _cfg_mod

# The relative import in tools.py is `from ..config import settings`.
# exec'ing the file in a flat namespace won't resolve relative imports, so we
# patch the resolved names that the import machinery would inject.
_TOOLS_SRC = (
    Path(__file__).resolve().parent.parent / "app" / "investigate" / "tools.py"
)
_source = _TOOLS_SRC.read_text(encoding="utf-8")

# Load the pure validator (no stubs needed) and inject it so tools.py's
# `from .tool_validators import validate_tool_args` resolves during exec.
_TV_SRC = (
    Path(__file__).resolve().parent.parent / "app" / "investigate" / "tool_validators.py"
)
_tv_ns: dict = {}
exec(_TV_SRC.read_text(encoding="utf-8"), _tv_ns)  # noqa: S102

# Replace the relative import with direct references to our stubs so the
# exec'd code can find `settings`, `text`, and `Session`.
_source_patched = _source.replace(
    "from sqlalchemy import text",
    "text = __builtins__['__import__']('sqlalchemy').text",
).replace(
    "from sqlmodel import Session",
    "Session = __builtins__['__import__']('sqlmodel').Session",
).replace(
    "from ..config import settings",
    "from app.config import settings",
).replace(
    "from .tool_validators import validate_tool_args",
    "validate_tool_args = _INJECTED_validate_tool_args",
)

_ns: dict = {}
_ns["_INJECTED_validate_tool_args"] = _tv_ns["validate_tool_args"]
exec(_source_patched, _ns)  # noqa: S102

# Pull out the symbols we want to test
TOOL_DEFINITIONS = _ns["TOOL_DEFINITIONS"]
_pin_finding = _ns["_pin_finding"]
_cape_task_id = _ns["_cape_task_id"]
_get_api_traces = _ns["_get_api_traces"]
_get_pcap_summary = _ns["_get_pcap_summary"]
execute_tool = _ns["execute_tool"]
_get_cape_payloads = _ns["_get_cape_payloads"]
_read_payload = _ns["_read_payload"]
_GHIDRA_TOOLS = _ns["_GHIDRA_TOOLS"]
GHIDRA_ARG_VALIDATORS = _tv_ns["GHIDRA_ARG_VALIDATORS"]
_ns_ghidra_tool_orig = _ns["_ghidra_tool"]

restore(_SAVED_MODULES)


# ---------------------------------------------------------------------------
# TOOL_DEFINITIONS sanity
# ---------------------------------------------------------------------------


def test_tool_schema_shape():
    """Every tool must have name, description, and input_schema."""
    for tool in TOOL_DEFINITIONS:
        assert "name" in tool, f"Tool missing 'name': {tool}"
        assert "description" in tool, f"Tool {tool['name']} missing 'description'"
        assert "input_schema" in tool, f"Tool {tool['name']} missing 'input_schema'"
        schema = tool["input_schema"]
        assert schema.get("type") == "object", (
            f"Tool {tool['name']} input_schema must be type=object"
        )


def test_tool_names_unique():
    names = [t["name"] for t in TOOL_DEFINITIONS]
    assert len(names) == len(set(names)), (
        f"Duplicate tool names: {[n for n in names if names.count(n) > 1]}"
    )


def test_all_expected_tools_present():
    names = {t["name"] for t in TOOL_DEFINITIONS}
    expected = {
        "search_iocs", "search_techniques", "search_analyses",
        "get_network_events", "get_signatures", "get_capabilities",
        "get_iocs", "get_sample_lineage",
        "decompile_function", "get_xrefs_to", "get_xrefs_from",
        "get_strings_at", "list_functions", "get_data_at",
        "get_cape_payloads", "read_payload",
        "get_pcap_summary", "get_api_traces",
        "run_python", "pin_finding",
    }
    assert names == expected, (
        f"Missing: {expected - names}; Extra: {names - expected}"
    )
    # Count is derived from the canonical set — no separate magic number to maintain
    assert len(TOOL_DEFINITIONS) == len(expected)


# ---------------------------------------------------------------------------
# _pin_finding tests
# ---------------------------------------------------------------------------


def test_pin_finding_valid_ioc():
    result = _pin_finding({
        "type": "ioc",
        "value": "192.168.1.100",
        "ioc_type": "ipv4-addr",
        "context": "C2 beacon destination observed in network_events",
    })
    assert result["status"] == "proposed"
    assert result["awaiting_confirmation"] is True
    assert result["type"] == "ioc"
    assert result["value"] == "192.168.1.100"
    assert result["ioc_type"] == "ipv4-addr"


def test_pin_finding_ioc_missing_ioc_type():
    result = _pin_finding({
        "type": "ioc",
        "value": "evil.example.com",
        "context": "DNS query during detonation",
    })
    assert "error" in result
    assert "ioc_type" in result["error"]


def test_pin_finding_invalid_type():
    result = _pin_finding({
        "type": "unknown_type",
        "value": "something",
        "context": "test",
    })
    assert "error" in result
    assert "unknown_type" in result["error"]


def test_pin_finding_valid_note():
    result = _pin_finding({
        "type": "note",
        "value": "RC4 key appears to be derived from mutex name",
        "context": "Observed pattern in decompile_function output for sub_401000",
    })
    assert result["status"] == "proposed"
    assert result["type"] == "note"
    assert result.get("ioc_type") is None


def test_pin_finding_valid_technique():
    result = _pin_finding({
        "type": "technique",
        "value": "T1055.003",
        "context": "Thread execution hijacking observed via CreateRemoteThread call",
    })
    assert result["status"] == "proposed"
    assert result["type"] == "technique"
    assert result["value"] == "T1055.003"


# ---------------------------------------------------------------------------
# _cape_task_id tests
# ---------------------------------------------------------------------------


def test_cape_task_id_from_id_key():
    report = {"cape": {"id": 42, "other": "stuff"}}
    assert _cape_task_id(report) == "42"


def test_cape_task_id_from_task_id_key():
    report = {"cape": {"task_id": 99}}
    assert _cape_task_id(report) == "99"


def test_cape_task_id_missing_cape():
    assert _cape_task_id({}) is None


def test_cape_task_id_empty_cape():
    assert _cape_task_id({"cape": {}}) is None


def test_cape_task_id_none_value():
    # Explicit None in the report should return None
    assert _cape_task_id({"cape": {"id": None, "task_id": None}}) is None


# ---------------------------------------------------------------------------
# _get_api_traces tests
# ---------------------------------------------------------------------------

_FAKE_REPORT = {
    "cape": {
        "behavior": {
            "processes": [
                {
                    "process_name": "malware.exe",
                    "pid": 1234,
                    "calls": [
                        {"api": "CreateFile", "args": {"filename": "evil.dat"}},
                        {"api": "WriteFile", "args": {"data": "AAAA"}},
                        {"api": "VirtualAlloc", "args": {"size": 4096}},
                    ],
                },
                {
                    "process_name": "cmd.exe",
                    "pid": 5678,
                    "calls": [
                        {"api": "CreateProcess", "args": {"cmdline": "whoami"}},
                    ],
                },
            ]
        }
    }
}


def test_get_api_traces_no_filter():
    result = _get_api_traces({}, _FAKE_REPORT)
    assert result["process_count"] == 2
    names = [p["process_name"] for p in result["processes"]]
    assert "malware.exe" in names
    assert "cmd.exe" in names


def test_get_api_traces_process_filter():
    result = _get_api_traces({"process": "malware"}, _FAKE_REPORT)
    assert result["process_count"] == 1
    assert result["processes"][0]["process_name"] == "malware.exe"


def test_get_api_traces_api_filter():
    result = _get_api_traces({"api_filter": "virtual"}, _FAKE_REPORT)
    # Only malware.exe has VirtualAlloc
    procs_with_calls = [p for p in result["processes"] if p["calls"]]
    assert len(procs_with_calls) == 1
    assert procs_with_calls[0]["calls"][0]["api"] == "VirtualAlloc"


def test_get_api_traces_caps_per_process():
    """Verify the 100-call-per-process cap is enforced."""
    many_calls = [{"api": f"Api{i}", "args": {}} for i in range(150)]
    report = {
        "cape": {
            "behavior": {
                "processes": [
                    {"process_name": "heavy.exe", "pid": 1, "calls": many_calls}
                ]
            }
        }
    }
    result = _get_api_traces({}, report)
    proc = result["processes"][0]
    assert proc["total_calls"] == 150
    assert proc["calls_shown"] == 100
    assert len(proc["calls"]) == 100


def test_get_api_traces_empty_report():
    result = _get_api_traces({}, {})
    assert result["process_count"] == 0
    assert result["processes"] == []


def test_get_api_traces_process_cap():
    """Verify the 10-process cap is enforced."""
    many_procs = [
        {"process_name": f"proc{i}.exe", "pid": i, "calls": [{"api": "Foo", "args": {}}]}
        for i in range(15)
    ]
    report = {"cape": {"behavior": {"processes": many_procs}}}
    result = _get_api_traces({}, report)
    assert result["process_count"] <= 10


def test_get_api_traces_non_json_calls_are_serializable():
    """Calls containing bytes or datetime values must not break json.dumps (Fix 1)."""
    import datetime

    report = {
        "cape": {
            "behavior": {
                "processes": [
                    {
                        "process_name": "weird.exe",
                        "pid": 999,
                        "calls": [
                            # bytes value — not JSON-serializable natively
                            {"api": "WriteFile", "args": {"data": b"\x00\x01\x02\x03"}},
                            # datetime value — also not JSON-serializable natively
                            {"api": "GetSystemTime", "args": {"ts": datetime.datetime(2026, 1, 1)}},
                        ],
                    }
                ]
            }
        }
    }
    result = _get_api_traces({}, report)
    # The whole result dict must survive json.dumps without raising TypeError
    serialized = json.dumps(result)
    assert "WriteFile" in serialized
    assert "GetSystemTime" in serialized


# ---------------------------------------------------------------------------
# _get_pcap_summary tests
# ---------------------------------------------------------------------------


def test_get_pcap_summary_present():
    report = {"pcap_analysis": {"alerts": [{"sig": "ET MALWARE"}], "flows": 5}}
    result = _get_pcap_summary({}, report)
    assert "pcap_analysis" in result
    assert result["pcap_analysis"]["flows"] == 5


def test_get_pcap_summary_absent():
    result = _get_pcap_summary({}, {})
    assert "error" in result
    assert "pcap_analysis" in result["error"]


def test_get_pcap_summary_large_truncation():
    """Large pcap_analysis should be trimmed to top-level keys with a note."""
    big_value = "x" * 60000
    report = {"pcap_analysis": {"alerts": big_value, "flows": 10}}
    result = _get_pcap_summary({}, report)
    assert "note" in result
    assert "keys" in result
    # Should NOT include the raw pcap_analysis blob
    assert "pcap_analysis" not in result


# ---------------------------------------------------------------------------
# Argument validation at the dispatch boundary
# ---------------------------------------------------------------------------


def test_execute_tool_rejects_bad_args_without_dispatch():
    """An invalid Ghidra arg returns an error AND never reaches the subprocess."""
    calls = []
    _ns["_ghidra_tool"] = lambda *a, **k: calls.append(a) or {"ok": True}
    try:
        result = execute_tool(
            "decompile_function",
            {"name": "x" * 300},
            session=None,
            report={},
            analysis_id=1,
        )
    finally:
        _ns["_ghidra_tool"] = _ns_ghidra_tool_orig
    assert "error" in result
    assert calls == [], "validation must run before dispatch — _ghidra_tool was called"


def test_execute_tool_allows_valid_args_to_dispatch():
    """A valid arg passes validation and reaches the (spied) Ghidra dispatch."""
    calls = []
    _ns["_ghidra_tool"] = lambda *a, **k: calls.append(a) or {"ok": True}
    try:
        result = execute_tool(
            "decompile_function",
            {"name": "main"},
            session=None,
            report={},
            analysis_id=1,
        )
    finally:
        _ns["_ghidra_tool"] = _ns_ghidra_tool_orig
    assert result == {"ok": True}
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Prompt-injection regression: adversarial tool args must not reach a tool
# ---------------------------------------------------------------------------
#
# Threat model: untrusted (malware-derived) data is wrapped in UNTRUSTED_DATA
# delimiters and the system prompt forbids following it (covered by
# test_system_prompt.py). This battery covers the OTHER half — if an injected
# LLM nonetheless emits a tool call whose ARGUMENTS carry the attack, the call
# must be rejected at execute_tool *before* any dispatch.
#
# Payloads target the strictly-validated Ghidra args (address / filter / range /
# length). The free-form `name` arg (regex ^.{1,200}$) is intentionally NOT
# exercised here: function names are arbitrary, so the regex is permissive by
# design — `name` safety comes from passing argv as JSON (no shell) to a Ghidra
# subprocess that returns null on an unknown symbol, not from the pattern. Adding
# metachars to `name` is inert, not a finding, so asserting its rejection would
# encode a false requirement.

_INJECTION_TOOL_ARGS = [
    ("get_strings_at", {"address": "0x401000; rm -rf /"}),          # shell metachars
    ("get_strings_at", {"address": "$(id)"}),                       # command substitution
    ("get_strings_at", {"address": "0x401000\nIGNORE PREVIOUS"}),   # newline / instruction
    ("get_data_at", {"address": "../../../etc/passwd"}),            # path traversal
    ("get_data_at", {"address": "0x00401000", "length": 999999}),   # over the 65536 bound
    ("get_strings_at", {"address": "0x00401000", "range": 99999}),  # over the 4096 bound
    ("list_functions", {"filter": "*; cat /etc/shadow"}),           # shell metachars
    ("list_functions", {"filter": "$(reboot)"}),                    # command substitution
]


@pytest.mark.parametrize(
    "tool_name,args",
    _INJECTION_TOOL_ARGS,
    ids=[f"{t}:{list(a.values())[0]!r}"[:48] for t, a in _INJECTION_TOOL_ARGS],
)
def test_injection_args_rejected_before_dispatch(tool_name, args):
    """An injection-style tool arg must error out and never reach the Ghidra subprocess."""
    calls = []
    _ns["_ghidra_tool"] = lambda *a, **k: calls.append(a) or {"ok": True}
    try:
        result = execute_tool(
            tool_name,
            args,
            session=None,
            report={},
            analysis_id=1,
        )
    finally:
        _ns["_ghidra_tool"] = _ns_ghidra_tool_orig
    assert "error" in result, f"{tool_name} {args} should be rejected, got {result!r}"
    assert calls == [], (
        f"INJECTION REACHED TOOL: {tool_name} dispatched despite adversarial args {args}"
    )


def test_ghidra_validators_match_registry():
    """Every Ghidra tool has an arg validator (drift guard against the real registry)."""
    assert set(GHIDRA_ARG_VALIDATORS) == _GHIDRA_TOOLS


# ---------------------------------------------------------------------------
# Cape payload tools (#377)
# ---------------------------------------------------------------------------


@pytest.fixture
def cape_storage(tmp_path, monkeypatch):
    """Point the payload tools at a throwaway storage tree."""
    monkeypatch.setitem(_ns, "CAPE_STORAGE", tmp_path)
    return tmp_path


def _write_payload(directory, name, size=4096):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(b"MZ\x90\x00" + b"\x00" * (size - 4))


REPORT = {"cape": {"id": 77}}


def test_payloads_found_outside_dropped(cape_storage):
    """dropped/ is empty on this deployment; the payloads are elsewhere."""
    _write_payload(cape_storage / "77" / "CAPE", "a" * 64)
    _write_payload(cape_storage / "77" / "procdump", "b" * 64)

    result = _get_cape_payloads({}, REPORT)

    assert result["count"] == 2, f"expected payloads, got {result!r}"
    assert {p["source_dir"] for p in result["payloads"]} == {"CAPE", "procdump"}


def test_listed_index_resolves_to_the_listed_file(cape_storage):
    """The desync bug: listing enumerated before filtering, reading after.

    A subdirectory alongside the payloads shifted every subsequent index, so
    read_payload(n) returned a different file than the one get_cape_payloads
    labelled n — with no error to reveal it.
    """
    files_dir = cape_storage / "77" / "files"
    (files_dir / "subdir").mkdir(parents=True)
    for i in range(4):
        _write_payload(files_dir, f"{i}" * 64, size=4096 + i)

    listed = _get_cape_payloads({}, REPORT)["payloads"]

    for entry in listed:
        got = _read_payload({"payload_index": entry["index"]}, REPORT)
        assert got["filename"] == entry["filename"], (
            f"index {entry['index']} listed as {entry['filename']} "
            f"but read back {got['filename']}"
        )
        assert got["size"] == entry["size"]


def test_payload_index_out_of_range_reports_the_real_count(cape_storage):
    _write_payload(cape_storage / "77" / "CAPE", "c" * 64)

    result = _read_payload({"payload_index": 5}, REPORT)

    assert "error" in result
    assert "1 payloads available" in result["error"]


def test_no_extraction_is_an_explicit_result_not_a_missing_directory(cape_storage):
    """The old message blamed a missing dropped/ dir, which was always missing."""
    (cape_storage / "77").mkdir(parents=True)

    result = _get_cape_payloads({}, REPORT)

    assert "error" in result
    assert "dropped" not in result["error"].lower()


def test_undetonated_sample_is_distinguished_from_empty_extraction(cape_storage):
    result = _get_cape_payloads({}, {"cape": {}})

    assert "error" in result
    assert "task ID" in result["error"]
