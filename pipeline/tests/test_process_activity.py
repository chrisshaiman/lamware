# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pipeline must copy CAPE's process activity into report.json (#406).

The investigation agent's get_api_traces tool answers from the pipeline's
report only. Before #406 nothing wrote the key it read, so it told the agent
every analysis had zero processes. On analysis v655 (CAPE task 1275) the tool
returned ``{"processes": [], "process_count": 0}`` while CAPE had recorded 11
processes and 60,089 API call entries.

The fixture is CAPE task 1275's behaviour section trimmed to four processes:
real key sets, pid/ppid tree and API/category names; process names, command
lines, paths, arguments and timestamps are synthesised.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

import stages.cape as cape_mod  # noqa: E402
from stages.cape import detonation_health, extract_cape_intel  # noqa: E402
from stages.process_activity import (  # noqa: E402
    MAX_APIS_PER_PROCESS,
    MAX_CMDLINE_CHARS,
    MAX_PROCESSES,
    summarize_process_activity,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cape_behavior_trimmed.json"


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def _by_pid(summary: dict) -> dict:
    return {p["pid"]: p for p in summary["processes"]}


# --- what CAPE recorded reaches the summary ---------------------------------

def test_counts_match_what_cape_recorded():
    s = summarize_process_activity(_fixture())
    assert s["process_count"] == 4
    assert s["api_calls_total"] == 34
    assert s["processes_truncated"] is False
    assert s["processes_omitted"] == 0
    assert [p["api_calls"] for p in s["processes"]] == [13, 11, 10, 0]


def test_pid_and_ppid_come_from_capes_keys():
    """CAPE writes process_id/parent_id, not pid. The old tool read "pid" and
    so returned null for every process even when it had data (#406 defect 2)."""
    procs = _by_pid(summarize_process_activity(_fixture()))
    assert set(procs) == {8332, 4228, 1364, 1936}
    assert procs[8332]["ppid"] == 7240
    assert procs[4228]["ppid"] == 8332
    assert procs[1364]["ppid"] == 8332


def test_per_process_api_and_category_counts():
    p = _by_pid(summarize_process_activity(_fixture()))[8332]
    assert p["apis"]["WriteProcessMemory"] == 1
    assert p["apis"]["RtlUserThreadStart"] == 3
    assert next(iter(p["apis"])) == "RtlUserThreadStart", "most-called first"
    assert p["apis_distinct"] == 9
    assert p["apis_truncated"] is False
    assert p["categories"] == {"threading": 6, "process": 4, "system": 2, "registry": 1}


def test_command_line_comes_from_environ():
    p = _by_pid(summarize_process_activity(_fixture()))[4228]
    assert p["command_line"].endswith("-NoProfile -Command Get-Date")
    assert p["name"] == "powershell.exe"


def test_totals_agree_with_detonation_health():
    """Two numbers for the same thing in one report must not disagree."""
    report = _fixture()
    s = summarize_process_activity(report)
    d = detonation_health(report)
    assert (s["process_count"], s["api_calls_total"]) == (d["process_count"], d["api_calls_total"])


def test_extract_cape_intel_writes_the_key_the_tool_reads(tmp_path, monkeypatch):
    """The producer link itself: extract_cape_intel -- what run-pipeline merges
    into report["cape"] -- must emit process_activity. A summariser nobody
    calls is the #325 shape."""
    report_file = tmp_path / "report.json"
    report_file.write_text(FIXTURE.read_text())
    monkeypatch.setattr(cape_mod, "Path", lambda _p: report_file)
    intel = extract_cape_intel({"id": 1275})
    assert intel["process_activity"]["process_count"] == 4
    assert intel["process_activity"]["api_calls_total"] == 34


# --- absent vs empty ---------------------------------------------------------

def test_no_behaviour_section_writes_nothing():
    """Absent stays absent, so the consumer can say "not recorded"."""
    assert summarize_process_activity({}) is None
    assert summarize_process_activity({"behavior": {}}) is None
    assert summarize_process_activity({"behavior": {"processes": None}}) is None


def test_empty_process_list_is_a_recorded_zero():
    s = summarize_process_activity({"behavior": {"processes": []}})
    assert s is not None
    assert (s["process_count"], s["api_calls_total"], s["processes"]) == (0, 0, [])


# --- bounded, and truncation is said out loud -------------------------------

def _oversized(n_procs=100, n_apis=300, cmd_chars=10_000):
    calls = [{"api": f"Api{i:03d}", "category": f"cat{i % 40}"} for i in range(n_apis)]
    return {"behavior": {"processes": [
        {"process_id": 5000 + i, "parent_id": 4, "process_name": f"proc{i}.exe",
         "environ": {"CommandLine": "A\x00" * (cmd_chars // 2)},
         "module_path": "C:\\" + "d\\" * 400 + "x.exe",
         "calls": calls}
        for i in range(n_procs)]}}


def test_process_list_is_capped_and_says_so():
    s = summarize_process_activity(_oversized())
    assert len(s["processes"]) == MAX_PROCESSES
    assert s["processes_truncated"] is True
    assert s["processes_omitted"] == 100 - MAX_PROCESSES
    # Totals still cover everything CAPE recorded, not just what was kept.
    assert s["process_count"] == 100
    assert s["api_calls_total"] == 100 * 300


def test_api_list_is_capped_and_says_so():
    p = summarize_process_activity(_oversized())["processes"][0]
    assert len(p["apis"]) == MAX_APIS_PER_PROCESS
    assert p["apis_truncated"] is True
    assert p["apis_distinct"] == 300
    assert p["categories_truncated"] is True


def test_sample_controlled_strings_are_capped_and_marked():
    p = summarize_process_activity(_oversized())["processes"][0]
    assert len(p["command_line"]) == MAX_CMDLINE_CHARS
    assert "command_line" in p["truncated_fields"]
    assert "module_path" in p["truncated_fields"]
    # jsonb rejects \u0000; one NUL would fail ingestion of the whole analysis.
    assert "\x00" not in json.dumps(p, ensure_ascii=False)
    assert "\\u0000" not in json.dumps(p)


def test_untruncated_process_carries_no_truncation_marker():
    p = _by_pid(summarize_process_activity(_fixture()))[8332]
    assert "truncated_fields" not in p


def test_summary_size_is_bounded():
    blob = json.dumps(summarize_process_activity(_oversized(n_procs=500, n_apis=1000)))
    assert len(blob) < 1_000_000, f"summary grew to {len(blob)} bytes"


def test_malformed_entries_do_not_crash_or_become_zero():
    s = summarize_process_activity({"behavior": {"processes": [
        "junk", {"process_id": True, "parent_id": "12", "calls": "nope"}]}})
    assert s["process_count"] == 1
    p = s["processes"][0]
    assert p["pid"] is None, "a bool is not a pid; unknown, never 0/1"
    assert p["ppid"] == 12
    assert p["api_calls"] == 0
