# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Lost instrumentation must not read as a quiet sample.

A controlled 5x quasarrat reproduction on an idle host (CAPE tasks 1117-1121)
showed the sample behaving IDENTICALLY every run: it hollows two children,
CreateProcessW succeeds, and the parent runs 4,112-4,118 calls before a clean
NtTerminateProcess. The guest Application event log holds no crash record.

The only thing that varied was whether CAPE's monitor DLL reached the children:

    task 1117    4,114 api calls   1 process    2 pids injected, 0 loaded
    task 1118   49,574 api calls   6 processes  all loaded
    task 1119   89,165 api calls   7 processes  all loaded
    task 1120   91,880 api calls   7 processes  all loaded
    task 1121   87,217 api calls   7 processes  all loaded

So 1117 is not a sample that did nothing. It is 45-90k api calls of payload
behaviour that happened and was never recorded. Scoring it as a measurement is
what put the low values into the #518 corpus averages.

The log strings are the contract with CAPE, so the fixtures below are VERBATIM
captured text from tasks 1117 and 1118 rather than text written to match the
regexes. If CAPE rewords either line the patterns stop matching and the guard
goes silent, which is the failure mode these tests exist to catch.
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.cape import detonation_health  # noqa: E402

_SCORE_SRC = ROOT / "ansible" / "roles" / "pipeline" / "files" / "score_report.py"
_spec = importlib.util.spec_from_file_location("_score_report_dh", _SCORE_SRC)
_score_mod = importlib.util.module_from_spec(_spec)
sys.modules["_score_report_dh"] = _score_mod
_spec.loader.exec_module(_score_mod)
score = _score_mod.score

# Verbatim from /opt/CAPEv2/storage/analyses/1117/analysis.log.
LOG_1117_FAILED = """\
2026-09-12 06:41:58,128 [root] INFO: Loaded monitor into process with pid 7548
2026-09-12 06:42:17,563 [root] DEBUG: 7548: CreateProcessHandler: Injection info set for new process 3092: C:\\WINDOWS\\TEMP\\quasarrat.exe, ImageBase: 0x00170000
2026-09-12 06:42:17,637 [root] DEBUG: 7548: SetThreadContextHandler: Hollow process entry point reset via NtSetContextThread to 0x000581FE (process 3092).
2026-09-12 06:42:48,030 [root] WARNING: Monitor injection attempted but failed for process 3092
2026-09-12 06:42:48,030 [root] WARNING: Monitor injection attempted but failed for process 6680
"""

# Verbatim from /opt/CAPEv2/storage/analyses/1118/analysis.log.
LOG_1118_HEALTHY = """\
2026-09-12 06:46:27,082 [root] INFO: Loaded monitor into process with pid 5272
2026-09-12 06:46:47,149 [root] INFO: Loaded monitor into process with pid 2632
2026-09-12 06:47:30,533 [root] INFO: Loaded monitor into process with pid 972
2026-09-12 06:47:32,605 [root] INFO: Loaded monitor into process with pid 5192
2026-09-12 06:47:44,898 [root] INFO: Loaded monitor into process with pid 7024
2026-09-12 06:47:46,211 [root] INFO: Loaded monitor into process with pid 8200
"""


def _cape_report(analyzer_log, n_procs, calls_each, duration=290, timeout=False):
    """A Cape report in the shape extract_cape_intel actually receives."""
    return {"CAPE": {}, "target": {}, "network": {}, "signatures": [],
            "debug": {"log": analyzer_log, "errors": []},
            "info": {"duration": duration, "timeout": timeout},
            "behavior": {"processes": [
                {"process_id": 1000 + i, "process_name": "quasarrat.exe",
                 "calls": [{"api": "NtClose"}] * calls_each}
                for i in range(n_procs)]}}


def _intel(report, tmp_path=None):
    return {"detonation": detonation_health(report)}


# --- the producer reads the pids out of the real log text ------------------

def test_failed_run_names_the_lost_pids(tmp_path):
    det = _intel(_cape_report(LOG_1117_FAILED, 1, 4114), tmp_path)["detonation"]
    assert det["monitor_injection_failed_pids"] == [3092, 6680]
    assert det["monitors_loaded"] == 1


def test_healthy_run_loses_nothing(tmp_path):
    det = _intel(_cape_report(LOG_1118_HEALTHY, 6, 8262), tmp_path)["detonation"]
    assert det["monitor_injection_failed_pids"] == []
    assert det["monitors_loaded"] == 6


def test_pids_are_deduplicated_and_sorted(tmp_path):
    doubled = LOG_1117_FAILED + LOG_1117_FAILED
    det = _intel(_cape_report(doubled, 1, 4114), tmp_path)["detonation"]
    assert det["monitor_injection_failed_pids"] == [3092, 6680]


def test_missing_debug_section_does_not_raise(tmp_path):
    """Older reports predate this block; absence must read as 'nothing lost',
    not as a crash in the stage."""
    report = _cape_report(LOG_1118_HEALTHY, 6, 8262)
    del report["debug"]
    det = _intel(report, tmp_path)["detonation"]
    assert det["monitor_injection_failed_pids"] == []
    assert det["monitors_loaded"] == 0


# --- the regexes are a contract with CAPE's source -------------------------

@pytest.mark.parametrize("line,pattern_name,expected", [
    # analyzer/windows/analyzer.py:350
    ("2026-09-12 06:42:48,030 [root] WARNING: Monitor injection attempted "
     "but failed for process 3092", "_INJECT_FAILED_RE", ["3092"]),
    # analyzer/windows/analyzer.py:1102
    ("2026-09-12 06:41:58,128 [root] INFO: Loaded monitor into process "
     "with pid 7548", "_MONITOR_LOADED_RE", ["7548"]),
])
def test_pattern_matches_capes_literal_log_line(line, pattern_name, expected):
    from stages import cape
    assert getattr(cape, pattern_name).findall(line) == expected


def test_patterns_do_not_match_each_other():
    """Both lines name a pid. Neither pattern may claim the other's line, or a
    healthy run would report lost pids."""
    from stages import cape
    loaded_line = ("[root] INFO: Loaded monitor into process with pid 7548")
    failed_line = ("[root] WARNING: Monitor injection attempted but failed "
                   "for process 3092")
    assert cape._INJECT_FAILED_RE.findall(loaded_line) == []
    assert cape._MONITOR_LOADED_RE.findall(failed_line) == []


# --- the scorer acts on it -------------------------------------------------

_OK_REST = {"ghidra": {"triggered": True},
            "llm_interpretation": {"tool_calls_used": 10,
                                   "analysis": {"malware_family_guess": "quasar"}}}


def _scored(detonation):
    return score({"cape": {"malscore": 10.0, "status": "reported",
                           "detonation": detonation}, **_OK_REST})


def test_lost_instrumentation_is_suspect_even_with_high_call_volume():
    """The point of the direct signal. A run can lose a child and STILL clear
    the api-call threshold, which is exactly what the heuristic cannot see."""
    v, detail = _scored({"process_count": 6, "api_calls_total": 60000,
                         "monitors_loaded": 5,
                         "monitor_injection_failed_pids": [4208]})
    assert v == "SUSPECT", "a lost child is invisible when output looks healthy"
    assert "4208" in detail


def test_task_1117_is_suspect():
    v, detail = _scored({"process_count": 1, "api_calls_total": 4114,
                         "monitors_loaded": 1,
                         "monitor_injection_failed_pids": [3092, 6680]})
    assert v == "SUSPECT"
    assert "3092" in detail and "6680" in detail


def test_task_1118_is_ok():
    v, _ = _scored({"process_count": 6, "api_calls_total": 49574,
                    "monitors_loaded": 6, "monitor_injection_failed_pids": []})
    assert v == "OK"


def test_quiet_run_without_any_warning_still_caught():
    """Task 1103: under-instrumented with an EMPTY failed-pid list. The backstop
    is the only thing that sees this one."""
    v, detail = _scored({"process_count": 1, "api_calls_total": 2344,
                         "monitors_loaded": 1,
                         "monitor_injection_failed_pids": []})
    assert v == "SUSPECT"
    assert "2344" in detail


def test_reports_predating_the_field_are_not_all_suspect():
    """A report with no detonation block at all must not become SUSPECT — that
    would condemn every archived report rather than flag a real failure."""
    v, _ = score({"cape": {"malscore": 10.0, "status": "reported"}, **_OK_REST})
    assert v == "OK"


# --- the producer is actually WIRED IN -------------------------------------

def test_extract_cape_intel_emits_the_detonation_block(tmp_path, monkeypatch):
    """Without this, deleting the detonation_health() call from
    extract_cape_intel leaves every test above green while the rule goes inert.
    That exact mutation has slipped through here before.

    extract_cape_intel reads report.json off CAPE storage by task id, so the
    absolute prefix is redirected into tmp_path.
    """
    from stages import cape

    stored = (tmp_path / "opt" / "CAPEv2" / "storage" / "analyses" / "1117"
              / "reports")
    stored.mkdir(parents=True)
    (stored / "report.json").write_text(
        json.dumps(_cape_report(LOG_1117_FAILED, 1, 4114)))

    real_path = cape.Path

    def redirected(p):
        if isinstance(p, str) and p.startswith("/opt/CAPEv2/"):
            return real_path(str(tmp_path) + p)
        return real_path(p)

    monkeypatch.setattr(cape, "Path", redirected)

    intel = cape.extract_cape_intel({"id": 1117}, tmp_path / "out")
    assert "detonation" in intel, "extract_cape_intel no longer emits detonation"
    assert intel["detonation"]["monitor_injection_failed_pids"] == [3092, 6680]


# --- the two ways a process leaves are not the same thing ------------------
# "has terminated" (hook saw the exit) vs "appears to have terminated" (poller
# found it gone). The strings differ by has/have, so a sloppy pattern matches
# both and the distinction silently disappears.

# Verbatim from tasks 1103 and 1117 respectively.
LINE_VANISHED = ("2026-09-09 11:39:14,661 [root] INFO: Process with pid 3540 "
                 "appears to have terminated")
LINE_CLEAN_EXIT = ("2026-09-12 06:42:20,007 [root] INFO: Process with pid 7548 "
                   "has terminated")


def test_vanished_and_clean_exit_are_told_apart():
    det = detonation_health({"debug": {"log": LINE_VANISHED + "\n" + LINE_CLEAN_EXIT}})
    assert det["vanished_pids"] == [3540]
    assert det["clean_exit_pids"] == [7548]


def test_clean_exit_pattern_does_not_claim_the_vanished_line():
    """'appears to have terminated' also ends in 'terminated' and names a pid.
    If the exit pattern matches it, a vanished process reads as a clean exit."""
    from stages import cape
    assert cape._PROCESS_EXITED_RE.findall(LINE_VANISHED) == []
    assert cape._PROCESS_VANISHED_RE.findall(LINE_CLEAN_EXIT) == []


def test_task_1103_shape_reports_why_it_was_quiet():
    v, detail = _scored({"process_count": 1, "api_calls_total": 2344,
                         "monitors_loaded": 1, "monitor_injection_failed_pids": [],
                         "vanished_pids": [3540], "clean_exit_pids": []})
    assert v == "SUSPECT"
    assert "3540" in detail and "no exit call" in detail


def test_a_quiet_but_cleanly_exited_run_is_not_blamed_on_vanishing():
    """A sample that ran briefly and exited properly is still SUSPECT for being
    quiet, but must not be reported as having vanished."""
    v, detail = _scored({"process_count": 1, "api_calls_total": 900,
                         "monitors_loaded": 1, "monitor_injection_failed_pids": [],
                         "vanished_pids": [], "clean_exit_pids": [1234]})
    assert v == "SUSPECT"
    assert "vanished" not in detail


def test_repro_runs_record_clean_exits_and_no_vanishing():
    det = detonation_health({"debug": {"log": LOG_1118_HEALTHY + LINE_CLEAN_EXIT}})
    assert det["vanished_pids"] == []
    assert det["clean_exit_pids"] == [7548]
