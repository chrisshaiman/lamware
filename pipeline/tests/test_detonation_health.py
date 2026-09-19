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


def test_no_tier_is_rejected_globally():
    """POLICY REVERSAL, measured. An earlier version rejected ALL-LOST and
    NO-HOLLOW. Across ~230 runs of nine samples that was wrong for five of them:

      NO-HOLLOW  means "died before hollowing" for quasarrat, and simply "does
                 not hollow" for salat, latrodectus, unclassified, xworm and
                 agenttesla -- 100% false positives on those
      ALL-LOST   is fatal for quasarrat (observed 26 vs 54) and harmless for
                 cobaltstrikebeacon, ALL-LOST in 12 of 13 runs while scoring the
                 most stable in the corpus (90.1 +/- 2.5)

    Whether a tier means failure is a property of the SAMPLE. A rule that fires
    on healthy data is worse than no rule."""
    for tier in ("CLEAN", "PARTIAL", "ALL-LOST", "NO-HOLLOW"):
        v, _ = _scored({"tier": tier, "process_count": 1,
                        "api_calls_total": 2415, "monitors_loaded": 1,
                        "hollowed_pids": [], "traced_pids": [], "lost_pids": []})
        assert v == "OK", f"tier {tier} must not be rejected without a baseline"


def test_a_quiet_sample_is_not_called_dead():
    """latrodectus makes 266 api calls on a HEALTHY run; the old 5,000 threshold
    rejected all ten of its runs, and agenttesla's six at 3,741."""
    for calls in (0, 266, 432, 746, 3741):
        v, _ = _scored({"tier": "NO-HOLLOW", "process_count": 1,
                        "api_calls_total": calls, "monitors_loaded": 1})
        assert v == "OK", f"{calls} api calls is normal for some sample"


def test_the_tier_is_still_recorded():
    """The recording half is what made #518 tractable and is retained. Only the
    global rejection was wrong."""
    rep = {"cape": {"malscore": 10.0, "status": "reported",
                    "detonation": {"tier": "PARTIAL"}}, **_OK_REST}
    score(rep)
    assert any("PARTIAL" in n for n in rep.get("_notes", [])), \
        "the tier must survive into the report even though it no longer gates"


# --- tier classification ----------------------------------------------------
# Verbatim fragments from tasks 1158 (CLEAN), 1168 (PARTIAL), 1117 (ALL-LOST).
# The tier is a property of OUR OBSERVATION, not the sample: the malware runs
# identically every time (parent API counts are byte-identical across runs) and
# always hollows two children. The tier records how many CAPE managed to watch.

_HOLLOW = ("2026-09-17 04:07:41,225 [root] DEBUG: 716: SetThreadContextHandler: "
           "Hollow process entry point reset via NtSetContextThread to 0x000581FE "
           "(process {pid}).")
_LOADED = "2026-09-17 04:08:00,972 [root] INFO: Loaded monitor into process with pid {pid}"
_CREATED = ("2026-09-17 04:07:59,900 [root] DEBUG: 716: CreateProcessHandler: Injection "
            "info set for new process {pid}: C:\\WINDOWS\\TEMP\\quasarrat.exe, ImageBase: {base}")


def _log(children):
    """children: [(pid, imagebase, traced_bool)]"""
    lines = []
    for pid, base, _ in children:
        lines.append(_CREATED.format(pid=pid, base=base))
    for pid, _, _ in children:
        lines.append(_HOLLOW.format(pid=pid))
    for pid, _, traced in children:
        if traced:
            lines.append(_LOADED.format(pid=pid))
    return "\n".join(lines) + "\n"


def test_tier_clean_when_every_hollowed_child_is_traced():
    det = detonation_health({"debug": {"log": _log([
        (4660, "0x00C40000", True), (4592, "0x00660000", True)])}})
    assert det["tier"] == "CLEAN"
    assert det["hollowed_pids"] == [4592, 4660]
    assert det["lost_pids"] == []


def test_tier_partial_when_one_child_is_lost():
    det = detonation_health({"debug": {"log": _log([
        (9884, "0x00350000", False), (6504, "0x00F60000", True)])}})
    assert det["tier"] == "PARTIAL"
    assert det["traced_pids"] == [6504]
    assert det["lost_pids"] == [9884]


def test_tier_all_lost_when_no_child_is_traced():
    det = detonation_health({"debug": {"log": _log([
        (3092, "0x00170000", False), (6680, "0x001B0000", False)])}})
    assert det["tier"] == "ALL-LOST"
    assert det["traced_pids"] == []
    assert det["lost_pids"] == [3092, 6680]


def test_tier_no_hollow_is_not_vacuously_clean():
    """The bug this precondition exists for. With nothing hollowed, 'every
    hollowed child was traced' is trivially true, and three plainly dead runs
    (1144, 1153, 1162 — ~2,400 calls each) were scored CLEAN because of it."""
    det = detonation_health({"debug": {"log": "nothing hollowed here\n"}})
    assert det["tier"] == "NO-HOLLOW", "an empty set must not pass as CLEAN"


def test_child_image_bases_are_recorded():
    """The predictor, kept so the tier can be explained after the fact. Below
    0x00400000 instrumentation has never succeeded: 0 of 55 across six families
    (#606). The mechanism is unknown, so this is recorded, not acted on."""
    det = detonation_health({"debug": {"log": _log([
        (9884, "0x00350000", False), (6504, "0x00F60000", True)])}})
    assert det["child_image_bases"] == {"9884": "0x350000", "6504": "0xf60000"}
    lost_base = int(det["child_image_bases"][str(det["lost_pids"][0])], 16)
    assert lost_base < 0x00400000
