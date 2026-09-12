# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A report is SUSPECT only when something that SHOULD have run did not.

The run driver's inline check has been wrong three times, always the same way —
it read one field and called everything else OK:

  run 4  read llm_interpretation.error only. Six samples whose 404 sat in
         llm_interpretation.analysis.error were reported OK, and the whole run
         was declared clean (#590).
  run 5  flagged any empty analysis, without asking WHY it was empty. Sample
         unclassified_25d18a2b is a 56MB blob with no PE inside, so Ghidra
         reports "no PE files found" and interpret is correctly never invoked —
         a false positive on the one sample where nothing was wrong.

"Is there an analysis" and "should there have been one" are different questions.
Only the second is a verdict.

Fixtures are the real shapes, taken from those runs.
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "ansible" / "roles" / "pipeline" / "files" / "score_report.py"
spec = importlib.util.spec_from_file_location("_score_report", SRC)
mod = importlib.util.module_from_spec(spec)
sys.modules["_score_report"] = mod
spec.loader.exec_module(mod)
score = mod.score

_CAPE_OK = {"malscore": 10.0, "status": "reported"}


def test_a_real_analysis_is_ok():
    v, _ = score({"cape": _CAPE_OK,
                  "ghidra": {"triggered": True},
                  "llm_interpretation": {"tool_calls_used": 10, "duration_seconds": 489.1,
                                         "analysis": {"malware_family_guess": "upx_variant"}}})
    assert v == "OK"


def test_the_run4_nested_404_is_suspect():
    """The exact shape that six samples had while being reported OK. The error
    is in analysis.error, NOT llm_interpretation.error."""
    v, detail = score({"cape": _CAPE_OK,
                       "ghidra": {"triggered": True},
                       "llm_interpretation": {
                           "tool_calls_used": 0,
                           "analysis": {"error": "NotFoundError: Error code: 404 - "
                                                 "not_found_error: model: local-qwen-llamacpp-re"}}})
    assert v == "SUSPECT", "the nested 404 is being missed again"
    assert "404" in detail


def test_no_pe_to_analyse_is_skipped_not_suspect():
    """unclassified_25d18a2b. Nothing went wrong: there is no PE in the sample,
    so there is nothing for interpret to read."""
    v, detail = score({"cape": _CAPE_OK,
                       "ghidra": {"triggered": True, "error": "no PE files found"},
                       "llm_interpretation": {}})
    assert v == "SKIPPED", "a sample with no PE is being reported as a failure"
    assert "no PE files found" in detail


def test_ghidra_not_triggered_is_also_skipped():
    v, _ = score({"cape": _CAPE_OK, "ghidra": {"triggered": False},
                  "llm_interpretation": {}})
    assert v == "SKIPPED"


def test_an_empty_analysis_WITH_usable_ghidra_is_suspect():
    """The case the SKIPPED branch must not swallow: Ghidra produced output and
    interpret still returned nothing."""
    v, detail = score({"cape": _CAPE_OK,
                       "ghidra": {"triggered": True},
                       "llm_interpretation": {"analysis": {}}})
    assert v == "SUSPECT"
    assert "ghidra produced output" in detail


def test_a_timeout_is_suspect():
    v, _ = score({"cape": _CAPE_OK, "ghidra": {"triggered": True},
                  "llm_interpretation": {"timed_out": True, "analysis": {}}})
    assert v == "SUSPECT"


def test_the_outer_error_is_still_read():
    """Both levels. Fixing run 4 must not lose the level that already worked."""
    v, _ = score({"cape": _CAPE_OK, "ghidra": {"triggered": True},
                  "llm_interpretation": {"error": "Interpret container exited without final result",
                                         "analysis": {}}})
    assert v == "SUSPECT"


def test_a_dead_cape_is_suspect_whatever_interpret_did():
    """observed_behaviour comes from CAPE. If that failed, the sample is
    worthless for #518 even with a perfect analysis."""
    v, _ = score({"cape": {"status": "error"},
                  "ghidra": {"triggered": True},
                  "llm_interpretation": {"analysis": {"malware_family_guess": "x"},
                                         "tool_calls_used": 5}})
    assert v == "SUSPECT"


# --- failed detonations are not measurements ------------------------------
# Across three #518 corpus runs quasarrat scored 55, 17, 45 and warzonerat
# 51, 30, 51. The low values were not noise: they were runs where the sample
# died before spawning and CAPE ended the analysis with an empty process list.
# Averaging them in as measurements produced the +/-15-25 noise floor that made
# the experiment unable to resolve its own question.

_DET_OK = {"process_count": 6, "api_calls_total": 48000, "duration_s": 295}


def test_a_dead_detonation_is_suspect():
    """quasarrat's failed run: one process, 2,344 api calls."""
    v, detail = score({"cape": dict(_CAPE_OK,
                                    detonation={"process_count": 1, "api_calls_total": 2344}),
                       "ghidra": {"triggered": True},
                       "llm_interpretation": {"analysis": {"malware_family_guess": "x"},
                                              "tool_calls_used": 3}})
    assert v == "SUSPECT", "a sample that died before doing anything scored as a measurement"
    assert "2344" in detail


def test_a_busy_single_process_sample_is_not_suspect():
    """xworm legitimately runs as ONE process and makes 24,132 calls. Judging on
    process_count would reject it — which is why the rule is on call volume."""
    v, _ = score({"cape": dict(_CAPE_OK,
                               detonation={"process_count": 1, "api_calls_total": 24132}),
                  "ghidra": {"triggered": True},
                  "llm_interpretation": {"analysis": {"malware_family_guess": "x"},
                                         "tool_calls_used": 3}})
    assert v == "OK", "a healthy single-process sample was rejected"


def test_a_healthy_detonation_is_ok():
    v, _ = score({"cape": dict(_CAPE_OK, detonation=_DET_OK),
                  "ghidra": {"triggered": True},
                  "llm_interpretation": {"analysis": {"malware_family_guess": "x"},
                                         "tool_calls_used": 3}})
    assert v == "OK"


def test_an_older_report_without_the_field_is_not_penalised():
    """Reports predating the detonation block must still score. Absent is not zero."""
    v, _ = score({"cape": _CAPE_OK, "ghidra": {"triggered": True},
                  "llm_interpretation": {"analysis": {"malware_family_guess": "x"},
                                         "tool_calls_used": 3}})
    assert v == "OK", "a report without detonation stats was treated as a failed detonation"


def test_the_detonation_check_precedes_the_interpret_checks():
    """A failed detonation makes the interpret verdict irrelevant — the sample
    produced nothing to interpret, and reporting it as an interpret problem sends
    the next reader to the wrong place."""
    v, detail = score({"cape": dict(_CAPE_OK,
                                    detonation={"process_count": 1, "api_calls_total": 100}),
                       "ghidra": {"triggered": True, "error": "no PE files found"},
                       "llm_interpretation": {}})
    assert v == "SUSPECT" and "detonation" in detail


# --- the producer must actually produce it --------------------------------
# The rule above reads cape.detonation. Nothing tested that the cape stage
# WRITES it, so deleting the producer left every test green while the rule
# became permanently inert — two halves in two files that must agree, which is
# the shape of #584 and #590.

def test_the_cape_stage_records_the_detonation_block():
    """Behavioural, not grepped. The rule above keys on api_calls_total, so the
    cape stage must actually compute it by summing the per-process call lists —
    an assertion on source text passes for the wrong reasons the moment the
    block moves, which is what happened when it became a function.

    The wiring — that extract_cape_intel still CALLS this — is held by
    test_detonation_health.test_extract_cape_intel_emits_the_detonation_block.
    """
    import sys
    sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))
    from stages.cape import detonation_health

    det = detonation_health({
        "info": {"duration": 290, "timeout": False},
        "debug": {"log": ""},
        "behavior": {"processes": [
            {"process_id": 1, "calls": [{"api": "NtClose"}] * 7},
            {"process_id": 2, "calls": [{"api": "NtClose"}] * 5},
        ]}})

    assert det["api_calls_total"] == 12, \
        "api_calls_total is not summed from the per-process call lists"
    assert det["process_count"] == 2
    # A process whose calls are absent must count as zero, not raise.
    assert detonation_health(
        {"behavior": {"processes": [{"process_id": 1}]}})["api_calls_total"] == 0
