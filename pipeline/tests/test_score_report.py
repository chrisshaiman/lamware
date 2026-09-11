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
