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
    """Parsed, not grepped: the assignment must target intel["detonation"] and
    carry the field the rule keys on.

    stages/cape.py cannot be imported here — it reads /opt/pipeline/config.json
    at import time — so this asserts on the AST."""
    import ast
    src = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "stages"
           / "cape.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                    and t.value.id == "intel"
                    and isinstance(t.slice, ast.Constant) and t.slice.value == "detonation"):
                body = ast.get_source_segment(src, node.value) or ""
                assert "api_calls_total" in body, \
                    "the detonation block omits api_calls_total, which the rule keys on"
                assert "sum(" in body and "calls" in body, \
                    "api_calls_total is not summed from the per-process call lists"
                assert "process_count" in body
                return
    raise AssertionError(
        'stages/cape.py never assigns intel["detonation"], so score_report\'s '
        'failed-detonation rule can never fire')
