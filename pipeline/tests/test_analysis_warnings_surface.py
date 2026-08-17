# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Ghidra's self-contradiction warnings must reach somebody (#367).

`run-ghidra` returned `analysis_success: True` for a 150 KB PE from which it
extracted **1 function and 0 imports**, while that binary's import directory sat
intact at `rva=0x031114, size=40`. Restoring one zeroed header field yields 617
functions from the same bytes.

#372 built the detector — `_analysis_warnings()` in `run-ghidra.py.j2` — and it
has been emitting `analysis_warnings` on every analysed file since. Verified on
the host: 29 analysed files carry the key, and **nothing anywhere reads it**.
Produced, written to the report, never surfaced. The state it exists to describe
stayed exactly as invisible as before the detector existed.

So this covers the second half: lifting the warnings to the top of the ghidra
result and putting a count in the scorecard, so "the analyser could not read
this sample" stops being identical to "the model had nothing to say" (#315).
"""
from pathlib import Path

from lamware_eval.metrics import aggregate, compose_cell
from stages.ghidra import (
    LOW_FUNCTION_THRESHOLD,
    collect_analysis_warnings,
    derive_analysis_warnings,
)

TEMPLATE = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "ghidra"
            / "templates" / "run-ghidra.py.j2").read_text(encoding="utf-8")


def analysed(name="sample.exe", warnings=None, functions=617):
    af = {"program_name": name, "functions_count": functions,
          "analysis_success": True, "project_dir": "/output/project"}
    if warnings is not None:
        af["analysis_warnings"] = warnings
    return af


# ---------------------------------------------------------------------------
# Lifting them off the per-file dicts
# ---------------------------------------------------------------------------

THE_WARNING = ("only 1 function(s) recovered — the loader may not have "
               "resolved an architecture for this binary")


def test_a_warning_reaches_the_top_of_the_result():
    out = collect_analysis_warnings([analysed(warnings=[THE_WARNING], functions=1)])

    assert len(out) == 1
    assert THE_WARNING in out[0]


def test_the_warning_names_the_file_it_came_from():
    """One of several files failing is the interesting case.

    On latrodectus a 124-function payload and a 1-function one sat in the same
    analyzed_files list (#390); an unattributed warning cannot tell them apart.
    """
    out = collect_analysis_warnings([
        analysed("good.exe"),
        analysed("bad.exe", warnings=[THE_WARNING], functions=1),
    ])

    assert len(out) == 1
    assert out[0].startswith("bad.exe:")


def test_a_clean_analysis_produces_nothing():
    """Positive control: not every run is flagged."""
    assert collect_analysis_warnings([analysed(), analysed("other.exe")]) == []


def test_reports_predating_the_detector_do_not_crash():
    """Files written before #372 have no analysis_warnings key at all."""
    assert collect_analysis_warnings([{"program_name": "old.exe"}]) == []
    assert collect_analysis_warnings([]) == []


def test_a_file_with_no_name_is_still_reported():
    out = collect_analysis_warnings([{"analysis_warnings": ["something"]}])

    assert out == ["?: something"]


# ---------------------------------------------------------------------------
# Reaching the scorecard
# ---------------------------------------------------------------------------

def _cell(warnings=None, **over):
    from lamware_eval.corpus import CorpusSample
    s = CorpusSample("a" * 64, "icedid", "/tmp/x")
    tool_metrics = {"completed": True, "tool_calls_used": 10,
                    "tool_call_error_rate": 0.0, "tool_layer_broken": False}
    tool_metrics.update(over)
    return compose_cell("qwen@10", s, {"code_level_iocs": []}, "src", None,
                        400.0, 0.0, tool_metrics, None,
                        ghidra_warnings=warnings)


def test_the_cell_carries_a_count_and_the_reason():
    c = _cell([f"bad.exe: {THE_WARNING}"])

    assert c["ghidra_warnings"] == 1
    assert THE_WARNING in c["ghidra_warning_detail"][0], (
        "the count alone cannot tell an operator WHY")


def test_a_clean_cell_reports_zero():
    """Positive control."""
    c = _cell(None)

    assert c["ghidra_warnings"] == 0
    assert c["ghidra_warning_detail"] == []


def test_the_arm_summary_counts_affected_cells():
    """This is the column that separates 'could not read it' from 'said nothing'."""
    agg = aggregate([_cell([f"a: {THE_WARNING}"]), _cell(None), _cell(None)])["qwen@10"]

    assert agg["cells_with_ghidra_warnings"] == 1


def test_warnings_are_counted_even_when_the_tool_layer_was_broken():
    """A dead tool layer does not make the static analysis behind it any less broken.

    Both facts matter and they are independent: the cell leaves the capability
    aggregates for the tool layer (#316) while still reporting that Ghidra read
    nothing.
    """
    agg = aggregate([_cell([f"a: {THE_WARNING}"], tool_layer_broken=True)])["qwen@10"]

    assert agg["n_valid"] == 0
    assert agg["cells_with_ghidra_warnings"] == 1


# ---------------------------------------------------------------------------
# Wiring, not presence
# ---------------------------------------------------------------------------

def test_run_ghidra_actually_populates_the_field(tmp_path, monkeypatch):
    """A collector nothing calls is the same as no collector.

    #372's detector was fully implemented, fully tested, and unreachable from
    the report — which is why this asserts the call happens rather than that
    the function exists.
    """
    import stages.ghidra as mod

    ghidra_cmd = tmp_path / "run-ghidra"
    ghidra_cmd.write_text("#!/bin/sh\n")
    (tmp_path / "900" / "CAPE").mkdir(parents=True)
    (tmp_path / "900" / "CAPE" / ("a" * 64)).write_bytes(b"MZ\x90\x00" + b"\x00" * 8192)

    monkeypatch.setattr(mod, "run_ghidra_on_file", lambda p, o, c: {
        "program_name": p.name, "functions_count": 1, "analysis_success": True,
        "project_dir": "/output/project", "host_output_dir": str(o),
        "analysis_warnings": [THE_WARNING],
    })

    result = mod.run_ghidra({"id": 900, "status": "reported"}, tmp_path / "out",
                            tmp_path / "sample.bin", ghidra_cmd=str(ghidra_cmd),
                            get_cape_signatures_fn=lambda _c: ["packed_binary"],
                            storage=tmp_path)

    assert result["analysis_warnings"], (
        "run_ghidra did not lift the per-file warnings — they die in "
        "analyzed_files exactly as they did before")
    assert THE_WARNING in result["analysis_warnings"][0]


def test_run_ghidra_reports_no_warnings_for_a_clean_run(tmp_path, monkeypatch):
    """Positive control: the field is not unconditionally non-empty."""
    import stages.ghidra as mod

    ghidra_cmd = tmp_path / "run-ghidra"
    ghidra_cmd.write_text("#!/bin/sh\n")
    (tmp_path / "900" / "CAPE").mkdir(parents=True)
    (tmp_path / "900" / "CAPE" / ("b" * 64)).write_bytes(b"MZ\x90\x00" + b"\x00" * 8192)

    monkeypatch.setattr(mod, "run_ghidra_on_file", lambda p, o, c: {
        "program_name": p.name, "functions_count": 617, "analysis_success": True,
        "project_dir": "/output/project", "host_output_dir": str(o),
        "analysis_warnings": [],
    })

    result = mod.run_ghidra({"id": 900, "status": "reported"}, tmp_path / "out",
                            tmp_path / "sample.bin", ghidra_cmd=str(ghidra_cmd),
                            get_cape_signatures_fn=lambda _c: ["packed_binary"],
                            storage=tmp_path)

    assert result["analysis_warnings"] == []


# ---------------------------------------------------------------------------
# Deriving warnings for reports that predate the detector
# ---------------------------------------------------------------------------



def test_the_threshold_matches_the_detector_in_the_template():
    """Cross-copy drift guard.

    run-ghidra.py.j2 runs in a container and cannot be imported, so the
    count-based rule necessarily exists twice. #380 is what happens when two
    copies of a rule drift, so pin them together.
    """
    assert f"n_funcs <= {LOW_FUNCTION_THRESHOLD}:" in TEMPLATE, (
        f"template threshold no longer matches LOW_FUNCTION_THRESHOLD="
        f"{LOW_FUNCTION_THRESHOLD}")


def test_the_derived_message_matches_the_detectors_wording():
    """Same finding should read the same way, however it was produced.

    Compared as fragments because the template splits the message across two
    adjacent f-strings; reconstructing that by stripping quotes and newlines
    was fragile enough to fail against correct code on the first attempt.
    """
    derived = derive_analysis_warnings(
        {"analysis_success": True, "functions_count": 1})[0]

    for fragment in ("function(s) recovered — the loader may not have",
                     "resolved an architecture for this binary"):
        assert fragment in TEMPLATE, f"template no longer says {fragment!r}"
        assert fragment in derived, f"derived message no longer says {fragment!r}"


def test_a_legacy_low_function_file_is_derived():
    """The 6 real files in the corpus: success, 1 function, no warning key."""
    out = derive_analysis_warnings({"analysis_success": True, "functions_count": 1})

    assert len(out) == 1
    assert "derived at re-score" in out[0], (
        "a derived warning must not pass as one the analyser emitted")


def test_a_healthy_legacy_file_is_not_derived():
    """Positive control."""
    assert derive_analysis_warnings({"analysis_success": True, "functions_count": 617}) == []


def test_a_failed_analysis_is_not_derived():
    """It already reports failure; a warning would add nothing."""
    assert derive_analysis_warnings({"analysis_success": False, "functions_count": 0}) == []


def test_derivation_is_off_by_default():
    """The live path must not second-guess the detector.

    An EMPTY analysis_warnings list is a real answer — checked, nothing wrong —
    and deriving over it would invent findings at analysis time.
    """
    legacy = [{"program_name": "old.exe", "analysis_success": True, "functions_count": 1}]

    assert collect_analysis_warnings(legacy) == []
    assert collect_analysis_warnings(legacy, derive_when_absent=True) != []


def test_an_explicit_empty_list_is_never_overridden():
    """The detector ran and found nothing; that is not a missing value."""
    checked = [{"program_name": "x.exe", "analysis_success": True,
                "functions_count": 1, "analysis_warnings": []}]

    assert collect_analysis_warnings(checked, derive_when_absent=True) == []


def test_rebuild_actually_derives_for_legacy_reports():
    """Wiring, not presence — again.

    The derivation existed and rebuild called the collector WITHOUT
    derive_when_absent, so every legacy report still scored zero. Mutating that
    argument away left the whole suite green until this test existed, which is
    the same gap the detector itself had in #372.
    """
    from lamware_eval.rebuild import _ghidra_warnings

    legacy = {"analyzed_files": [
        {"program_name": "old.exe", "analysis_success": True, "functions_count": 1}]}

    out = _ghidra_warnings(legacy)

    assert out, "rebuild did not derive; legacy reports still score zero"
    assert out[0].startswith("old.exe:")
    assert "derived at re-score" in out[0]


def test_rebuild_prefers_recorded_warnings_over_derived_ones():
    """A report that HAS the detector's output must not be second-guessed."""
    from lamware_eval.rebuild import _ghidra_warnings

    recorded = {"analysis_warnings": ["x.exe: something the detector said"],
                "analyzed_files": [
                    {"program_name": "x.exe", "analysis_success": True,
                     "functions_count": 1}]}

    out = _ghidra_warnings(recorded)

    assert out == ["x.exe: something the detector said"]
    assert not any("derived" in w for w in out)
