# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""#709: strings Ghidra referenced by an `s_`/`u_` label were scored as fabricated.

Ghidra's decompiler does not print a string where code uses it; it prints a label
built from the text — `s_`/`u_`, every non-alphanumeric character as `_`, then the
address — and cuts long text at a fixed length. Measured 2026-10-06 across 88 eval
cells: 11 of 48 "fabricated" claims were a string the model read through one of
these (7 exact, 4 truncated).

The grounding shapes below are the two observed lines. The NEGATIVE cases matter
more: a label-aware matcher loose enough to let a short literal ride inside any long
string would flatter every arm, and nothing downstream could see it.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from grounding_check import (  # noqa: E402
    _GHIDRA_LABEL_TRUNCATION,
    grounding_scorecard,
    labelify,
)

# Verbatim from eval tool output / init text (lead, 2026-10-06).
EXACT_LINE = "local_14c8[0] = s_nbgtpasrg_exe_14001b610[8];"
TRUNC_LINE = "fun_00dddaf5(u__c__windows_system32_fodhelper_e_00e16c38,0x2000,0);"
# The same label as Ghidra itself spells it, before lowercasing.
TRUNC_LINE_CASED = "FUN_00dddaf5(u__C__Windows_System32_fodhelper_e_00e16c38,0x2000,0);"


def _score(claims, source):
    return grounding_scorecard({"code_level_iocs": claims}, source)


def _grounded(claim, source) -> bool:
    return _score([claim], source)["grounded"] == 1


# --- the observed false positives, now grounded ---


def test_the_observed_truncated_label_is_32_characters():
    """The number the prefix rule rests on, read off the real label rather than
    assumed: `u_` + body + `_00e16c38`, body cut inside `.exe`."""
    body = TRUNC_LINE.split("u_", 1)[1].rsplit("_00e16c38", 1)[0]
    assert len(body) == _GHIDRA_LABEL_TRUNCATION == 32


def test_exact_ascii_label_grounds_the_filename():
    r = _score(["nbgtpasrg.exe"], EXACT_LINE)
    assert r["grounded"] == 1 and r["fabricated"] == []
    assert r["grounded_via_label"] == [{
        "claim": "nbgtpasrg.exe",
        "literals": [{"literal": "nbgtpasrg.exe", "label_body": "nbgtpasrg_exe",
                      "via": "exact"}]}]


@pytest.mark.parametrize("source", [TRUNC_LINE, TRUNC_LINE_CASED])
def test_truncated_utf16_label_grounds_the_full_path(source):
    r = _score([r"C:\Windows\System32\fodhelper.exe"], source)
    assert r["grounded"] == 1 and r["fabricated"] == []
    (hit,) = r["grounded_via_label"][0]["literals"]
    assert hit["via"] == "truncated_prefix"
    assert hit["label_body"] == "c__windows_system32_fodhelper_e"


def test_json_doubled_backslashes_in_the_claim_spell_the_same_label():
    """`normalize` collapses backslash runs, so `C:\\\\Windows` is one `_` per
    separator — as the binary's string has one character there."""
    assert labelify("C:\\\\Windows\\\\System32") == labelify(r"C:\Windows\System32")
    assert _grounded("C:\\\\Windows\\\\System32\\\\fodhelper.exe", TRUNC_LINE)


def test_a_label_literal_inside_a_longer_claim_is_covered():
    """Matching is per LITERAL, so a descriptive claim citing both strings grounds."""
    claim = (r"Copies itself to %LOCALAPPDATA%\nbgtpasrg.exe and runs "
             r"C:\Windows\System32\fodhelper.exe for UAC bypass")
    r = _score([claim], EXACT_LINE + "\n" + TRUNC_LINE)
    assert r["grounded"] == 1
    vias = sorted(h["via"] for h in r["grounded_via_label"][0]["literals"])
    assert vias == ["exact", "truncated_prefix"]


def test_pointer_to_string_label_names_the_same_string():
    assert _grounded("nbgtpasrg.exe", "x = PTR_s_nbgtpasrg_exe_14001b610;")


# --- transparency: the change must be visible, and only where it applies ---


def test_plainly_grounded_claims_are_not_reported_as_via_label():
    r = _score(["nbgtpasrg.exe"], EXACT_LINE + ' "nbgtpasrg.exe"')
    assert r["grounded"] == 1 and r["grounded_via_label"] == []


def test_a_label_does_not_rescue_a_claim_with_an_invented_artifact():
    """One invented artifact still flags the claim (the #243 contract)."""
    r = _score(["nbgtpasrg.exe beacons to evil-c2.example.net"], EXACT_LINE)
    assert r["grounded"] == 0
    assert len(r["fabricated"]) == 1 and len(r["partial"]) == 1
    assert r["grounded_via_label"] == []
    assert r["details"][0]["via_label"][0]["via"] == "exact"


# --- must stay FABRICATED ---


def test_a_shared_prefix_shorter_than_the_label_does_not_ground():
    """`cmd.exe` shares `c__windows_system32_` with the truncated fodhelper label;
    the literal must START WITH the whole 32-character body."""
    assert not _grounded(r"C:\Windows\System32\cmd.exe", TRUNC_LINE)


def test_a_literal_that_is_only_a_substring_of_a_label_does_not_ground():
    assert not _grounded("`Windows\\System32`", TRUNC_LINE)
    assert not _grounded("nbgtpasrg.exe",
                         "f(s_install_nbgtpasrg_exe_now_00401000);")


def test_the_basename_of_a_truncated_path_label_does_not_ground():
    """Deliberate: the label never shows `.exe`, and allowing a match inside a label
    is the substring loophole. This claim shape stays fabricated after #709."""
    assert not _grounded("fodhelper.exe", TRUNC_LINE)


def test_an_untruncated_label_is_not_a_prefix():
    """A 19-character body was not cut, so it cannot vouch for anything longer."""
    assert not _grounded(r"C:\Windows\System32\cmd.exe",
                         "f(s_C__Windows_System32_00401000);")


def test_a_label_body_below_the_minimum_does_not_ground():
    assert not _grounded("a.exe", "f(s_a_exe_00401000);")


def test_a_punctuation_heavy_truncated_label_is_not_a_prefix():
    raw = "_" * 20 + "abcdef" + "_" * 6
    assert len(raw) == _GHIDRA_LABEL_TRUNCATION
    assert not _grounded("abcdefgh.dll", f"f(s_{raw}_00401000);")


def test_an_identifier_merely_containing_s_is_not_a_label():
    """Labels are whole tokens: `my_s_..._addr` is someone else's identifier."""
    assert not _grounded("nbgtpasrg.exe", "my_s_nbgtpasrg_exe_14001b610 = 0;")


def test_a_label_needs_its_address():
    assert not _grounded("nbgtpasrg.exe", "s_nbgtpasrg_exe = 1;")


# --- a number nobody can see is not a fix (#380) ---


def test_the_count_reaches_the_cell_the_summary_and_the_rendered_scorecard():
    from lamware_eval.corpus import CorpusSample
    from lamware_eval.metrics import aggregate, compose_cell
    from lamware_eval.scorecard import render_scorecard

    sample = CorpusSample("ab" * 32, "unclassified", "/tmp/x")
    analysis = {"code_level_iocs": [{"value": "nbgtpasrg.exe", "type": "file"}]}
    cell = compose_cell("qwen@10", sample, analysis, EXACT_LINE, None, 1.0, 0.0,
                        {"completed": True}, None)
    assert cell["grounded"] == 1 and cell["grounded_via_label"] == 1
    summary = aggregate([cell])["qwen@10"]
    assert summary["total_grounded_via_label"] == 1
    md = render_scorecard("t", [cell], aggregate([cell]))
    headers = [ln for ln in md.splitlines()
               if ln.startswith("| arm |") or ln.startswith("| n |")]
    tables = [ln for ln in md.splitlines() if "grounded_via_label" in ln
              and ln.startswith("|")]
    assert len(tables) == 2, f"expected both tables to carry the column: {headers}"
