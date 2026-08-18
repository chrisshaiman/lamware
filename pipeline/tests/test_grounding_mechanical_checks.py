# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Two ways a claim scores as grounded while being worthless or wrong (#319).

Both were found by adjudicating `depth-10-vs-15-n7` (2026-08-07) by hand, and they
fail in OPPOSITE directions — which is why `grounded_ratio` could not rank depths:

  bare symbols   INFLATE the score. raccoonstealer/qwen@15 emitted 12 of 17
                 code_level_iocs as auto-generated `DAT_` names. It scored 16/17 =
                 0.941 and looked 3.4x more productive than qwen@10's 5/5, which had
                 named the same findings WITH their significance.

  misattribution HIDES a regression. icedid/qwen@10 said "0x811c9dc5 used in FNV-1a
                 hash validation routine" (correct); qwen@15 said "Adler-32 initial
                 value: 0x811c9dc5" (wrong). Both scored grounded.

Neither check alters `grounded_ratio`. They make the failures visible; folding them
into the headline is a deliberate re-baseline decision, not a side effect.

The claim strings below are copied verbatim from the stored cells. A check that
passes on invented examples but not on the output that motivated it is worthless.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from grounding_check import (  # noqa: E402
    constant_misattributions,
    grounding_scorecard,
)

# Verbatim from raccoonstealer_982a0d1b/eval/qwen_15/result.json
RACCOON_15 = [
    "f26f614d4c0bc2bcd6601785661fb5cf", "DAT_0041b6f4", "DAT_0041c048",
    "DAT_0041c088", "DAT_0041c0bc", "DAT_0041c0d8", "DAT_0041c138",
    "DAT_0041c184", "DAT_0041c190", "DAT_0041c0c4", "DAT_0041c028",
    "DAT_0041c0a8", "DAT_0041c0f0", "CoDecodeProxy", "FUN_0041246b",
    "FUN_0040ce41", "FUN_00412dc2",
]

# Verbatim from raccoonstealer_982a0d1b/eval/qwen_10/result.json
RACCOON_10 = [
    "Hex string 'f26f614d4c0bc2bcd6601785661fb5cf' passed to FUN_0041246b, "
    "likely encryption key or IV",
    "Magic constant 0x5cdabf15 used in GetObjectW parameter in anti-analysis routine",
    "Function call CoDecodeProxy used in custom COM proxy decoding function",
]


# ---------------------------------------------------------------------------
# Bare symbols
# ---------------------------------------------------------------------------

def test_the_real_enumerated_cell_is_flagged():
    """THE motivating case: 12 of 17 claims carry no information."""
    res = grounding_scorecard({"code_level_iocs": RACCOON_15}, "\n".join(RACCOON_15))
    # 12 DAT_ + 3 FUN_. The hex key and CoDecodeProxy are real artifacts.
    assert len(res["bare_symbol_claims"]) == 15, (
        f"expected the DAT_/FUN_ enumeration to be flagged, got "
        f"{res['bare_symbol_claims']}")
    assert "DAT_0041c048" in res["bare_symbol_claims"]
    assert "f26f614d4c0bc2bcd6601785661fb5cf" not in res["bare_symbol_claims"], (
        "a hex key is a real artifact, not an auto-generated symbol name")
    assert "CoDecodeProxy" not in res["bare_symbol_claims"], (
        "a real API name is not an auto-generated symbol")


def test_the_explanatory_cell_is_not_flagged():
    """The check must not fire on the analysis it is meant to favour.

    qwen@10 cites FUN_0041246b too — but as part of a claim ABOUT it. Flagging that
    would punish exactly the behaviour worth rewarding.
    """
    res = grounding_scorecard({"code_level_iocs": RACCOON_10}, "\n".join(RACCOON_10))
    assert res["bare_symbol_claims"] == []


def test_a_symbol_with_context_is_not_bare():
    res = grounding_scorecard(
        {"code_level_iocs": ["FUN_0041246b is the core anti-analysis function"]},
        "FUN_0041246b")
    assert res["bare_symbol_claims"] == []


def test_backticks_do_not_smuggle_a_bare_symbol_past_the_check():
    res = grounding_scorecard({"code_level_iocs": ["`DAT_0041c048`"]}, "DAT_0041c048")
    assert res["bare_symbol_claims"] == ["`DAT_0041c048`"]


def test_bare_symbols_do_not_change_the_ratio():
    """Deliberate. Altering the headline would make every archived scorecard
    incomparable; the point is visibility, not a re-baseline by stealth."""
    res = grounding_scorecard({"code_level_iocs": RACCOON_15}, "\n".join(RACCOON_15))
    assert res["grounded_ratio"] == 1.0
    assert res["grounded"] == 17


# ---------------------------------------------------------------------------
# Constant misattribution
# ---------------------------------------------------------------------------

def test_the_real_regression_is_caught():
    """icedid qwen@15, verbatim. Depth 10 got this right and depth 15 got it wrong;
    grounding scored both identically."""
    wrong = constant_misattributions("Adler-32 initial value: 0x811c9dc5")
    assert wrong, "0x811c9dc5 called Adler-32 must be flagged"
    assert "FNV-1a" in wrong[0]


def test_the_second_half_of_the_same_regression():
    wrong = constant_misattributions("Adler-32 multiplier: 0x1000193")
    assert wrong and "FNV-1a" in wrong[0]


def test_the_correct_identification_is_not_flagged():
    """icedid qwen@10, verbatim — and claude-sonnet-5 said the same. A check that
    fires on the right answer is worse than no check."""
    assert constant_misattributions(
        "Magic constant: 0x811c9dc5 used in FNV-1a hash validation routine") == []
    assert constant_misattributions(
        "0x811c9dc5 — FNV-1a hash offset-basis used to validate decrypted data") == []


def test_naming_no_algorithm_is_not_an_error():
    """Silence is the default. A bare constant expresses no opinion to contradict."""
    assert constant_misattributions("Magic constant 0x811c9dc5 at FUN_00401000") == []


def test_an_unknown_constant_is_not_second_guessed():
    assert constant_misattributions("Adler-32 seed: 0xdeadbeef") == []


def test_windows_protection_constants_are_checked_in_reverse():
    """icedid qwen@15, verbatim. 0x20 is PAGE_EXECUTE_READ; READWRITE is 0x40."""
    wrong = constant_misattributions("Memory protection: 0x20 (PAGE_EXECUTE_READWRITE)")
    assert wrong, "0x20 labelled PAGE_EXECUTE_READWRITE must be flagged"
    assert "0X40" in wrong[0].upper()


def test_the_correct_protection_constant_passes():
    assert constant_misattributions("Memory protection: 0x40 PAGE_EXECUTE_READWRITE") == []


def test_misattribution_is_reported_but_does_not_change_the_ratio():
    res = grounding_scorecard(
        {"code_level_iocs": ["Adler-32 initial value: 0x811c9dc5"]}, "0x811c9dc5")
    assert res["misattributed"], "must be reported"
    assert res["grounded_ratio"] == 1.0, (
        "the literal IS in the source — only the interpretation is wrong, and "
        "conflating the two would make `fabricated` mean two different things")


def test_substring_collisions_do_not_produce_false_positives():
    """`sha-1` must not match inside `sha-256`, or every SHA-256 claim is flagged."""
    assert constant_misattributions(
        "0x6a09e667 is the SHA-256 initial hash value") == []


# ---------------------------------------------------------------------------
# A cited ADDRESS is not a claim about a named constant's value
# ---------------------------------------------------------------------------
#
# The named-constant check collected every hex value in the text and required
# the constant's value to be among them:
#
#     cited = {h.lstrip("0").lower() for h in _HEX_IN_TEXT.findall(text)}
#     if cited and expected not in cited: ...flag...
#
# `cited` was not scoped to the constant, so any address in the same sentence
# counted as a competing claim. "VirtualAlloc at 0x00401230 requests
# PAGE_EXECUTE_READWRITE" — a correct statement, and the ordinary way to write
# RE prose — was reported as "PAGE_EXECUTE_READWRITE is 0x40, not 0x401230".
#
# This is the checker that measures hallucination, so its false positives are
# recorded as the model's. A grounding check that invents misattributions
# against correct analyses corrupts the metric the eval exists to produce, in
# the direction that looks like rigour.

CORRECT_PROSE = [
    "VirtualAlloc at 0x00401230 requests PAGE_EXECUTE_READWRITE.",
    "The shellcode at 0x7ffd1000 maps PAGE_READWRITE for its config.",
    "At FUN_00401000 (0x401000) the stub sets PAGE_EXECUTE_READ on the region.",
    "PAGE_EXECUTE_READWRITE (0x40) applied at 0x00401230.",
    "Memory protection: 0x40 PAGE_EXECUTE_READWRITE",
    "The region was allocated PAGE_EXECUTE_READWRITE.",
]

REAL_MISATTRIBUTIONS = [
    ("Memory protection: 0x20 (PAGE_EXECUTE_READWRITE)", "0X40"),
    ("Claims PAGE_EXECUTE_READWRITE is 0x20.", "0X40"),
    ("PAGE_READWRITE = 0x40 in the config blob at 0x140001000", "0X4"),
    ("The loader uses PAGE_EXECUTE_READ, i.e. 0x40.", "0X20"),
]


@pytest.mark.parametrize("text", CORRECT_PROSE)
def test_an_address_in_the_same_sentence_is_not_a_misattribution(text):
    """THE bug. Every one of these is a true statement."""
    assert constant_misattributions(text) == [], (
        f"a correct claim was reported as a hallucination: {text!r}")


@pytest.mark.parametrize("text,expected_hex", REAL_MISATTRIBUTIONS)
def test_a_real_misattribution_is_still_caught(text, expected_hex):
    """The check must not be narrowed into uselessness — this is the half that
    matters, and both orderings and several copulas have to keep working."""
    wrong = constant_misattributions(text)
    assert wrong, f"a genuine misattribution went unreported: {text!r}"
    assert expected_hex in wrong[0].upper()


def test_a_wrong_value_still_flags_when_an_address_is_also_present():
    """The two halves together: scoping to the constant must not let a real
    misattribution hide behind an unrelated address."""
    wrong = constant_misattributions(
        "At 0x00401230 the stub sets PAGE_EXECUTE_READWRITE (0x20).")
    assert wrong and "0X40" in wrong[0].upper()


def test_naming_the_constant_with_no_value_stays_silent():
    """Silence is the documented default: expressing no opinion is not an error."""
    assert constant_misattributions("It sets PAGE_EXECUTE_READWRITE on the region.") == []


def test_the_nesting_rule_still_holds():
    """PAGE_EXECUTE is a substring of PAGE_EXECUTE_READWRITE; the longest match
    wins, or the shorter name is checked against the longer one's value."""
    assert constant_misattributions("Sets PAGE_EXECUTE_READWRITE (0x40).") == []
    assert constant_misattributions("Sets PAGE_EXECUTE (0x10).") == []
