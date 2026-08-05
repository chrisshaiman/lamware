# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A re-spelled address is the same address (#286).

Ghidra prints the SAME address two ways in one run's output: zero-padded in string
listings (`0x00419070`) and bare in decompiled operands (`0x41970c`). Plain substring
matching treats those as different literals, so a model that quotes the listing form
for an address that appears in code is recorded as having invented it.

Measured 2026-08-03 on qwen@15:s1337 / raccoonstealer. The run's ONLY "fabrication"
was:

    XOR Key Pattern: hex strings in data section (0x00419070-0x0041970c) are
    16-byte XOR-encoded API names

`0x00419070` hit; `0x0041970c` missed. The source contained
`FUN_0040b477(0x41970c,"23ff5473b825af32",0x18)` feeding GetProcAddress — so the
claim was not merely grounded, it was correct, and it was the single claim standing
between that run and 5/5.

This matters beyond one cell: the penalty falls on whoever cites Ghidra-style padded
addresses, which is the local model's house style. Every qwen-vs-cloud comparison we
have published is biased by it in one direction.

The boundary tests are the important half. Matching by value must not become a
looser match than the substring rule it replaces.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from grounding_check import grounding_scorecard  # noqa: E402


def _score(claim: str, source: str) -> dict:
    return grounding_scorecard({"code_level_iocs": [claim]}, source)


# The real decompilation, trimmed. Note the address appears WITHOUT zero padding,
# which is the whole point.
REAL_SOURCE = (
    'pCVar1 = FUN_0040b477(0x4196ec,"0d64a84468a4a1e5",9);\n'
    "DAT_0041c074 = GetProcAddress(pHVar2,pCVar1);\n"
    'pCVar1 = FUN_0040b477(0x41970c,"23ff5473b825af32",0x18);\n'
    "DAT_0041c094 = GetProcAddress(pHVar2,pCVar1);\n"
    '{"address": "0x00419070", "value": "50f2ede2f8931f7c", "length": 16}\n'
)

REAL_CLAIM = ("XOR Key Pattern: hex strings in data section "
              "(0x00419070-0x0041970c) are 16-byte XOR-encoded API names")


def test_the_measured_regression():
    """The exact claim and source that produced the false fabrication."""
    r = _score(REAL_CLAIM, REAL_SOURCE)
    assert r["fabricated"] == [], (
        f"the qwen@15 XOR-key claim is grounded — 0x0041970c and 0x41970c are the "
        f"same address. Got {r['fabricated']}")
    assert r["grounded"] == 1
    assert r["grounded_ratio"] == 1.0


@pytest.mark.parametrize("claim_form,source_form", [
    ("0x0041970c", "0x41970c"),    # padded claim, bare source — the measured case
    ("0x41970c", "0x0041970c"),    # bare claim, padded source — the converse
    ("0x0000419c", "0x419c"),
    ("0x419c", "0x00000000419c"),  # padding width is arbitrary
])
def test_padding_is_not_a_difference(claim_form, source_form):
    r = _score(f"Address {claim_form} holds the key", f"mov eax, {source_form}")
    assert r["grounded"] == 1, f"{claim_form} should match {source_form}"


@pytest.mark.parametrize("claim_form,source_form", [
    ("0x4197", "0x41970c"),        # shorter must NOT match a longer containing it
    ("0x41970", "0x41970c"),
    ("0x41970c", "0x41970cd"),     # nor the reverse
    ("0xdead", "0xdeadbeef"),
])
def test_a_longer_address_does_not_ground_a_shorter_one(claim_form, source_form):
    """The loophole guard.

    Plain substring matching allowed `0x4197` to be satisfied by `0x41970c`; value
    matching must be strictly tighter, not looser. Without this the fix trades a
    false fabrication for a false acquittal, which is the worse error — this module
    exists because a model invented a C2 domain.
    """
    r = _score(f"Key at {claim_form}", f"data at {source_form}")
    assert r["fabricated"], (
        f"{claim_form} must not be grounded by {source_form}; that is a looser "
        f"match than the substring rule it replaces")


def test_an_invented_address_is_still_fabricated():
    """The fix must not ground an address that appears in no spelling."""
    r = _score("Key at 0x00deadbe", REAL_SOURCE)
    assert r["fabricated"], "an absent address stays fabricated regardless of padding"


def test_non_hex_literals_are_unaffected():
    """Domains and symbols keep exact matching — only hex re-spells."""
    assert _score("C2 at evil-c2.example.com", REAL_SOURCE)["fabricated"]
    assert _score("Decoder FUN_0040b477 XORs the name", REAL_SOURCE)["grounded"] == 1


def test_placeholder_symbol_is_unscoreable_not_fabricated():
    """`DAT_0041cXXX` names a family; the X's are wildcards, not digits.

    Recording that as "invented" is factually wrong — DAT_0041c074 and DAT_0041c094
    are both right there. It routes to `unscoreable` instead.
    """
    r = _score("API Resolution Table: Multiple DAT_0041cXXX function pointers",
               REAL_SOURCE)
    assert r["fabricated"] == [], f"placeholder is not a fabrication: {r['fabricated']}"
    assert len(r["unscoreable"]) == 1


def test_placeholder_relabelling_does_not_change_the_score():
    """Honest labelling, strict scoring.

    `unscoreable` stays in the denominator by design, so this changes what we SAY
    about a claim, not what we score it. A test pins that, because quietly turning
    fabrications into free passes is exactly how this check would get disarmed.
    """
    r = _score("Multiple DAT_0041cXXX function pointers", REAL_SOURCE)
    assert r["total"] == 1 and r["grounded"] == 0
    assert r["grounded_ratio"] == 0.0


def test_a_placeholder_cannot_launder_a_real_fabrication():
    """A claim citing a wildcard AND an invented domain is still flagged."""
    r = _score("Table DAT_0041cXXX exfils to evil-c2.example.com", REAL_SOURCE)
    assert r["fabricated"], "the invented domain must still flag the claim"


# --- the address may be a SYMBOL, not a number (#286, second pass) ----------
#
# The first fix required a literal `0x` in the source. Ghidra names an address as a
# symbol far more often than it prints it as a number, so that missed the commoner
# case entirely — and it was the dominant error in the six-sample sweep.

AMADEY_SOURCE = (
    '"decompilation": "  uVar3 = DAT_140014c40 ^ 0x9e3779b9;\\n'
    "  puVar1 = (undefined8 *)DAT_140054300;\\n"
    '  DAT_1400546f0 = FUN_140054480(puVar1);"\n'
)


@pytest.mark.parametrize("claim_hex,source_form", [
    ("0x140014c40", "DAT_140014c40"),     # the measured amadey case
    ("0x140054300", "DAT_140054300"),
    ("0x140054480", "FUN_140054480"),     # function symbols too
    ("0x41970c", "LAB_41970c"),
    ("0x140054300", "140054300"),         # bare, no prefix at all
    ("0x0140054300", "DAT_140054300"),    # padded claim vs symbol
])
def test_an_address_inside_a_ghidra_symbol_is_grounded(claim_hex, source_form):
    r = _score(f"Encrypted Payload at {claim_hex}", f"  x = {source_form};")
    assert r["grounded"] == 1, (
        f"{claim_hex} should be grounded by {source_form} — the surrounding syntax "
        f"is Ghidra's choice, not part of the model's claim")


def test_the_measured_amadey_regression():
    """Nine of amadey's eleven 'fabrications' were this, on the 2026-08-04 sweep.

    Reported 2/13 = 0.154; the true score is 11/13 = 0.846. Every address was in the
    source, several of them four times over.
    """
    claims = [f"Encrypted Payload at {h}" for h in
              ("0x140014c40", "0x140054300", "0x1400546f0", "0x140054480")]
    r = grounding_scorecard({"code_level_iocs": claims}, AMADEY_SOURCE)
    assert r["fabricated"] == [], (
        f"addresses present as DAT_/FUN_ symbols are grounded, not invented: "
        f"{r['fabricated']}")
    assert r["grounded_ratio"] == 1.0


# --- guards on the WIDER match ---------------------------------------------


@pytest.mark.parametrize("claim_hex,source_form", [
    ("0x4197", "DAT_41970c"),        # short must not match a longer symbol
    ("0x140054", "DAT_140054300"),
    ("0x54300", "DAT_140054300"),    # nor a SUFFIX of a longer address
    ("0xdead", "DAT_deadbeef"),
])
def test_a_longer_symbol_does_not_ground_a_shorter_address(claim_hex, source_form):
    """Dropping the `0x` requirement widens the match; it must not widen into a
    free pass. Same direction as the padding guards above."""
    r = _score(f"Key at {claim_hex}", f"  x = {source_form};")
    assert r["fabricated"], f"{claim_hex} must not be grounded by {source_form}"


def test_a_short_value_still_requires_the_0x_prefix():
    """Without `0x` to anchor on, a 2-digit value collides with any decimal in the
    tool output — a length, a count, an offset — and would ground a claim on a
    coincidence. Short values keep the strict rule."""
    r = _score("Flag 0x40 controls the branch", '{"length": 40, "count": 12}')
    assert r["fabricated"], (
        "a 2-digit hex value must not be grounded by a bare decimal 40; that is a "
        "collision, not evidence")


def test_a_long_invented_address_is_still_fabricated():
    r = _score("Payload at 0x140099999", AMADEY_SOURCE)
    assert r["fabricated"], "an address absent in every spelling stays fabricated"
