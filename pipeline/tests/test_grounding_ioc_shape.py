# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Grounding must accept every IOC shape the models actually emit.

Models disagree on the schema: claude-sonnet-5 emits dicts
({"type","value","context"}), qwen3.6 emits bare strings. Assuming dicts raised
`AttributeError: 'str' object has no attribute 'get'` and killed 5 of 7 local
cells mid-scoring in benchmark pass 4 (2026-07-25) — after their results were
written, so the run reported "0 claims, 28% completion" instead of a crash, and
the local arm's grounding was never measured at all.
"""
from grounding_check import grounding_scorecard

SOURCE = "the loader calls GetTempPathW and builds ~%u.tmp then resolves LoadLibraryA"


def test_dict_shaped_iocs_score():
    a = {"code_level_iocs": [{"value": "GetTempPathW"}, {"value": "notreal.example"}]}
    s = grounding_scorecard(a, SOURCE)
    assert s["total"] == 2 and s["grounded"] == 1
    assert s["fabricated"] == ["notreal.example"]


def test_string_shaped_iocs_score():
    """The shape qwen emits - this used to raise AttributeError."""
    a = {"code_level_iocs": ["GetTempPathW", "notreal.example"]}
    s = grounding_scorecard(a, SOURCE)
    assert s["total"] == 2 and s["grounded"] == 1
    assert s["fabricated"] == ["notreal.example"]


def test_mixed_and_odd_shapes_do_not_raise():
    a = {"code_level_iocs": [{"value": "GetTempPathW"}, "~%u.tmp", 12345, None, ""]}
    s = grounding_scorecard(a, SOURCE)
    assert s["grounded"] == 2          # both real ones found
    assert "12345" in s["fabricated"]  # coerced, not crashed


DECOMP = ("undefined4 FUN_0040b477(char *data,char *key){ "
          "do { data[idx] = data[idx] ^ key[idx % len]; } while (idx < n); } "
          "DestroyWindow((HWND)0x0); CheckRemoteDebuggerPresent((HANDLE)0x0,(PBOOL)0x0);")


def test_descriptive_ioc_is_grounded_via_its_literals():
    """The pass-4 failure: prose claims never match verbatim.

    qwen scored 0/20 grounded because its IOCs are descriptive signatures, e.g.
    a claim naming `FUN_0040b477` - an address four independent runs had
    corroborated - was counted as fabricated.
    """
    a = {"code_level_iocs": [
        "Decryption Loop Signature: the XOR pattern `data[idx] ^ key[idx % len]` "
        "wrapped in a `do` loop in `FUN_0040b477`."]}
    s = grounding_scorecard(a, DECOMP)
    assert s["grounded"] == 1 and s["fabricated"] == []


def test_descriptive_ioc_with_a_bogus_literal_is_still_fabricated():
    """Extraction must not become a free pass - one bad literal fails the claim."""
    a = {"code_level_iocs": [
        "Beacon config decoded in `FUN_0040b477` and posted to `evil-c2.example`."]}
    s = grounding_scorecard(a, DECOMP)
    assert s["grounded"] == 0 and len(s["fabricated"]) == 1


def test_prose_with_no_literals_stays_fabricated():
    a = {"code_level_iocs": ["The binary probably contacts a command and control server."]}
    s = grounding_scorecard(a, DECOMP)
    assert s["grounded"] == 0 and len(s["fabricated"]) == 1


def test_empty_list_is_not_a_perfect_score_by_accident():
    s = grounding_scorecard({"code_level_iocs": []}, SOURCE)
    assert s["total"] == 0 and s["grounded_ratio"] == 1.0  # aggregate() excludes these
