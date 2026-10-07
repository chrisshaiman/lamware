"""A template slot (`<path>`) in a claim is not checked; the concrete rest is.

Owner's decision, 2026-10-07: `<path>` says "a value goes here", it is not a
claim about the binary. Before, the slot alone made a claim fabricated:
    powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "<path>"
    /create /sc minute /tn "Windows Defender Security Scanner" /tr "<path_to_dropper>"
(both real, from the eval corpus). The scorer runs here against text, so these
are behavioural tests of grounding_scorecard itself.
"""

import grounding_check as gc

SRC = ('schtasks /create /sc minute /tn "Windows Defender Security Scanner" '
       'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File')


def score(v, src=SRC):
    return gc.grounding_scorecard({"code_level_iocs": [v]}, src)


def test_the_concrete_rest_of_a_slotted_command_is_grounded():
    g = score('powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "<path>"')
    assert g["grounded"] == 1 and g["fabricated"] == []


def test_a_multiword_slot_does_not_leak_its_inner_name():
    """The identifier rule would pull `path_to_dropper` out of the slot on its own."""
    v = '/create /sc minute /tn "Windows Defender Security Scanner" /tr "<path_to_dropper>"'
    lits, _ = gc._extract_literals_detail(v)
    assert not any("path_to_dropper" in t.lower() for t in lits), lits
    assert score(v)["grounded"] == 1


def test_a_claim_that_is_only_a_slot_is_unscoreable_not_grounded():
    g = score('"<path>"')
    assert g["grounded"] == 0 and g["fabricated"] == [] and len(g["unscoreable"]) == 1
    assert g["total"] == 1   # still in the denominator


def test_an_invented_artifact_beside_a_slot_is_still_fabricated():
    g = score('powershell.exe -File "<path>" C:\\Users\\evil\\dropper.exe')
    assert len(g["fabricated"]) == 1


def test_mixed_case_brackets_are_not_slots():
    assert len(score('"<Evil>" C:\\x\\evil.exe')["fabricated"]) == 1
    lits, _ = gc._extract_literals_detail("<Evil_Name>")
    assert any("Evil_Name" in t for t in lits)


def test_slotted_claims_are_listed():
    g = score('powershell.exe -File "<path>"')
    assert g["placeholder_claims"] == ['powershell.exe -File "<path>"']
    assert score("powershell.exe")["placeholder_claims"] == []
