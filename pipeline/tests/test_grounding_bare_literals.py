# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""#243: the scorer must measure truthfulness, not citation style.

On 2026-07-29 a raccoonstealer run scored 0.25 grounded with three claims listed as
fabricated. Every one of them was verbatim in the run's own captured tool output —
`MilcoSoft_#Rip_X` appeared twice, `CheckRemoteDebuggerPresent` 123 times. The only
claim that scored was the one whose evidence happened to look like a Ghidra symbol,
because the literal extractor recognised backticks, quotes, `0x`, and `FUN_` and
nothing else. Claims yielding no literals then fell through to `fabricated`, turning
"I cannot check this" into "the model invented this".

The danger in fixing it is the mirror image: an extractor loose enough to ground
everything would be just as wrong and just as invisible, and it would flatter the
local model — the arm this metric has repeatedly under-scored. So the fabrication
cases below matter more than the grounding cases, and they use the same claim shapes
with artifacts that are genuinely absent.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from grounding_check import _extract_literals, grounding_scorecard  # noqa: E402

# The decompilation the 2026-07-29 run actually saw, trimmed to the relevant lines.
REAL_SOURCE = """
  iVar1 = (*DAT_0041c164)(0x1f0001,0,L"MilcoSoft_#Rip_X");
  GetObjectW((HANDLE)0x0,-0x663d0cb1,(LPVOID)0x0);
  CheckRemoteDebuggerPresent((HANDLE)0x0,(PBOOL)0x0);
  (*DAT_0041c100)(0,0,L"MilcoSoft_#Rip_X");
  DestroyWindow((HWND)0x0);
  undefined4 FUN_0040b477(void) { /* xor loop at 0x0040b477 */ }
  hex samples: 50f2ede2f8931f7c 3b172b1bdf08fcbb 552e3efc272bafd4
"""

# The four claims from that run, verbatim.
CLAIM_MUTEX = "Mutex/Event Name: MilcoSoft_#Rip_X"
CLAIM_XOR = "XOR Decryption Routine: FUN_0040b477 (address 0x0040b477)"
CLAIM_HEX = ("Hex String Samples (pre-decryption): 50f2ede2f8931f7c, "
             "3b172b1bdf08fcbb, 552e3efc272bafd4")
CLAIM_ANTIDEBUG = ("Anti-Debug Noise Pattern: Repeated calls to CheckRemoteDebuggerPresent, "
                   "DestroyWindow, and GetObjectW with zero/null handles interspersed "
                   "between legitimate API calls.")


def _score(claims, source=REAL_SOURCE):
    return grounding_scorecard({"code_level_iocs": claims}, source)


# --------------------------------------------------------------------------
# The regression: real claims, real evidence, previously scored as lies
# --------------------------------------------------------------------------

def test_the_run_that_scored_025_now_scores_100():
    r = _score([CLAIM_MUTEX, CLAIM_XOR, CLAIM_HEX, CLAIM_ANTIDEBUG])
    assert r["grounded"] == 4, r["details"]
    assert r["fabricated"] == []
    assert r["grounded_ratio"] == 1.0


def test_bare_mutex_name_is_checkable():
    """Not backticked, not quoted, not 0x — extracted nothing before."""
    lits = _extract_literals(CLAIM_MUTEX)
    assert "MilcoSoft_#Rip_X" in lits


def test_unprefixed_hex_runs_are_checkable():
    lits = _extract_literals(CLAIM_HEX)
    assert "50f2ede2f8931f7c" in lits


def test_camelcase_api_names_are_checkable():
    lits = _extract_literals(CLAIM_ANTIDEBUG)
    for api in ("CheckRemoteDebuggerPresent", "DestroyWindow", "GetObjectW"):
        assert api in lits, f"{api} not extracted from {lits}"


# --------------------------------------------------------------------------
# The mirror-image danger: it must still catch real fabrication
# --------------------------------------------------------------------------

def test_an_invented_mutex_is_still_fabricated():
    r = _score(["Mutex/Event Name: TotallyFake_#Nope_Z"])
    assert r["fabricated"] == ["Mutex/Event Name: TotallyFake_#Nope_Z"]
    assert r["grounded_ratio"] == 0.0


def test_an_invented_api_name_is_still_fabricated():
    r = _score(["Anti-Debug: calls to NtQueryFakeInformation and ZwBogusCheck"])
    assert len(r["fabricated"]) == 1, r["details"]


def test_an_invented_hex_sample_is_still_fabricated():
    r = _score(["Hex String Samples: deadbeefcafebabe, 0123456789abcdef"])
    assert len(r["fabricated"]) == 1, r["details"]


def test_an_invented_address_is_still_fabricated():
    r = _score(["XOR Decryption Routine: FUN_00999999 (address 0x00999999)"])
    assert len(r["fabricated"]) == 1, r["details"]


def test_a_fabricated_c2_domain_is_still_caught():
    """The failure mode the module was written for (qwen3:32b invented a C2)."""
    r = _score(["C2 domain: evil-command-control.example"])
    assert len(r["fabricated"]) == 1, r["details"]


# --------------------------------------------------------------------------
# The new buckets
# --------------------------------------------------------------------------

def test_an_unscoreable_claim_is_not_called_fabricated():
    """A claim with no extractable artifact is a coverage gap, not a lie.

    Conflating the two is what turned the extractor's blind spot into an accusation.
    It is labelled honestly -- but it is NOT free: see the next test.
    """
    r = _score(["The binary appears to use anti-analysis logic"])
    assert r["unscoreable"] == ["The binary appears to use anti-analysis logic"]
    assert r["fabricated"] == [], "an uncheckable claim is not evidence of lying"


def test_vague_padding_cannot_buy_a_perfect_score():
    """One true claim plus two hedges must NOT score 1.0.

    `code_level_ioc` is defined as concrete, checkable artifacts. If prose were
    excluded from the denominator, a model could emit one real IOC and nine
    sentences of hedging and score perfectly -- the same loophole that
    test_descriptive_ioc_with_a_bogus_literal_is_still_fabricated closes from the
    other side, and that aggregate() already documents for empty cells.
    """
    r = _score([CLAIM_MUTEX, "It behaves maliciously", "It is probably a loader"])
    assert r["grounded"] == 1
    assert len(r["unscoreable"]) == 2
    assert r["total"] == 3, "unscoreable claims must count against the model"
    assert r["grounded_ratio"] == 0.333


def test_partial_evidence_is_reported_and_counted_conservatively():
    """Some artifacts present, one invented: not clean, not a pure fabrication."""
    r = _score(["Anti-Debug: CheckRemoteDebuggerPresent and NtTotallyInvented"])
    assert len(r["partial"]) == 1, r["details"]
    assert len(r["fabricated"]) == 1, (
        "a partial claim is still FLAGGED -- burying one invented artifact among real "
        "ones must not buy a clean score")
    assert r["grounded"] == 0
    assert r["grounded_ratio"] == 0.0


def test_truncation_is_reported_not_silent():
    """The old limit of 6 silently left later artifacts unchecked."""
    many = "Samples: " + ", ".join(f"{i:016x}" for i in range(20))
    r = _score([many])
    assert r["truncated_claims"] == 1


# --------------------------------------------------------------------------
# Style-neutrality: the property the metric is actually supposed to have
# --------------------------------------------------------------------------

def test_the_same_fact_scores_the_same_in_either_citation_style():
    """qwen writes bare, claude backticks. Identical fact, identical verdict.

    This is the whole point of #243: the metric must not encode one model's
    formatting habits as the definition of a checkable claim.
    """
    bare = _score(["Mutex/Event Name: MilcoSoft_#Rip_X"])
    quoted = _score(['Mutex/Event Name: `MilcoSoft_#Rip_X`'])
    assert bare["grounded"] == quoted["grounded"] == 1
    assert bare["grounded_ratio"] == quoted["grounded_ratio"] == 1.0


def test_style_neutrality_holds_for_fabrications_too():
    bare = _score(["Mutex: FakeMutex_#Nope"])
    quoted = _score(['Mutex: `FakeMutex_#Nope`'])
    assert len(bare["fabricated"]) == len(quoted["fabricated"]) == 1


def test_dict_shaped_iocs_still_work():
    """claude-sonnet-5 emits dicts; regressing this killed 5 of 7 cells in July."""
    r = _score([{"type": "mutex", "value": "MilcoSoft_#Rip_X"}])
    assert r["grounded"] == 1


def test_no_claims_is_not_a_perfect_score_in_disguise():
    r = _score([])
    assert r["total"] == 0 and r["grounded_ratio"] == 1.0  # vacuous, flagged by n_with_claims


def test_defanged_iocs_still_refang():
    r = grounding_scorecard({"code_level_iocs": ["C2: evil[.]com"]}, "contact evil.com now")
    assert r["grounded"] == 1


def test_the_shared_extractor_contract_stays_a_list():
    """lamware_eval.consensus consumes this directly.

    An earlier draft of #243 changed `_extract_literals` to return
    (literals, truncated) so the scorer could report truncation. consensus.py calls it
    for claim matching across seeded runs and broke with an AttributeError -- action at
    a distance from changing a shared helper's contract to suit one caller. The
    truncation flag now lives in `_extract_literals_detail`.
    """
    from grounding_check import _extract_literals_detail
    lits = _extract_literals(CLAIM_HEX)
    assert isinstance(lits, list) and all(isinstance(x, str) for x in lits)
    detail, truncated = _extract_literals_detail(CLAIM_HEX)
    assert detail == lits and isinstance(truncated, bool)


# --------------------------------------------------------------------------
# ReDoS: this scorer parses adversarial input
# --------------------------------------------------------------------------

def test_literal_extraction_is_not_vulnerable_to_catastrophic_backtracking():
    """CodeQL py/redos, high severity, on the identifier pattern added by #243.

    The first version was `[A-Za-z][A-Za-z0-9]*(?:[_#][A-Za-z0-9#]+)+` -- `#` appeared in
    BOTH the separator class and the body class, so a run of `##` could be split between
    them exponentially many ways.

    Not a theoretical concern here. `grounding_scorecard` runs over `code_level_ioc`
    values produced by a model reading MALWARE, so the claim text is adversarial input in
    the ordinary sense: a sample can influence what the model writes. A hang in the
    scorer takes the eval harness with it.

    Fixed by making the classes disjoint (`[_#]+` then `[A-Za-z0-9]+`), which makes the
    match unambiguous and linear. This test pins the timing, because the pattern still
    LOOKS fine if the classes silently overlap again.
    """
    import time

    for n in (2_000, 10_000, 40_000):
        pathological = "A" + "#" * n + "!"
        start = time.perf_counter()
        _extract_literals(pathological)
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, (
            f"extraction took {elapsed:.2f}s on {n} repeated '#' -- the separator and "
            f"body character classes have probably started overlapping again")


def test_the_pattern_still_matches_the_mutex_it_exists_for():
    """The ReDoS fix must not quietly drop the case that motivated the pattern."""
    assert "MilcoSoft_#Rip_X" in _extract_literals("Mutex/Event Name: MilcoSoft_#Rip_X")
