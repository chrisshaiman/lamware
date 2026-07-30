# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the IOC grounding (fabrication) check."""
from grounding_check import grounding_scorecard, normalize


def test_normalize_refangs_and_lowercases():
    assert normalize("hxxp://Evil[.]Com[:]8080") == "http://evil.com:8080"
    assert normalize("A  b\tc") == "a b c"


def test_grounded_ioc_present_in_source():
    analysis = {"code_level_ioc": [{"type": "domain", "value": "evil.example.com"}]}
    source = "the sample beacons to evil.example.com over https"
    sc = grounding_scorecard(analysis, source)
    assert sc["total"] == 1
    assert sc["grounded"] == 1
    assert sc["fabricated"] == []
    assert sc["grounded_ratio"] == 1.0


def test_fabricated_ioc_flagged():
    analysis = {"code_level_ioc": [
        {"type": "domain", "value": "evil.example.com"},
        {"type": "domain", "value": "notreal.cloudflare.net"},
    ]}
    source = "beacons to evil.example.com"
    sc = grounding_scorecard(analysis, source)
    assert sc["total"] == 2
    assert sc["grounded"] == 1
    assert sc["fabricated"] == ["notreal.cloudflare.net"]
    assert sc["grounded_ratio"] == 0.5


def test_defanged_claim_matches_plain_source():
    analysis = {"code_level_ioc": [{"type": "url", "value": "hxxp://evil[.]test/x"}]}
    source = "downloads from http://evil.test/x"
    sc = grounding_scorecard(analysis, source)
    assert sc["fabricated"] == []


def test_no_iocs_is_clean():
    sc = grounding_scorecard({"code_level_ioc": []}, "anything")
    # Asserted key-by-key rather than by whole-dict equality: #243 added `partial`,
    # `unscoreable`, `truncated_claims` and `details`, and an exact-match assertion
    # fails on any future addition without saying anything about the behaviour it
    # was written to protect.
    assert sc["total"] == 0
    assert sc["grounded"] == 0
    assert sc["fabricated"] == []
    assert sc["grounded_ratio"] == 1.0


def test_missing_key_is_clean():
    sc = grounding_scorecard({}, "anything")
    assert sc["total"] == 0
    assert sc["grounded_ratio"] == 1.0


def test_plural_code_level_iocs_key_is_scored():
    # Models frequently emit the plural key; it must still be grounded.
    analysis = {"code_level_iocs": [{"type": "domain", "value": "evil.example.com"}]}
    sc = grounding_scorecard(analysis, "beacon to evil.example.com")
    assert sc["total"] == 1
    assert sc["grounded"] == 1
    assert sc["fabricated"] == []
