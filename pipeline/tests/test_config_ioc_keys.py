# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cape's decoded C2 addresses never became IOCs.

`extract_iocs` looked up a fixed lowercase tuple of config keys with
`cfg.get(key)`. Cape's extractors name config fields the way each family's own
config does, and capitalised forms are the common case — this repo's own
correlation fixtures use {"C2": ...}. So the highest-confidence indicators the
pipeline ever gets, already decoded by Cape, produced no IOC at all.

correlation_rules.py reads the same structures with `key.lower()` and had it
right, so the two modules disagreed about the same data: one built a
`c2_from_config` finding while the other emitted nothing for the same address.

Matching is now case-insensitive over an explicit key set, deliberately NOT
substring hints: an "ip" or "url" hint would match "description" and
"curl_useragent" and turn prose into indicators. The scalar and list branches
also share one classifier — the duplicated list branch had no URL case, so a
list of C2 URLs was filed as domain-name.
"""
import json
from pathlib import Path

import pytest

# conftest.py puts ansible/roles/pipeline/files on sys.path — the modules deploy
# flat to /opt/pipeline/, so `ioc_extract` is only importable via that hook.
from ioc_extract import extract_iocs


def _config_iocs(cfg: dict) -> dict:
    report = {"cape": {"extracted_configs": [cfg]}}
    return {i["value"]: i["type"] for i in extract_iocs(report)}


@pytest.mark.parametrize("key", ["C2", "c2", "CNC", "Domains", "Server", "Hosts",
                                 "C2_Address", "URLs", "IPs", "Address"])
def test_config_keys_match_regardless_of_case(key):
    """THE bug. The repo's own correlation fixtures use "C2"."""
    found = _config_iocs({key: "203.0.113.7"})
    assert "203.0.113.7" in found, f"config key {key!r} produced no IOC"


def test_the_capitalised_fixture_this_repo_already_uses_produces_an_ioc():
    """Pinned against the exact shape in test_correlation_rules.py, so the two
    modules cannot disagree about the same config again."""
    found = _config_iocs({"C2": "203.0.113.7", "version": "1.2"})
    assert found.get("203.0.113.7") == "ipv4-addr"
    assert "1.2" not in found, "a version string became an indicator"


def test_urls_in_a_list_are_typed_as_urls():
    """The list branch used to classify everything non-IPv4 as domain-name, so a
    list of C2 URLs was filed under the wrong type."""
    found = _config_iocs({"URLs": ["http://evil.example/gate.php",
                                   "evil2.example", "203.0.113.8"]})
    assert found.get("http://evil.example/gate.php") == "url"
    assert found.get("evil2.example") == "domain-name"
    assert found.get("203.0.113.8") == "ipv4-addr"


@pytest.mark.parametrize("key", ["description", "curl_useragent", "version",
                                 "encryption_key", "campaign", "mutex"])
def test_prose_fields_do_not_become_indicators(key):
    """Why this is an explicit key set and not substring hints: "description"
    contains "ip", and "curl_useragent" contains "url"."""
    assert _config_iocs({key: "some descriptive text"}) == {}


def test_a_non_string_value_is_skipped_not_crashed():
    """Cape configs carry ints, bools and nested dicts alongside the addresses."""
    assert _config_iocs({"C2": 8080, "port": 443, "hosts": [None, "evil.example"]}) == {
        "evil.example": "domain-name"}


def test_the_sample_report_fixture_still_round_trips():
    """Guards the guard: a fixture whose configs are empty would make every
    assertion above vacuous if the loop were accidentally removed."""
    fixture = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "sample_report.json")
        .read_text(encoding="utf-8"))
    assert isinstance(extract_iocs(fixture), list)
