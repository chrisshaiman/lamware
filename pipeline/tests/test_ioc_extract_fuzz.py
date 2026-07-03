# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Property-based fuzzing of the IOC extraction parsers.

These functions ingest a fully adversary-controlled report dict (CAPE +
Volatility + Ghidra output derived from a malicious sample). A malformed or
hostile report must never crash the parser with an uncaught exception — a crash
here aborts DB ingestion for the whole analysis. The invariant under test:
**the parsers are total** — for any input shape they return a well-formed
result and never raise.
"""
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from ioc_extract import (
    extract_iocs,
    is_benign_domain,
    is_benign_indicator,
    map_iocs_to_techniques,
)

# Field names the parser reads at every nesting level. Drawing dict keys from
# this pool (mixed with random text) makes the fuzzer build report-shaped nested
# structures that actually reach the deep access paths (network.dns_queries[].
# domain, cape.mutex_iocs[].name, volatility.insights.mutexes[], …) instead of
# random dicts that bail at the first .get().
KNOWN_KEYS = [
    "triage", "cape", "volatility", "ghidra", "pcap_analysis", "llm_interpretation",
    "yara_matches", "rule", "ssdeep", "analyzed_files", "sha256",
    "strings_of_interest", "shellcode_artifacts", "source", "network",
    "dns_queries", "domains", "hosts", "http_requests", "tcp_connections",
    "domain", "ip", "answers", "url", "host", "method", "dst",
    "extracted_configs", "c2", "server", "mutex_iocs", "name", "action",
    "plugins", "netscan", "ForeignAddr", "ForeignPort", "insights", "mutexes",
    "mutex", "active_connections", "foreign_addr", "suspicious_dlls", "dll_path",
    "suspicious_cmdlines", "cmdline", "suspicious_files", "path", "file_paths",
    "urls", "ip_addresses", "dll_names", "zeek", "iocs", "type", "value",
    "suricata", "alerts", "signature", "analysis", "capabilities",
]

# Arbitrary JSON-ish values: the shapes an attacker can put anywhere in a report.
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(),
    lambda children: st.lists(children, max_size=5)
    | st.dictionaries(st.sampled_from(KNOWN_KEYS) | st.text(max_size=8), children, max_size=6),
    max_leaves=40,
)

report_shaped = st.dictionaries(
    st.sampled_from(KNOWN_KEYS) | st.text(max_size=8),
    json_values,
    max_size=10,
)

IOC_KEYS = {"type", "value", "source", "context"}


def _assert_wellformed_iocs(iocs):
    assert isinstance(iocs, list)
    for ioc in iocs:
        assert isinstance(ioc, dict)
        assert IOC_KEYS.issubset(ioc.keys())
        for k in IOC_KEYS:
            assert isinstance(ioc[k], str)


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(report=report_shaped)
def test_extract_iocs_is_total_on_report_shaped(report):
    _assert_wellformed_iocs(extract_iocs(report))


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(report=st.dictionaries(st.text(max_size=10), json_values, max_size=8))
def test_extract_iocs_is_total_on_arbitrary_dict(report):
    _assert_wellformed_iocs(extract_iocs(report))


@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(report=report_shaped, extra=st.lists(json_values, max_size=6))
def test_map_iocs_to_techniques_is_total(report, extra):
    # Pass arbitrary junk as the "iocs" arg too — it is derived data, but harden anyway.
    result = map_iocs_to_techniques(report, extra)
    assert isinstance(result, list)


@settings(max_examples=300)
@given(domain=st.text())
def test_is_benign_domain_is_total(domain):
    assert isinstance(is_benign_domain(domain), bool)


@settings(max_examples=300)
@given(ioc_type=st.text(), value=st.text(), context=st.text())
def test_is_benign_indicator_is_total(ioc_type, value, context):
    assert isinstance(is_benign_indicator(ioc_type, value, context), bool)


# --- Happy path: the hardening must not have gutted real extraction ---


def test_extract_iocs_pulls_real_indicators_from_a_realistic_report():
    report = {
        "triage": {
            "yara_matches": [{"rule": "MALWARE_Win_AsyncRAT"}],
            "ssdeep": "3072:abcdefghijklmnop:qrstuvwx",
        },
        "cape": {
            "network": {
                "dns_queries": [{"domain": "evil-c2.example", "answers": ["9.9.9.9"]}],
                "hosts": ["203.0.113.7"],
                "http_requests": [{"url": "http://evil-c2.example/gate.php", "method": "POST"}],
            },
            "mutex_iocs": [{"name": "Global\\AsyncMutex_6SI8OkPnk", "action": "created"}],
        },
    }
    iocs = extract_iocs(report)
    values = {i["value"] for i in iocs}
    assert "MALWARE_Win_AsyncRAT" in values
    assert "evil-c2.example" in values
    assert "203.0.113.7" in values
    assert "http://evil-c2.example/gate.php" in values
    assert "Global\\AsyncMutex_6SI8OkPnk" in values
    # And benign Windows noise is still filtered out.
    report["cape"]["network"]["dns_queries"].append({"domain": "time.windows.com"})
    assert "time.windows.com" not in {i["value"] for i in extract_iocs(report)}

    # Techniques still map from the extracted IOCs.
    techniques = map_iocs_to_techniques(report, iocs)
    assert any(t["technique_id"] == "T1071" for t in techniques)  # domain contacted
