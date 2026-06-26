# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Characterization + unit tests for the extracted correlation helpers.

Baseline captured by running pipeline/tests/_throwaway_capture.py against
pipeline/tests/fixtures/sample_report.json using verbatim copies of the four
functions from run-pipeline.py.j2:175-691 BEFORE extraction. If any
characterization assertion fails, the extraction diverged — fix the
extraction, NEVER change the expected value to match.
"""

import json
from pathlib import Path

from lamware_pipeline.correlation import (
    build_mitre_mapping,
    calculate_severity,
    cross_correlate,
    determine_family,
)

_REPORT = json.loads((Path(__file__).parent / "fixtures" / "sample_report.json").read_text())

# ---------------------------------------------------------------------------
# Captured baseline (from throwaway_capture.py run 2026-06-21)
# ---------------------------------------------------------------------------

EXPECTED_FAMILY = 'sliver'
EXPECTED_SEVERITY = 'critical'
EXPECTED_MITRE = [
    {'id': 'T1055', 'source_signature': 'injection_process', 'sources': ['Cape', 'AI Reverse Engineering']},
    {'id': 'T1071', 'source_signature': 'network_cnc_http', 'sources': ['Cape']},
    {'id': 'T1082', 'name': 'System Information Discovery', 'sources': ['AI Reverse Engineering']},
]
# Updated 2026-06-25: rule_injection_corroborated (new) fires on this fixture —
# Cape flagged injection into PID 1234 and Volatility malfind found a region in
# PID 1234. This is an INTENTIONAL new detection (see
# docs/superpowers/specs/2026-06-25-correlation-rule-registry-design.md), NOT
# extraction drift. The "never change the expected value to match" rule guards
# against masking extraction divergence, which this is not.
EXPECTED_CORRELATIONS = [
    {
        "type": "injection_corroborated",
        "severity": "medium",
        "title": "Process injection into PID 1234 corroborated in memory",
        "detail": "Cape flagged injection into PID 1234; Volatility malfind found 1 anomalous executable region(s) in that process.",
        "pid": 1234,
        "sources": ["Cape", "Volatility"],
        "mitre": "T1055 — Process Injection",
    }
]


# ---------------------------------------------------------------------------
# Characterization tests — pin behavior of the extraction to the baseline
# ---------------------------------------------------------------------------

def _fresh_report() -> dict:
    """Return a fresh copy of the fixture so side effects (e.g. _family_source) don't leak."""
    return json.loads((Path(__file__).parent / "fixtures" / "sample_report.json").read_text())


def test_determine_family_matches_baseline():
    assert determine_family(_fresh_report()) == EXPECTED_FAMILY


def test_calculate_severity_matches_baseline():
    assert calculate_severity(_fresh_report()) == EXPECTED_SEVERITY


def test_build_mitre_mapping_matches_baseline():
    assert build_mitre_mapping(_fresh_report()) == EXPECTED_MITRE


def test_cross_correlate_matches_baseline():
    assert cross_correlate(_fresh_report()) == EXPECTED_CORRELATIONS


# ---------------------------------------------------------------------------
# Safety / contract tests — independent of the fixture
# ---------------------------------------------------------------------------

def test_cross_correlate_empty_report_is_safe():
    assert isinstance(cross_correlate({}), list)


def test_determine_family_empty_report_returns_unknown():
    result = determine_family({})
    assert result == "unknown"


def test_calculate_severity_empty_report_returns_low():
    result = calculate_severity({})
    assert result == "low"


def test_build_mitre_mapping_empty_report_returns_list():
    result = build_mitre_mapping({})
    assert isinstance(result, list)
    assert result == []
