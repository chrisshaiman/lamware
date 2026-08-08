# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""LLM output must not set the severity verdict (GHSA-f5q8-v78c-mr55, finding 1).

THREAT_MODEL.md §4.3/§5 justify accepting best-effort prompt-injection defence with:

    "LLM output never sets verdicts or triggers pipeline actions... a fully-deceived
     model corrupts a narrative, not a decision."

That was false. `calculate_severity()` scored model-produced fields directly:

    capability count                +5
    evasion self-reported confidence +15
    family, when model-derived      +10
    ------------------------------------
    total                           +30   against a `critical` threshold of 30

A sample whose decompiled strings reach the model's context could argue about its
own severity. **Deflation is the dangerous direction**: a real threat talked down to
`low` is the one nobody looks at twice.

The fix is dual scoring rather than deletion — the model's view is genuinely
informative, it just cannot be decisive. A large gap between the two bands is itself
a signal: the evidence and the model disagree, which is either a real find or an
injection attempt.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))

from lamware_pipeline.correlation import calculate_severity  # noqa: E402


def _maxed_llm_report(family_source="llm_interpretation") -> dict:
    """Every model-controlled input at its maximum, no programmatic evidence."""
    return {
        "cape": {"malscore": 0, "signatures": []},
        "family": "lockbit",
        "_family_source": family_source,
        "evasion_analysis": {"enabled": True, "analysis": {"confidence": "high"}},
        "llm_interpretation": {"analysis": {"capabilities": ["c"] * 12}},
    }


def test_llm_input_alone_cannot_raise_the_verdict():
    """THE security property. This exact report used to score 30 = `critical`."""
    report = _maxed_llm_report()
    assert calculate_severity(report) == "low", (
        f"model-controlled input alone reached {calculate_severity(report)!r}; "
        f"programmatic score was {report['_severity_score']}")
    assert report["_severity_score"] == 0


def test_the_evasion_hunter_counts_as_a_model_not_as_code():
    """Easy to miss: `evasion_analysis` is a run_interpret() call, so its family
    verdict and its `confidence` are both model output wearing a
    programmatic-looking key. The advisory that found this bug missed it."""
    report = _maxed_llm_report(family_source="evasion_analysis")
    assert calculate_severity(report) == "low"
    assert report["_severity_score"] == 0
    assert any("evasion_analysis" in i for i in report["_severity_llm_inputs"])


def test_a_programmatic_family_still_counts():
    """The fix must not disarm real evidence. A family from Cape signatures or a Go
    module is code-derived and load-bearing."""
    report = {
        "cape": {"malscore": 0, "signatures": []},
        "family": "sliver",
        "_family_source": "go_module",
    }
    calculate_severity(report)
    assert report["_severity_score"] == 10
    assert report["_severity_score_llm_context"] == 0


def test_programmatic_evidence_alone_still_reaches_critical():
    """Guards against over-correcting into a scorer that can never alarm."""
    report = {
        "cape": {
            "malscore": 8,
            "signatures": [{"severity": 3}] * 3,
            "injection_buffers": [{"x": 1}],
            "network": {"dns_queries": ["evil.test"]},
        },
        "family": "lockbit",
        "_family_source": "cape_signatures",
    }
    assert calculate_severity(report) == "critical"


def test_the_model_view_is_recorded_not_discarded():
    """Dual scoring, not deletion. An analyst should see what the model thought."""
    report = _maxed_llm_report()
    calculate_severity(report)
    assert report["_severity_score_llm_context"] == 30
    assert report["_severity_band_with_llm"] == "critical"
    assert report["_severity_llm_inputs"], "the contributing signals must be named"


def test_the_two_bands_can_disagree_and_both_are_visible():
    """The disagreement is the interesting datum — it is what an injection attempt
    looks like from the outside."""
    report = _maxed_llm_report()
    verdict = calculate_severity(report)
    assert verdict == "low"
    assert report["_severity_band_with_llm"] == "critical"
    assert verdict != report["_severity_band_with_llm"]


def test_deflation_is_covered_too():
    """The inverse attack: a genuinely bad sample whose model output says nothing.
    The verdict must still come from the evidence."""
    report = {
        "cape": {
            "malscore": 9,
            "signatures": [{"severity": 3}] * 2,
            "injection_buffers": [{"x": 1}],
        },
        "family": "unknown",
        "evasion_analysis": {"enabled": True, "analysis": {"confidence": "none"}},
        "llm_interpretation": {"analysis": {"capabilities": []}},
    }
    assert calculate_severity(report) == "critical", (
        "a silent model must not be able to suppress programmatic evidence")


def test_db_ingest_does_not_take_the_models_word_for_severity():
    """The second path by which model output became a decision: when the
    programmatic verdict was absent, db_ingest wrote `analysis.risk_assessment`
    straight into the severity column.

    Absent must stay absent — a missing verdict is a visible gap an analyst can act
    on; a model-supplied one is indistinguishable from a real one.
    """
    src = (ROOT / "ansible" / "roles" / "pipeline" / "files"
           / "db_ingest.py").read_text(encoding="utf-8")
    idx = src.index("severity = (report.get(")
    expr = src[idx:idx + 200]
    assert "risk_assessment" not in expr, (
        f"db_ingest still falls back to the model's risk_assessment: {expr!r}")
