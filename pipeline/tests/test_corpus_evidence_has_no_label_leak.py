# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A sample's own family name must not appear in its evidence (#634).

`mb_family` is the held-out label. When it appears inside the evidence an arm
is shown, that arm has been handed the answer — and a model told the family can
recall that family's known TTPs from training instead of deriving them from the
binary. Technique recall (#491) is scored against exactly that held-out key.

This is invisible to every existing defence. The grounding check compares claims
against the evidence, and the leaked name really IS in the evidence, so a claim
citing it is correctly scored as grounded. `warmcookie` returned the only
perfect recall in the first #630 batch, on the sample whose label sat in its own
command lines.

ADR-019 already says family_guess is a CONTAMINATION PROBE rather than a
capability metric. This test is that probe made executable: a correct family
guess should be treated as a leak until proven otherwise.

The check runs against whatever corpus is deployed; where none is (CI), it
skips rather than passing vacuously.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = sorted((ROOT / "ansible" / "roles" / "pipeline" / "files" / "eval").glob("*.json"))

# Words that are not attribution: a family token has to be discriminative.
_NOT_A_FAMILY = {"unclassified", "unknown", "trojan", "generic", "malware"}


def _samples(manifest: Path):
    data = json.loads(manifest.read_text())
    return data.get("samples", data) if isinstance(data, dict) else data


def _evidence_text(report: dict) -> str:
    """Everything the correlated arm is shown, as one lowercase blob."""
    sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))
    from lamware_eval.runner import correlated_evidence
    return json.dumps(correlated_evidence(report)).lower()


def test_there_are_manifests_to_check():
    assert MANIFESTS, "no corpus manifests found — this file would vacuously pass"


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_no_sample_leaks_its_family_into_behavioural_evidence(manifest):
    checked, leaks = 0, []
    for s in _samples(manifest):
        family = (s.get("mb_family") or "").strip().lower()
        if not family or family in _NOT_A_FAMILY:
            continue
        report_path = Path(s["corpus_dir"]) / "report.json"
        if not report_path.exists():
            continue
        checked += 1
        if family in _evidence_text(json.loads(report_path.read_text())):
            leaks.append(f"{Path(s['corpus_dir']).name} leaks {family!r}")
    if checked == 0:
        pytest.skip(f"{manifest.name}: corpus not deployed here")
    assert not leaks, (
        "held-out label present in the evidence an arm is shown; technique "
        "recall on these samples is not trustworthy:\n  " + "\n  ".join(leaks))
