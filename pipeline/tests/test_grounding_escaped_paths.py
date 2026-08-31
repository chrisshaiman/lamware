# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
r"""A path quoted verbatim from the evidence scored FABRICATED.

`run_arm` builds the grounding source with `json.dumps`, which doubles every
backslash. A claim arrives as an ordinary string with single ones. So a Windows
path present verbatim in the source could never match it:

    claim   C:\Windows\System32\config\systemprofile\...\ffmpeg.dll
    source  C:\\Windows\\System32\\config\\systemprofile\\...\\ffmpeg.dll

Found in the #420 stage-2 output. The `+corr` arm on `unclassified_25d18a2b`
was flagged for fabricating a dropped-file path that its own correlation
evidence states in full, and the base arm on `cobaltstrikebeacon` was flagged
for a `%PATH%` string out of the same source.

It biases hardest against whichever arm sees the most paths, which is the
evidence-fed one — so the metric leaned against the exact thing the experiment
was measuring. Both fabrications in that run were phantoms.
"""
import json

import pytest
from grounding_check import grounding_scorecard, normalize

REAL_PATH = (r"C:\Windows\System32\config\systemprofile\AppData\Local"
             r"\UltraSuiteSmartCoreware\ffmpeg.dll")


def _analysis(*values):
    return {"code_level_iocs": [{"value": v, "type": "path", "context": "c"}
                                for v in values]}


def test_a_path_quoted_from_json_evidence_is_not_a_fabrication():
    """THE bug, end to end through the scorer."""
    source = json.dumps({"cross_correlations": [
        {"detail": f"Cape observed this file being written to {REAL_PATH}."}]})
    g = grounding_scorecard(_analysis(REAL_PATH), source)
    assert g["fabricated"] == [], g["fabricated"]
    assert g["grounded"] == 1


def test_the_base_arms_phantom_reproduces_too():
    """The same defect flagged a %PATH% string in the base arm."""
    env = (r"C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell"
           r"\v1.0\;C:\WINDOWS\System32\OpenSSH\;")
    g = grounding_scorecard(_analysis(env), json.dumps({"cmdline": env}))
    assert g["fabricated"] == [], g["fabricated"]


def test_a_path_genuinely_absent_is_still_a_fabrication():
    """The fix must not turn the checker into one that always agrees. This is
    the assertion that keeps it a check."""
    source = json.dumps({"detail": r"C:\Windows\System32\kernel32.dll"})
    g = grounding_scorecard(_analysis(r"C:\Users\victim\evil.exe"), source)
    assert g["fabricated"], "an unsupported path must still be flagged"
    assert g["grounded"] == 0


@pytest.mark.parametrize("claim,source,expected", [
    # single vs doubled, both directions
    (r"C:\a\b.dll", r"C:\\a\\b.dll", True),
    (r"C:\\a\\b.dll", r"C:\a\b.dll", True),
    (r"C:\a\b.dll", r"C:\a\b.dll", True),
    # a UNC path normalises like any other; both sides collapse alike
    (r"\\server\share\x.dll", r"\\\\server\\share\\x.dll", True),
    # and something genuinely different still does not match
    (r"C:\a\b.dll", r"C:\a\c.dll", False),
])
def test_backslash_runs_compare_equal_in_either_direction(claim, source, expected):
    assert (normalize(claim) in normalize(source)) is expected


def test_normalize_still_does_its_other_jobs():
    """Collapsing backslashes must not disturb refanging, lowercasing or
    whitespace — the behaviours other callers depend on."""
    assert normalize("evil[.]com") == "evil.com"
    assert normalize("  Hello   World ") == "hello world"
    assert normalize("hxxp://a[.]b") == "http://a.b"


def test_a_hex_claim_is_unaffected():
    """Hex re-spelling has its own path through the checker (#410); the
    backslash collapse must not interfere with it."""
    g = grounding_scorecard(_analysis("0x100557a4"),
                            json.dumps({"pseudocode": "DAT_100557a4"}))
    assert g["fabricated"] == []
