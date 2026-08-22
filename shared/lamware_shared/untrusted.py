# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Canonical untrusted-content fencing — the shared source of truth.

The system prompts on both agent loops tell the model that anything between
`---UNTRUSTED_DATA---` markers came from a malicious binary and must never be
followed as instructions. That framing has a corollary nobody states out loud:
content OUTSIDE the fence is, by the same rule, presented as trustworthy. So an
unfenced channel is not merely unprotected — it is affirmatively mislabelled.

GHSA-f5q8-v78c-mr55 #3 found exactly that in the pipeline's interpret loop: tool
results went in as bare `json.dumps(...)`, which in a deep agentic run is where most
sample-derived content arrives. It was fixed there and nowhere else. The
investigation agent had the same defect, still unfixed, while
`api/app/investigate/system_prompt.py` claimed parity with the pipeline's defence.

TWO COPIES EXIST, DELIBERATELY. `interpret-ghidra.py` is copied into its container as
a single file with only `requirements.txt` beside it — it cannot import this package.
So it keeps its own implementation, and `test_untrusted_shared_parity.py` asserts the
two do not drift. That is the cross-copy guard `tool_validators` was able to retire
when it reached one copy; here two copies are structural, so the guard is required.
"""
import re

# Matched loosely on purpose: hyphen count, surrounding whitespace and case all vary
# in a near-miss a model may still read as a closing marker.
#
# BOTH fence shapes, because the prompts use both. Most builders fence with the dash
# form, but the Office and PowerShell paths use the XML tag form
# (<UNTRUSTED_CODE> / </UNTRUSTED_CODE>). A dash-anchored pattern could not match the
# tag form even in principle, so those paths had no working defence at all.
DELIMITER_RE = re.compile(
    r"(?:-{2,}\s*|<\s*/?\s*)(?:END_)?UNTRUSTED_(?:DATA|CODE)(?:\s*-{2,}|\s*/?\s*>)",
    re.IGNORECASE)


def neutralize_delimiters(s: str) -> str:
    """Defuse fence markers embedded in untrusted content.

    Replaced rather than stripped: an analyst reading the transcript should see that
    the sample tried it, and silently deleting evidence of an injection attempt
    destroys the one artifact worth keeping.
    """
    return DELIMITER_RE.sub("[NEUTRALISED_DELIMITER]", s)


def wrap_untrusted(payload: str) -> str:
    """Fence a block of sample-derived text with the delimiters the prompts name.

    Neutralises markers inside the payload first — otherwise wrapping is theatre: the
    sample closes the fence on its first line and everything after it reads as
    trusted narration.
    """
    return ("---UNTRUSTED_DATA---\n"
            + neutralize_delimiters(payload)
            + "\n---END_UNTRUSTED_DATA---")
