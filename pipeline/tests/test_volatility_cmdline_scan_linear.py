# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Suspicious command lines are found in linear time on sample-written lines (#734).

Three of the volatility cmdline patterns had the `A.*B` shape that made
stages/powershell.py quadratic: the regex engine rescans the rest of the line
from every A. Measured 2026-10-15 on `"powershell " * n`: 0.012 s at 22k
characters, 0.051 s at 44k, 0.19 s at 88k (x4 per doubling). A process's
command line is capped at 32k characters, so this was slow rather than
unbounded; it is the same class. The replacement must flag the same lines.
"""
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible/roles/pipeline/files"))
from stages.volatility import extract_volatility_insights  # noqa: E402

BLOB = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAaABpACcA"   # 40 base64 characters

# The replaced patterns, kept here as the reference for what should be flagged.
OLD = {label: re.compile(label) for label in (
    r'certutil.*-decode', r'bitsadmin.*transfer', r'powershell.*-e\s+[A-Za-z0-9+/=]{20,}')}


def _hit(args: str) -> str | None:
    out = extract_volatility_insights({"cmdline": [{"PID": 7, "Process": "x.exe", "Args": args}]})
    hits = out.get("suspicious_cmdlines", [])
    return hits[0]["pattern"] if hits else None


@pytest.mark.parametrize("args", [
    f"powershell -e {BLOB}",
    f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nologo -e {BLOB}",
    f"-e {BLOB} then powershell -e {BLOB}",     # a blob after the executable, not the first one
    f"-e {BLOB} powershell",                    # the blob before the executable: not flagged
    "powershell -e short",
    f"notepad -e {BLOB}",
    "certutil -urlcache -f http://x/y z && certutil -decode z w",
    "certutil -decode z w",
    "-decode z w certutil",
    "bitsadmin /transfer job http://x/y c:\\z",
    "bitsadmin /create job",
])
def test_flags_the_same_lines_as_the_regexes(args):
    # None of these trip the plain patterns tried first, so the hit, if any,
    # is attributable to the sequence check.
    want = next((label for label, rx in OLD.items() if rx.search(args.lower())), None)
    assert _hit(args) == want


@pytest.mark.parametrize("word", ["powershell ", "certutil ", "bitsadmin "])
def test_a_hostile_command_line_is_linear(word):
    """The shape that made the regexes quadratic: A repeated, each occurrence a
    fresh start for `.*` to scan to the end of the line. ~100k characters, three
    times a real command line's cap; the old patterns took 0.3-0.56 s here,
    0.03-0.06 s at the cap."""
    hostile = word * 10000
    t0 = time.perf_counter()
    assert _hit(hostile) is None
    assert time.perf_counter() - t0 < 0.1
