# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Encoded PowerShell is found in linear time on sample-controlled command lines (#734).

The regex this replaces took 1.2 s on a 32k-character command line and grew with
the square of its length; the sample controls the command line. The scan must
find what that regex found on real shapes, and stay fast on the hostile one.
"""
import base64
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible/roles/pipeline/files"))
from stages.powershell import encoded_command_blob  # noqa: E402

BLOB = base64.b64encode("Write-Host 'hi'; IEX (New-Object Net.WebClient)".encode("utf-16-le")).decode()

# The replaced pattern, kept here as the reference for what should match.
OLD = re.compile(
    r'(?:powershell|pwsh)(?:\.exe)?\s+.*?'
    r'-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm'
    r'|encodedcomma|encodedcomman|encodedcommand)\s+([A-Za-z0-9+/=]{20,})',
    re.IGNORECASE)


@pytest.mark.parametrize("cmdline", [
    f"powershell.exe -nop -w hidden -enc {BLOB}",
    f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -EncodedCommand {BLOB}",
    f"PowerShell -ExecutionPolicy Bypass -ENCODEDC {BLOB}",
    f"cmd.exe /c powershell -windowstyle hidden -en {BLOB} && exit",
    "powershell -enc short",
    "powershell -Command Get-Process",
    f"notepad.exe -enc {BLOB}",
])
def test_finds_what_the_regex_found(cmdline):
    want = OLD.search(cmdline)
    got = encoded_command_blob(cmdline)
    assert got == (want.group(1) if want else None)


@pytest.mark.parametrize("cmdline", [
    # A quoted executable path, the normal form when it contains a space: the
    # regex wanted whitespace straight after `pwsh.exe` and saw a quote.
    f'"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoProfile -e {BLOB}',
    # A quoted blob: the regex wanted the base64 straight after the whitespace.
    f"powershell -enc '{BLOB}'",
])
def test_finds_the_quoted_forms_the_regex_missed(cmdline):
    assert OLD.search(cmdline) is None
    assert encoded_command_blob(cmdline) == BLOB


def test_a_hostile_command_line_is_linear():
    """The shape that made the regex quadratic: the executable name repeated,
    each occurrence a fresh start for `.*?` to scan to the end of the line.
    Measured 2026-10-14: the regex took 0.06 s at 10k characters and 0.25 s at
    20k (x4 per doubling, ~6 s at this 100k); the scan takes under a millisecond."""
    hostile = "pwsh " * 20000                           # 100k characters
    t0 = time.perf_counter()
    assert encoded_command_blob(hostile) is None
    assert time.perf_counter() - t0 < 0.1
