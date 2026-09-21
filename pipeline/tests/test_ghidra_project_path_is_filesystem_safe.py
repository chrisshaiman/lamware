# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A shellcode project directory must be a directory, not a path fragment (#631).

`run_ghidra_shellcode` named each project after its candidate's base address:

    sc_output = output_dir / f"shellcode_{pid}_{str(base_addr).replace('0x','')}"

Volatility prints the string `"N/A"` for a VAD whose Start VPN it cannot
resolve, and `.get("start_vpn", default)` returns that string rather than the
default — the default only applies when the key is ABSENT. So the name became:

    shellcode_0_N/A

whose slash invents a directory level. The project was written somewhere no
consumer could reconstruct, and three of sixteen eval-corpus samples carried
such a path. Every agent tool call against them failed with

    realpath: .../shellcode_0_N/A/project: No such file or directory

which the eval scored as `tool_layer_broken` — correctly, but two months after
the fact.

An unparseable address is named `unknown` rather than coerced into something
address-shaped: a valid-but-wrong name would silently put two unrelated
candidates in one directory, which is worse than an honest collision on
`unknown`.
"""
import pytest
from stages.ghidra import _addr_token, _path_token


@pytest.mark.parametrize("raw", ["N/A", "n/a", "", "   ", None, "../../etc/passwd",
                                 "0x", "not-an-address", "12g4"])
def test_an_unusable_address_never_reaches_the_path(raw):
    """The whole defect in one assertion: no separator, ever."""
    tok = _addr_token(raw)
    assert "/" not in tok and "\\" not in tok
    assert tok == "unknown"


@pytest.mark.parametrize("raw,expected", [
    ("0x24cc1de0000", "24cc1de0000"),
    ("0X400000", "400000"),          # Cape and Volatility disagree on case
    ("400000", "400000"),            # already bare
    (4192, "4192"),                  # ints are pre-formatted by the caller
    ("0xDEADBEEF", "deadbeef"),      # one spelling per address, or two dirs
])
def test_a_real_address_is_preserved(raw, expected):
    assert _addr_token(raw) == expected


def test_two_spellings_of_one_address_give_one_directory():
    """`0xDEADBEEF` and `0xdeadbeef` are the same region. Two directories for it
    would split one candidate's artifacts across both."""
    assert _addr_token("0xDEADBEEF") == _addr_token("0xdeadbeef")


@pytest.mark.parametrize("raw", ["a/b", "..", "../x", "x\\y", "a b", "p:1"])
def test_other_path_components_are_sanitised(raw):
    tok = _path_token(raw)
    assert "/" not in tok and "\\" not in tok
    assert tok not in ("", ".", "..")


def test_a_normal_pid_is_untouched():
    assert _path_token(4192) == "4192"
    assert _path_token(0) == "0"


def test_the_caller_requires_a_pid_rather_than_defaulting():
    """A candidate with no pid is a programming error. Reading it with .get()
    would name the directory "None" and carry on — the silent-degradation shape
    this repo keeps finding."""
    import inspect

    from stages import ghidra
    src = inspect.getsource(ghidra.run_ghidra_shellcode)
    line = next(ln for ln in src.splitlines() if "sc_output" in ln and "=" in ln)
    # `.get("pid")` is correct elsewhere in this function — a missing pid should
    # be None in a RESULT dict. It is only the PATH that must not tolerate it.
    assert "candidate['pid']" in line or 'candidate["pid"]' in line, line
    assert ".get(" not in line.split("_addr_token")[0], line


@pytest.mark.parametrize("raw", ["400000\n", " 0x400000 ", "\t400000"])
def test_surrounding_whitespace_never_reaches_the_directory_name(raw):
    """Python's `$` matches before a trailing newline, so an unanchored
    validator would admit "400000\\n" as a path component. Guarded twice:
    the value is stripped, and the pattern is anchored with \\Z."""
    tok = _addr_token(raw)
    assert tok == "400000"
    assert tok == tok.strip() and "\n" not in tok
