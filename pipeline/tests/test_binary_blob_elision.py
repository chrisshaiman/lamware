# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Half the context was spent on hex byte arrays (#511).

Decompilers render static data they cannot express as source as long runs of raw
hex. Measured on warzonerat's real decompilation: TWO such runs held 46,557 of
the 100,041 stored characters — 46.5% — and one was 44,064 characters ending
exactly at the truncation point.

They also tokenize atrociously. Across that decompilation the chars/token ratio
degrades from 1.94 in the first 10KB to 1.47 by 100KB, entirely because of these
runs, so they cost far more of the 131,072-token window than their share of the
text. Raising the cap is not available: 100KB is already 68,152 tokens.

ELIDED, NOT REMOVED — three things depend on those bytes:

  * grounding scores the model's claims against this source, so a cited byte
    would read as FABRICATED (#503 is that defect in another guise)
  * `yara_suggestion` legitimately draws on byte sequences
  * a blob beginning 4D 5A 90 00 is an MZ header, and that is a finding

So the marker keeps size, offset and a prefix, and the tests below are mostly
about what must SURVIVE.
"""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = {
    "dotnet": ROOT / "ansible/roles/dotnet-analysis/templates/analyze-dotnet.py.j2",
    "java": ROOT / "ansible/roles/java-analysis/templates/analyze-java.py.j2",
}


def _load(name):
    """Exec the elision helper out of a container template."""
    src = TEMPLATES[name].read_text(encoding="utf-8")
    start = src.index("MIN_BLOB_BYTES")
    end = src.index("\n\n\n", src.index("def elide_binary_blobs"))
    ns = {"re": re}
    exec(compile(src[start:end], name, "exec"), ns)  # noqa: S102
    return ns["elide_binary_blobs"]


# The real shape, from warzonerat: ILSpy emits unsupported static data as
# `/* Not supported: data(79 CA BF ...) */`.
BLOB = " ".join(["79", "CA", "BF", "F9", "C3", "07", "02", "C9"] * 40)
REAL = ("\tinternal static _60DAC5B51EEC4947_ _3D38D3E604414752_"
        "/* Not supported: data(" + BLOB + ") */;\n")


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_a_long_blob_is_replaced_by_a_summary(lang):
    out, elided = _load(lang)(REAL, "//")
    assert elided > 900, elided
    assert "binary blob elided" in out
    assert len(out) < len(REAL) / 4


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_the_marker_keeps_what_is_diagnostic(lang):
    """Size, offset and the opening bytes. An MZ header must survive, because
    'this blob is a PE' is the finding a reader wants."""
    mz = "4D 5A 90 00 03 00 00 00 " + " ".join(["41"] * 200)
    out, _ = _load(lang)(mz, "//")
    assert "4D 5A 90 00" in out, "the MZ header was elided away"
    assert "208 bytes" in out, out
    assert "offset 0" in out


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_short_arrays_are_left_alone(lang):
    """`byte[] { 0x01, 0x02, 0x03 }` in real code is logic, not noise. Eliding
    it would hide the thing a reader came for."""
    code = "byte[] key = { 0x01, 0x02, 0x03, 0x04 };\nvoid Run() { Inject(); }"
    out, elided = _load(lang)(code, "//")
    assert elided == 0
    assert out == code


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_surrounding_code_survives_intact(lang):
    """The elision must not swallow the declaration it is attached to — that is
    where the type and field name live."""
    out, _ = _load(lang)(REAL, "//")
    assert "_3D38D3E604414752_" in out
    assert "internal static" in out


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_a_source_with_no_blobs_is_returned_unchanged(lang):
    """Positive control: the helper is not unconditionally destructive."""
    code = "public class A {\n  void B() { C(); }\n}\n"
    out, elided = _load(lang)(code, "//")
    assert out == code and elided == 0


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_several_blobs_are_each_summarised(lang):
    """warzonerat had two. Handling only the first would leave 44,064
    characters of the second in place."""
    src = REAL + "\nclass Between {}\n" + REAL
    out, _ = _load(lang)(src, "//")
    assert out.count("binary blob elided") == 2
    assert "class Between {}" in out


# --- ordering: elision must precede truncation, or it buys nothing ---


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_the_analyser_elides_before_it_truncates(lang):
    """The blobs are what FILLS the window. Truncating first and eliding after
    would summarise only what already fitted."""
    src = TEMPLATES[lang].read_text(encoding="utf-8")
    assert src.index("elide_binary_blobs(") < src.index("MAX_STORED_SOURCE]"), (
        f"{lang}: truncation happens before elision")


def test_dotnet_extracts_iocs_from_the_full_source_not_the_truncated_one():
    """`extract_strings_of_interest` used to run on the truncated text, so on a
    4.4MB assembly every URL and IP past 100,000 characters was silently lost.
    That is IOC loss, not context loss."""
    src = TEMPLATES["dotnet"].read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "main")
    body = ast.dump(fn)
    assert "extract_strings_of_interest" in body
    extract_at = src.index("extract_strings_of_interest(source)", src.index("def main"))
    truncate_at = src.index("MAX_STORED_SOURCE]", src.index("def main"))
    assert extract_at < truncate_at, "extraction still runs on truncated source"


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_the_analyser_reports_how_much_it_elided(lang):
    """A reduction nobody can see is indistinguishable from a decompiler that
    produced less — the same reason #507 propagates the true source size."""
    assert "blob_bytes_elided" in TEMPLATES[lang].read_text(encoding="utf-8")


@pytest.mark.parametrize("lang", ["dotnet", "java"])
def test_a_short_run_of_bare_hex_is_not_a_blob(lang):
    """Ten bytes is a constant, not a payload — and this is the ONLY assertion
    the threshold answers to.

    `test_short_arrays_are_left_alone` above cannot do it: the matcher requires
    bare hex pairs, and in `0x01` there is no word boundary before `01`, so an
    `0x`-prefixed array never matches at any threshold. That test passed
    unchanged with MIN_BLOB_BYTES dropped from 64 to 2 — insensitive to the
    number it looked like it was guarding.
    """
    code = "// checksum: AB CD EF 12 34 56 78 9A BC DE\nvoid Run() { Inject(); }"
    out, elided = _load(lang)(code, "//")
    assert elided == 0, "a ten-byte constant was treated as a payload"
    assert out == code
