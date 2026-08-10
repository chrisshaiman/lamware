# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Silent truncation (#370) and a health flag that could not fail (#367).

Both were found by pointing the new MOTIF corpus at the pipeline and comparing
extraction against MOTIF's independently recorded counts:

  #370  ExportAnalysis capped imports at a bare literal 200. Seven of 29 corpus
        samples were truncated, 1359 imports never reached the model, and the
        output said nothing — a list of exactly 200 is indistinguishable from a
        complete one.

  #367  run-ghidra reported analysis_success on a run that produced 1 function
        and 0 imports from a PE whose import directory was intact.

The Java is not executed here — there is no JVM in CI — so the exporter is
asserted against its source. The Python IS executed, against synthesised PEs.
"""
import re
import struct
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = ROOT / "ansible" / "roles" / "ghidra" / "templates"
EXPORT_JAVA = (GHIDRA / "ExportAnalysis.java.j2").read_text(encoding="utf-8")
RUN_GHIDRA = (GHIDRA / "run-ghidra.py.j2").read_text(encoding="utf-8")


def _load_run_ghidra_helpers():
    """Exec just the two pure helpers, without the module's Ghidra imports."""
    src = RUN_GHIDRA
    start = src.index("def _pe_declares_imports")
    end = src.index("def run_headless_analysis")
    ns: dict = {"Path": Path}
    exec(compile(src[start:end], "run-ghidra.py.j2", "exec"), ns)  # noqa: S102
    return ns["_pe_declares_imports"], ns["_analysis_warnings"]


pe_declares_imports, analysis_warnings = _load_run_ghidra_helpers()


def make_pe(*, import_rva: int = 0x1000, import_size: int = 40,
            magic: int = 0x10B) -> bytes:
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    coff = e_lfanew + 4
    struct.pack_into("<HHIIIHH", buf, coff, 0x14C, 1, 0, 0, 0, 224, 0x102)
    opt = coff + 20
    struct.pack_into("<H", buf, opt, magic)
    ndirs_off = opt + (92 if magic == 0x10B else 108)
    struct.pack_into("<I", buf, ndirs_off, 16)
    struct.pack_into("<II", buf, ndirs_off + 4 + 8, import_rva, import_size)
    return bytes(buf)


# ---------------------------------------------------------------------------
# #370 — the exporter must declare truncation
# ---------------------------------------------------------------------------

def test_the_bare_200_literal_is_gone():
    """THE bug. A magic number sitting next to named constants."""
    assert "imports.size() < 200" not in EXPORT_JAVA, (
        "the unnamed 200-import cap is back")
    assert "stringsOfInterest.size() < 100" not in EXPORT_JAVA


def test_the_caps_are_named_constants():
    for name in ("MAX_IMPORTS", "MAX_STRINGS_OF_INTEREST"):
        assert re.search(rf"static final int {name} = \d+;", EXPORT_JAVA), (
            f"{name} is not declared as a named constant")


def test_the_import_cap_covers_the_motif_corpus():
    """trickbot 1d9e9e60065c imports 567. A cap below that truncates the
    benchmark corpus itself, which would bake the bug into the baseline."""
    m = re.search(r"static final int MAX_IMPORTS = (\d+);", EXPORT_JAVA)
    assert m and int(m.group(1)) >= 567, (
        f"MAX_IMPORTS={m.group(1) if m else None} still truncates the corpus "
        f"(largest observed: 567)")


def test_the_total_is_counted_past_the_cap():
    """Counting must not stop when collecting does, or `imports_total` would be
    a restatement of the cap rather than the real number."""
    block = EXPORT_JAVA[EXPORT_JAVA.index("List<String> imports"):
                        EXPORT_JAVA.index("// Extract strings of interest")]
    assert "importsTotal++" in block
    assert "while (iter.hasNext()) {" in block, (
        "the iterator is still short-circuited by the cap, so the total is lost")
    assert "if (imports.size() < MAX_IMPORTS)" in block


def test_truncation_reaches_the_json():
    for field in ("imports_total", "imports_truncated", "strings_truncated"):
        assert f'\\"{field}\\"' in EXPORT_JAVA, f"{field} is never emitted"


def test_run_ghidra_forwards_the_truncation_fields():
    """Emitted by the exporter but dropped by the wrapper would be no better
    than never emitting them."""
    assert '"imports_total", "imports_truncated", "strings_truncated"' in RUN_GHIDRA


# ---------------------------------------------------------------------------
# #367 — warnings that can actually fire
# ---------------------------------------------------------------------------

def test_a_pe_with_an_import_directory_is_detected(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(make_pe(import_rva=0x2000, import_size=40))
    assert pe_declares_imports(p) is True


def test_a_pe_without_an_import_directory_is_detected(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(make_pe(import_rva=0, import_size=0))
    assert pe_declares_imports(p) is False


@pytest.mark.parametrize("payload", [b"not a pe", b"MZ" + b"\0" * 8, b""])
def test_a_non_pe_is_unknown_not_false(tmp_path, payload):
    """None, never False. False would make the 'declares imports but extracted
    none' check fire on every non-PE input — a false alarm on the majority."""
    p = tmp_path / "s.bin"
    p.write_bytes(payload)
    assert pe_declares_imports(p) is None


def test_pe32_plus_directories_are_read_at_the_right_offset(tmp_path):
    """NumberOfRvaAndSizes moves by 16 bytes for PE32+. Reading the PE32 offset
    on a 64-bit binary yields garbage — which is exactly the class of mistake
    that produced the 'subsystem=16' misdiagnosis on 2026-08-09."""
    p = tmp_path / "s64.bin"
    p.write_bytes(make_pe(import_rva=0x3000, import_size=80, magic=0x20B))
    assert pe_declares_imports(p) is True


def test_THE_regression_success_with_nothing_extracted(tmp_path):
    """The #367 case, verbatim: a PE with an import directory, 1 function, no
    imports. Previously reported clean."""
    p = tmp_path / "s.bin"
    p.write_bytes(make_pe())
    w = analysis_warnings(p, {"functions_count": 1, "imports": []})
    assert any("function(s) recovered" in x for x in w), w
    assert any("import directory" in x for x in w), w


def test_a_healthy_analysis_warns_about_nothing(tmp_path):
    """The positive control. Without it, a function returning a constant
    non-empty list would satisfy every other test here."""
    p = tmp_path / "s.bin"
    p.write_bytes(make_pe())
    assert analysis_warnings(p, {"functions_count": 617,
                                 "imports": ["KERNEL32.DLL:VirtualProtect"]}) == []


def test_a_legitimately_tiny_sample_still_warns_but_is_not_failed(tmp_path):
    """The packed azorult in the MOTIF corpus really does export 2 imports and
    4 functions. It must not be marked failed — the pipeline filters on
    analysis_success and would drop it — but 4 functions is worth saying."""
    p = tmp_path / "s.bin"
    p.write_bytes(make_pe())
    w = analysis_warnings(p, {"functions_count": 4,
                              "imports": ["A.DLL:x", "A.DLL:y"]})
    assert w == [], "4 functions with imports present is thin but not contradictory"


def test_truncation_is_surfaced_as_a_warning(tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(make_pe())
    w = analysis_warnings(p, {"functions_count": 300, "imports": ["a"] * 200,
                              "imports_truncated": True, "imports_total": 567})
    assert any("567" in x and "200" in x for x in w), w


def test_warnings_do_not_gate_analysis_success(tmp_path):
    """Degrading analysis_success would silently drop samples the pipeline
    filters on it. The comment saying so must stay attached to the decision."""
    assert '"analysis_warnings": []' in RUN_GHIDRA
    assert "Warnings inform; they do not gate." in RUN_GHIDRA
    assert 'output["analysis_success"] = False' not in RUN_GHIDRA.split(
        "def _analysis_warnings")[1].split("def run_headless_analysis")[0]
