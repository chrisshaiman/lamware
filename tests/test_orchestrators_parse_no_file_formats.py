# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The orchestrators import no file-format parser (ADR-021).

ADR-021: hostile files are interpreted only inside a sandbox. The pipeline and
the API may hash, peek at fixed-offset headers, read bounded byte ranges and
run fixed-pattern scans over bounded bytes; they never parse file formats and
never run model-supplied logic. The 2026-10-03 survey found exactly that —
every real parser (triage, CAPE, Volatility, Ghidra, ILSpy, PyInstaller,
Office, PowerShell, PCAP) runs in a container — and this test keeps it true.

STRUCTURAL, and deliberately so: no runtime observation can show an import is
ABSENT — a parser that is imported but rarely reached passes every behavioural
test until the sample that reaches it. So every .py under the orchestrators'
code is parsed with `ast` and its imports compared against a deny-list of
format-parsing libraries. `importlib.import_module("x")` and `__import__("x")`
with a literal name count as imports.

An import may be allowed only through ALLOWED below, with a written reason.
"""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: The orchestrators' code: the pipeline (stages, eval, helpers), its config
#: package, the shared package and the API.
SCOPES = (
    ROOT / "ansible" / "roles" / "pipeline" / "files",
    ROOT / "pipeline" / "lamware_pipeline",
    ROOT / "shared",
    ROOT / "api" / "app",
)

#: Top-level module names of libraries that parse (or decompress, or
#: disassemble) the formats hostile files arrive in. Any of these in an
#: orchestrator means sample bytes are being interpreted outside a sandbox.
DENY = {
    # executables and their metadata
    "pefile", "lief", "dnfile", "dotnetfile", "elftools", "macholib", "pyelftools",
    "capstone", "unicorn", "keystone", "r2pipe", "angr",
    # signatures over file contents (the triage container runs YARA)
    "yara", "yara_x", "magic",
    # documents
    "olefile", "oletools", "msoffcrypto", "extract_msg", "docx", "pptx", "openpyxl",
    "xlrd", "pdfminer", "PyPDF2", "pypdf", "fitz", "pdfplumber",
    # archives and compression
    "zipfile", "tarfile", "py7zr", "rarfile", "pyzipper", "libarchive", "zlib", "gzip",
    "bz2", "lzma", "zstandard", "lz4", "cabarchive",
    # network captures
    "scapy", "dpkt", "pyshark", "pcapy", "pcapkit",
    # Windows artefacts and memory
    "Evtx", "evtx", "Registry", "regipy", "volatility", "volatility3",
    # unsafe deserialisers: never on anything that came from a sample
    "pickle", "marshal", "shelve",
}

#: (path relative to ROOT, module) -> why it is acceptable. Empty on purpose:
#: the 2026-10-03 survey found no orchestrator import that needs one.
ALLOWED: dict[tuple[str, str], str] = {}


def _imports(tree: ast.AST) -> list[tuple[int, str]]:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(node.lineno, a.name.split(".")[0]) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.append((node.lineno, node.module.split(".")[0]))
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            f = node.func
            name = (f.attr if isinstance(f, ast.Attribute) else
                    f.id if isinstance(f, ast.Name) else None)
            if name in ("import_module", "__import__") and isinstance(node.args[0].value, str):
                found.append((node.lineno, node.args[0].value.split(".")[0]))
    return found


def _files() -> list[Path]:
    files = [p for scope in SCOPES for p in scope.rglob("*.py")
             if "tests" not in p.relative_to(scope).parts]
    assert len(files) > 50, f"the probe is broken: only {len(files)} files found"
    return files


def test_no_orchestrator_imports_a_file_format_parser():
    hits = []
    for path in _files():
        rel = str(path.relative_to(ROOT))
        for line, mod in _imports(ast.parse(path.read_text(encoding="utf-8"))):
            if mod in DENY and (rel, mod) not in ALLOWED:
                hits.append(f"{rel}:{line}  {mod}")
    assert not hits, (
        "an orchestrator imports a file-format parser; hostile files are interpreted "
        "only inside a sandbox (ADR-021):\n  " + "\n  ".join(hits))


def test_every_allowance_has_a_reason_and_still_exists():
    for (rel, mod), why in ALLOWED.items():
        assert len(why.split()) >= 8, f"{rel}: {mod} has no real reason"
        assert mod in DENY, f"{rel}: {mod} is allowed but not denied — remove it"
        assert mod in {m for _, m in _imports(ast.parse((ROOT / rel).read_text()))}, (
            f"{rel} no longer imports {mod}; remove the allowance")


@pytest.mark.parametrize("code,mod", [
    ("import pefile", "pefile"),
    ("from oletools.olevba import VBA_Parser", "oletools"),
    ("import zipfile as z", "zipfile"),
    ("import importlib\nimportlib.import_module('yara')", "yara"),
    ("__import__('lief')", "lief"),
    ("def f():\n    import tarfile", "tarfile"),
])
def test_the_probe_sees_every_import_form(code, mod):
    """Proves the guard can fail: each form a parser could arrive in is seen."""
    assert mod in {m for _, m in _imports(ast.parse(code))}
