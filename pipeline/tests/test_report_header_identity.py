# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The PDF header printed a dropped payload's hash as the sample's.

`render_header` read `ghidra.analyzed_files[0].sha256`. That list is built from
`find_pe_payloads(task_id)` — Cape's EXTRACTED payloads — and then from malfind
shellcode candidates; the original binary only lands there in the fallback
branch taken when no payload is readable.

So on any run that dropped a payload, the report labelled a dropped file's hash
"SHA256" while db_ingest stored the real one. The database and the PDF disagreed
about which sample the report described, and the PDF is the artifact that leaves
the platform — the one an analyst forwards, cites in a ticket, or hands to
someone who will look the hash up.

`sample_sha256()` resolves in the same order `ingest_to_db` uses, so the two
cannot drift apart again, and returns "unknown" rather than borrowing a
plausible-looking hash from somewhere else.
"""
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"


def _load_generate_report():
    """Import generate-report.py, whose dash means it needs a manual load.

    markdown and weasyprint are container runtime dependencies, not test ones —
    the PDF renderer is never exercised here, only the header's hash resolution
    — so they are stubbed rather than added to pipeline[test]. Same approach the
    api tests take with sqlalchemy/sqlmodel. Stubs are removed afterwards: a
    leaked one is visible to every module pytest collects later.
    """
    stubbed = {}
    for name in ("markdown", "weasyprint"):
        if name not in sys.modules:
            stub = types.ModuleType(name)
            stub.markdown = lambda text, **kw: text          # markdown.markdown
            stub.CSS = stub.HTML = lambda *a, **kw: None     # weasyprint.CSS/HTML
            sys.modules[name] = stub
            stubbed[name] = True
    try:
        spec = importlib.util.spec_from_file_location(
            "_generate_report_under_test", FILES / "generate-report.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for name in stubbed:
            sys.modules.pop(name, None)


PAYLOAD_SHA = "a" * 64
SAMPLE_SHA = "b" * 64


def test_the_header_hash_is_the_samples_not_the_first_analyzed_file():
    """THE bug. analyzed_files[0] is a Cape-extracted payload on any run that
    dropped one."""
    mod = _load_generate_report()
    report = {
        "sample_name": "invoice.exe",
        "triage": {"hashes": {"sha256": SAMPLE_SHA}},
        "ghidra": {"analyzed_files": [{"sha256": PAYLOAD_SHA}]},
    }
    assert mod.sample_sha256(report) == SAMPLE_SHA
    assert PAYLOAD_SHA not in mod.render_header(report), (
        "the PDF header still prints a dropped payload's hash as the sample's")


def test_the_header_agrees_with_what_db_ingest_stores():
    """The two disagreeing is the actual harm — one sample, two hashes, in the
    database and in the artifact that leaves the platform."""
    mod = _load_generate_report()
    # Same fallback chain as ingest_to_db: triage hash, then a <sha256>.ext name.
    assert mod.sample_sha256(
        {"sample_name": f"{SAMPLE_SHA}.exe", "triage": {}}) == SAMPLE_SHA
    assert mod.sample_sha256(
        {"sample_name": f"{SAMPLE_SHA.upper()}.bin", "triage": {}}) == SAMPLE_SHA


def test_an_unknown_hash_is_unknown_rather_than_borrowed():
    """With no triage hash and no hash-shaped filename, "unknown" is honest;
    reaching into analyzed_files for something plausible is what caused this."""
    mod = _load_generate_report()
    report = {"sample_name": "invoice.exe", "triage": {},
              "ghidra": {"analyzed_files": [{"sha256": PAYLOAD_SHA}]}}
    assert mod.sample_sha256(report) == "unknown"
