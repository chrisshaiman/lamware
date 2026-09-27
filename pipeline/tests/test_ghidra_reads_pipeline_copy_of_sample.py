# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Ghidra must analyse the submitted sample even when CAPE's copy is unreadable (#644).

#393 — the fix for #392, samples readable by every local account — made every
file under /opt/CAPEv2/storage/binaries `640 cape:cape`. The pipeline user is in
`lamware`, not `cape`, so from 2026-08-15 it could not read CAPE's copy of any
sample. `get_original_sample_path` swallowed the PermissionError, returned None,
and the stage reported "no PE files found" in zero seconds:

    before 2026-08-15   367 of 991 analyses analysed the original (37%)
    after  2026-08-15     2 of 106                                  (1.9%)

It hid for six weeks because the TRIGGER already fell back to the pipeline's own
copy — so Ghidra was started — while EXECUTION did not, so it found nothing.

These tests make CAPE's copy genuinely unreadable (mode 000) rather than mocking
the exception, so they exercise the same failure the host produced. They skip as
root, where mode 000 does not stop a read.
"""
import hashlib
import os
from pathlib import Path

import pytest
from stages import ghidra
from stages.ghidra import resolve_original_sample, run_ghidra, should_run_ghidra

PE = b"MZ" + b"\x90" * 510

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores mode 000")


def _storage(tmp_path: Path, content: bytes, readable: bool, task: int = 1262):
    """A CAPE storage tree: analyses/<task>/binary -> binaries/<sha256>."""
    sha = hashlib.sha256(content).hexdigest()
    root = tmp_path / "storage"
    (root / "binaries").mkdir(parents=True)
    stored = root / "binaries" / sha
    stored.write_bytes(content)
    if not readable:
        stored.chmod(0)
    (root / str(task)).mkdir()
    (root / str(task) / "binary").symlink_to(stored)
    return root


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "pipeline-copy.bin"
    p.write_bytes(PE)
    return p


CAPE = {"id": 1262, "status": "reported"}


def test_a_readable_cape_copy_is_still_preferred(tmp_path, sample):
    storage = _storage(tmp_path, PE, readable=True)
    path, source, note = resolve_original_sample(CAPE, sample, storage)
    assert source == "cape_storage" and note is None


def test_an_unreadable_cape_copy_falls_back_to_the_pipeline_copy(tmp_path, sample):
    """The #644 condition exactly."""
    storage = _storage(tmp_path, PE, readable=False)
    path, source, note = resolve_original_sample(CAPE, sample, storage)
    assert path == sample
    assert source == "pipeline_copy"
    assert "#644" in note and "sha256 matches" in note


def test_a_different_file_is_refused_not_analysed_as_the_sample(tmp_path, sample):
    """The fallback must not analyse the WRONG binary under the right name. Identity
    is checked without read access: CAPE names its copy by sha256."""
    storage = _storage(tmp_path, PE + b"-a-different-sample", readable=False)
    path, source, note = resolve_original_sample(CAPE, sample, storage)
    assert path is None and source == "none"
    assert "DIFFERENT file" in note


@pytest.fixture
def no_real_ghidra(monkeypatch):
    """Record which files run_ghidra would hand to Ghidra, without running it."""
    seen = []

    def fake(pe_path, output_dir, ghidra_cmd):
        seen.append(Path(pe_path))
        return {"analysis_success": True, "functions_count": 336,
                "program_name": Path(pe_path).name, "project_dir": str(output_dir)}

    monkeypatch.setattr(ghidra, "run_ghidra_on_file", fake)
    return seen


def test_run_ghidra_analyses_the_original_instead_of_reporting_none(
        tmp_path, sample, no_real_ghidra):
    """End to end through run_ghidra: this returned "no PE files found" before."""
    storage = _storage(tmp_path, PE, readable=False)
    out = run_ghidra(CAPE, tmp_path / "out", sample, "ghidra",
                     get_cape_signatures_fn=lambda d: [], storage=storage)
    assert out.get("error") != "no PE files found", out
    assert out.get("trigger_reason") == "original_sample_is_pe", out
    assert out.get("original_sample_source") == "pipeline_copy"
    assert no_real_ghidra == [sample], "Ghidra was not handed the pipeline's copy"


def test_a_refused_fallback_names_itself_rather_than_claiming_no_pe(
        tmp_path, sample, no_real_ghidra):
    """"no PE files found" is a claim about the sample. A refused fallback is a claim
    about us, and saying the first when the second is true is how #644 hid."""
    storage = _storage(tmp_path, PE + b"-other", readable=False)
    out = run_ghidra(CAPE, tmp_path / "out", sample, "ghidra",
                     get_cape_signatures_fn=lambda d: [], storage=storage)
    assert out.get("error") == "original sample unusable", out
    assert "DIFFERENT file" in out.get("original_sample_note", "")


def test_trigger_and_execution_agree(tmp_path, sample, no_real_ghidra, monkeypatch):
    """The defect's shape: should_run_ghidra said yes, run_ghidra found nothing.
    Whatever the trigger decides about the original, execution must act on."""
    storage = _storage(tmp_path, PE, readable=False)
    fake_cmd = tmp_path / "ghidra"
    fake_cmd.write_text("")
    triggered = should_run_ghidra(CAPE, sample, ghidra_cmd=str(fake_cmd),
                                  get_cape_signatures_fn=lambda d: [], storage=storage)
    out = run_ghidra(CAPE, tmp_path / "out", sample, str(fake_cmd),
                     get_cape_signatures_fn=lambda d: [], storage=storage)
    assert triggered is True
    assert out.get("analyzed_files") is not None and no_real_ghidra, (
        "triggered, then analysed nothing — the #644 divergence")


def test_genuinely_no_sample_still_reports_no_pe(tmp_path, no_real_ghidra):
    """The honest "no PE files found" must survive for the case where it is true."""
    storage = _storage(tmp_path, PE, readable=False)
    txt = tmp_path / "notes.txt"
    txt.write_text("not a binary")
    out = run_ghidra(CAPE, tmp_path / "out", txt, "ghidra",
                     get_cape_signatures_fn=lambda d: [], storage=storage)
    assert out.get("error") == "no PE files found"
