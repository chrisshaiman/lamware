# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The submitted sample reaches Ghidra even when CAPE saw a dropped PE (#649).

``run_ghidra`` used to analyse the original only when CAPE extracted *no*
dropped PEs. On the host, all 32 analyses recorded as
``trigger_reason: dropped_pe_with_signatures`` (2026-08-19 to 2026-10-02) have
no analysed file whose sha256 is the submitted sample's: for a dropper or a
stager the RE agent saw what was dropped and never the code that dropped it.

These tests call ``run_ghidra`` with ``run_ghidra_on_file`` stubbed, so they
observe which bytes would be handed to Ghidra, in what order, and into which
project directory.
"""
import hashlib
from pathlib import Path

import pytest
from stages import ghidra

ORIGINAL = b"MZ" + b"\x4f" * 700


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def pe_loader(monkeypatch):
    """Record (bytes, output_dir) for every file handed to the PE loader."""
    seen: list[tuple[bytes, Path]] = []

    def fake(pe_path, output_dir, ghidra_cmd):
        data = Path(pe_path).read_bytes()
        seen.append((data, Path(output_dir)))
        return {"analysis_success": True, "functions_count": 10,
                "program_name": Path(pe_path).name, "sha256": _sha(data),
                "project_dir": "/output/project", "host_output_dir": str(output_dir)}

    monkeypatch.setattr(ghidra, "run_ghidra_on_file", fake)
    monkeypatch.setattr(ghidra, "make_ghidra_verifier", lambda _c: (lambda *_a: None))
    return seen


def _setup(tmp_path, monkeypatch, dropped: list[bytes], original: bytes | None = ORIGINAL,
           source: str = "cape_storage", note: str | None = None):
    paths = []
    for i, data in enumerate(dropped):
        p = tmp_path / f"dropped{i}.exe"
        p.write_bytes(data)
        paths.append(p)
    monkeypatch.setattr(ghidra, "discover_pe_files", lambda *_a, **_k: (paths, None))
    sample = tmp_path / "sample.bin"
    if original is not None:
        sample.write_bytes(original)
        resolved = (sample, source, note)
    else:
        resolved = (None, "none", note)
    monkeypatch.setattr(ghidra, "resolve_original_sample", lambda *_a, **_k: resolved)
    return sample, paths


def _run(tmp_path, sample, include_original=True):
    return ghidra.run_ghidra({"id": 1, "status": "reported"}, tmp_path / "out", sample,
                             "ghidra", get_cape_signatures_fn=lambda d: [],
                             include_original=include_original)


def test_original_is_analysed_alongside_dropped_pes(tmp_path, monkeypatch, pe_loader):
    """rednat_179dcccf0614: CAPE dropped 781f65c7; the beacon itself was never loaded."""
    d1, d2 = b"MZ" + b"\x01" * 600, b"MZ" + b"\x02" * 600
    sample, _ = _setup(tmp_path, monkeypatch, [d1, d2])
    out = _run(tmp_path, sample)

    handed = [data for data, _ in pe_loader]
    assert handed == [ORIGINAL, d1, d2], "original not analysed first, or a dropped PE lost"
    assert out["original_sample_source"] == "cape_storage"
    assert out["original_sample_included"] is True
    # Why Ghidra ran is unchanged: CAPE extracted dropped PEs.
    assert out["trigger_reason"] == "dropped_pe_with_signatures"


def test_each_program_still_gets_its_own_project(tmp_path, monkeypatch, pe_loader):
    """#655 named projects by content, so adding the original cannot collide."""
    d1, d2 = b"MZ" + b"\x01" * 600, b"MZ" + b"\x02" * 600
    sample, _ = _setup(tmp_path, monkeypatch, [d1, d2])
    _run(tmp_path, sample)
    dirs = [d for _, d in pe_loader]
    assert len(set(dirs)) == 3, dirs
    assert dirs[0] == tmp_path / "out" / f"pe_{_sha(ORIGINAL)[:12]}"


def test_a_dropped_copy_of_the_original_is_analysed_once(tmp_path, monkeypatch, pe_loader):
    """CAPE can extract the sample's own bytes. Same sha256, same program: once."""
    other = b"MZ" + b"\x03" * 600
    sample, _ = _setup(tmp_path, monkeypatch, [ORIGINAL, other])
    out = _run(tmp_path, sample)

    handed = [data for data, _ in pe_loader]
    assert handed == [ORIGINAL, other], handed
    assert out["original_sample_deduplicated"] == ["dropped0.exe"]


def test_routed_samples_never_analyse_the_original(tmp_path, monkeypatch, pe_loader):
    """include_original=False (#646): the wrapper is not a native program."""
    d1 = b"MZ" + b"\x01" * 600
    sample, _ = _setup(tmp_path, monkeypatch, [d1])
    out = _run(tmp_path, sample, include_original=False)

    assert [data for data, _ in pe_loader] == [d1]
    assert "original_sample_source" not in out
    assert "original_sample_included" not in out


def test_the_cap_holds_and_the_original_keeps_its_place(tmp_path, monkeypatch, pe_loader):
    """Five files at most (prolific droppers); the original is never the one cut."""
    dropped = [b"MZ" + bytes([i]) * 600 for i in range(1, 7)]
    sample, _ = _setup(tmp_path, monkeypatch, dropped)
    out = _run(tmp_path, sample)

    handed = [data for data, _ in pe_loader]
    assert len(handed) == 5, len(handed)
    assert handed[0] == ORIGINAL
    assert handed[1:] == dropped[:4]
    assert out["pe_cap_skipped"] == ["dropped4.exe", "dropped5.exe"]


def test_no_dropped_pes_is_unchanged(tmp_path, monkeypatch, pe_loader):
    sample, _ = _setup(tmp_path, monkeypatch, [])
    out = _run(tmp_path, sample)
    assert [data for data, _ in pe_loader] == [ORIGINAL]
    assert out["trigger_reason"] == "original_sample_is_pe"
    assert out["original_sample_included"] is True
    assert "pe_cap_skipped" not in out and "original_sample_deduplicated" not in out


def test_a_refused_original_says_why_when_dropped_pes_exist(tmp_path, monkeypatch, pe_loader):
    """The dropped PEs still run, and the report says why the original did not."""
    d1 = b"MZ" + b"\x01" * 600
    sample, _ = _setup(tmp_path, monkeypatch, [d1], original=None,
                       note="pipeline's copy is a DIFFERENT file")
    out = _run(tmp_path, sample)
    assert [data for data, _ in pe_loader] == [d1]
    assert out["original_sample_included"] is False
    assert "original_sample_source" not in out
    assert "DIFFERENT file" in out["original_sample_note"]
