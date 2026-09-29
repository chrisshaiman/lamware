# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Two different shellcode candidates must never share a Ghidra project (#648).

CAPE's extracted payloads reach Ghidra through `run_ghidra_shellcode` with pid 0
and address "N/A", so the directory was `shellcode_0_unknown` for every one of
them. Each headless run starts with "Creating project", which replaces whatever
was there. On the host (2026-09-28) cobaltstrike's project held 1 of its 5
payloads and latrodectus's 1 of 4; across the database, 269 payload programs in
101 analyses were listed in their reports with function counts and could not be
opened by a single tool call.

These tests call the function with Ghidra stubbed out and assert on the
directory it actually passes to run-ghidra.
"""
import hashlib
import subprocess
from pathlib import Path

import pytest
from stages import ghidra


@pytest.fixture
def calls(monkeypatch):
    """Record the output directory handed to run-ghidra; pretend it failed so
    the function returns without needing a real project on disk."""
    seen: list[Path] = []

    def fake_run(cmd, **_kw):
        assert cmd[1] == "--shellcode", cmd
        seen.append(Path(cmd[3]))
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="stub")

    monkeypatch.setattr(ghidra.subprocess, "run", fake_run)
    monkeypatch.setattr(ghidra, "extract_shellcode_artifacts", lambda _p: {})
    return seen


def _payload(tmp_path: Path, name: str, data: bytes, **extra) -> dict:
    """A candidate shaped exactly like run-pipeline's cape_payload entries."""
    path = tmp_path / name
    path.write_bytes(data)
    return {"source": "cape_payload", "pid": 0, "injection_address": "N/A",
            "path": path, "region_size": len(data), "analyze_with_ghidra": True,
            "sha256": hashlib.sha256(data).hexdigest(), **extra}


def test_two_cape_payloads_get_two_projects(tmp_path, calls):
    a = _payload(tmp_path, "a", b"\x90" * 2048)
    b = _payload(tmp_path, "b", b"\xcc" * 2048)
    ghidra.run_ghidra_shellcode(a, tmp_path / "out", "run-ghidra")
    ghidra.run_ghidra_shellcode(b, tmp_path / "out", "run-ghidra")
    assert len(calls) == 2
    assert calls[0] != calls[1], calls


def test_identical_bytes_may_share_a_project(tmp_path, calls):
    """Same content is the same program; sharing loses nothing."""
    a = _payload(tmp_path, "a", b"\x90" * 2048)
    b = _payload(tmp_path, "b", b"\x90" * 2048)
    ghidra.run_ghidra_shellcode(a, tmp_path / "out", "run-ghidra")
    ghidra.run_ghidra_shellcode(b, tmp_path / "out", "run-ghidra")
    assert calls[0] == calls[1]


def test_a_missing_or_fake_sha_is_replaced_by_the_file_hash(tmp_path, calls):
    """run-pipeline defaults sha256 to "" when CAPE gave none. Two such
    payloads must still be told apart — by hashing what Ghidra will read."""
    a = _payload(tmp_path, "a", b"\x90" * 2048, sha256="")
    # Not a hash, and not path-safe: a value like this must never reach the
    # directory name, whatever else it would or would not collide with.
    b = _payload(tmp_path, "b", b"\xcc" * 2048, sha256="../../etc/x")
    ghidra.run_ghidra_shellcode(a, tmp_path / "out", "run-ghidra")
    ghidra.run_ghidra_shellcode(b, tmp_path / "out", "run-ghidra")
    assert calls[0] != calls[1]
    assert calls[0].name.endswith(hashlib.sha256(b"\x90" * 2048).hexdigest()[:12])
    assert calls[1].name.endswith(hashlib.sha256(b"\xcc" * 2048).hexdigest()[:12])
    assert calls[1].parent == tmp_path / "out", calls[1]


def test_same_pid_and_address_different_bytes_do_not_collide(tmp_path, calls):
    """Two writes to one address in one process are two programs."""
    a = _payload(tmp_path, "a", b"\x90" * 2048, pid=4192, injection_address="0x400000")
    b = _payload(tmp_path, "b", b"\xcc" * 2048, pid=4192, injection_address="0x400000")
    ghidra.run_ghidra_shellcode(a, tmp_path / "out", "run-ghidra")
    ghidra.run_ghidra_shellcode(b, tmp_path / "out", "run-ghidra")
    assert calls[0] != calls[1]


def test_artifact_only_buffers_never_need_a_readable_dump(tmp_path, calls):
    """A < 1KB buffer returns before any project is named, so a missing dump
    must not raise just because the name now includes a content hash."""
    cand = {"source": "cape_injection", "pid": 7, "injection_address": "0x10",
            "path": tmp_path / "gone", "region_size": 16,
            "analyze_with_ghidra": False, "shellcode_artifacts": {"x": 1}}
    out = ghidra.run_ghidra_shellcode(cand, tmp_path / "out", "run-ghidra")
    assert out["analysis_success"] is False
    assert calls == []
