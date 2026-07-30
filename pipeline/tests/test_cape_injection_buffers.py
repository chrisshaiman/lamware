# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cape injection-buffer extraction: a truncated buffer must not look complete.

`extract_injection_buffers` is the "ground-truth shellcode extraction" the README
headlines — Cape records the exact bytes written into another process, so we take them
directly instead of hunting them in a memory dump with malfind.

Cape caps how much of a buffer ARGUMENT it records, so a large injection can arrive
shorter than the malware asked to write. The declared length was parsed into
`buf_len_str` and then never used (ruff F841), so nothing downstream could tell a
partial payload from a whole one:

  - `size` is the CAPTURED length and is what the report shows an analyst
  - run-pipeline gates Ghidra on `analyze_with_ghidra: size >= 1024`, so truncation can
    silently change routing as well as reporting
  - the sha256 of a partial buffer will never match the real payload

This file is the first test coverage this function has had.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from stages.cape import _parse_size, extract_injection_buffers  # noqa: E402


def _report(buffer_escaped: str, declared, api="WriteProcessMemory"):
    """A minimal Cape report containing one cross-process write."""
    length_arg = ("BufferLength" if api == "WriteProcessMemory"
                  else "NumberOfBytesToWrite")
    args = [
        {"name": "ProcessId", "value": "4242"},
        {"name": "BaseAddress", "value": "0x400000"},
        {"name": "Buffer", "value": buffer_escaped},
    ]
    if declared is not None:
        args.append({"name": length_arg, "value": declared})
    return {"behavior": {"processes": [{
        "process_id": 1000, "process_name": "loader.exe",
        "calls": [{"api": api, "arguments": args}],
    }]}}


# 32 captured bytes, written as Python escapes the way Cape stores them.
BUF32 = "".join(f"\\x{i:02x}" for i in range(32))


def test_a_truncated_buffer_is_flagged(tmp_path):
    """The defect: malware asked to write 4096 bytes, Cape captured 32."""
    out = extract_injection_buffers(_report(BUF32, "4096"), tmp_path)
    assert len(out) == 1
    inj = out[0]
    assert inj["size"] == 32
    assert inj["declared_size"] == 4096
    assert inj["truncated"] is True


def test_a_complete_buffer_is_not_flagged(tmp_path):
    out = extract_injection_buffers(_report(BUF32, "32"), tmp_path)
    assert out[0]["truncated"] is False
    assert out[0]["declared_size"] == 32


def test_truncation_is_reported_on_stdout(tmp_path, capsys):
    """A partial payload that is only visible in a JSON field nobody reads is still
    invisible. The operator running the pipeline should see it."""
    extract_injection_buffers(_report(BUF32, "4096"), tmp_path)
    err = capsys.readouterr().out
    assert "TRUNCATED" in err
    assert "32" in err and "4096" in err


def test_a_missing_declared_length_is_not_claimed_as_complete(tmp_path):
    """Cape does not always record the length. `None` must mean "unknown", never
    "complete" — asserting completeness we cannot support is the same class of error
    as calling an uncheckable IOC fabricated."""
    out = extract_injection_buffers(_report(BUF32, None), tmp_path)
    assert out[0]["declared_size"] is None
    assert out[0]["truncated"] is False


def test_nt_variant_uses_its_own_length_argument(tmp_path):
    """NtWriteVirtualMemory spells it NumberOfBytesToWrite, and usually in hex."""
    out = extract_injection_buffers(
        _report(BUF32, "0x1000", api="NtWriteVirtualMemory"), tmp_path)
    assert out[0]["declared_size"] == 4096
    assert out[0]["truncated"] is True


def test_the_buffer_bytes_are_still_extracted_correctly(tmp_path):
    """Guard the behaviour that already worked — the fix must not disturb extraction."""
    out = extract_injection_buffers(_report(BUF32, "32"), tmp_path)
    written = Path(out[0]["path"]).read_bytes()
    assert written == bytes(range(32))
    assert out[0]["content_hash"] == __import__("hashlib").sha256(written).hexdigest()


@pytest.mark.parametrize("raw,expected", [
    ("4096", 4096),
    ("0x1000", 4096),
    ("0X1000", 4096),
    (4096, 4096),
    ("", None),
    (None, None),
    ("not-a-number", None),
    ("-1", None),          # nonsense length must not read as "declared 0"
    (True, None),          # bool is an int subclass; must not become 1
])
def test_parse_size_handles_capes_inconsistent_formats(raw, expected):
    assert _parse_size(raw) == expected
