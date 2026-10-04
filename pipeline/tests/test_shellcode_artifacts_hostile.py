# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A region's bytes must not be able to stall or end the run (#678).

`extract_shellcode_artifacts` scans every CAPE injection buffer, CAPE payload
and malfind region in the pipeline process. The bytes are the sample's. The
probe that opened this file, on the code as it was:

  * `[\\w.-]+\\.dll` was quadratic: 5.6-12.5 s on a 64 KB region of `a`, `a.`,
    `.dl`, `MZ`, digits — any long word run with no `.dll` in it;
  * `HKEY_[\\w]+\\\\...` was quadratic: 2.7 s on 64 KB of repeated `HKEY_`;
  * `open()` on a FIFO with no writer never returned;
  * a `str` path raised AttributeError;
  * and nothing around the Stage 2.5 call caught anything, so an exception
    there ended the run after CAPE had finished.

One report on the host scanned 44 regions, so a sample could buy roughly
nine minutes per run with its own bytes. Everything here calls the code.
"""
import importlib.util
import os
import random
import re
import threading
import time
from pathlib import Path

import pytest
from stages import ghidra, volatility
from stages.volatility import (
    ARTIFACT_SCAN_BYTES,
    _dll_names,
    _registry_keys,
    artifacts_from_bytes,
    extract_shellcode_artifacts,
    scan_shellcode_artifacts,
)

RUN_PIPELINE = (Path(__file__).resolve().parents[2]
                / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py")

# The two patterns as they were. They are the specification the linear scans
# must reproduce, match for match.
ORIGINAL_DLL = re.compile(r'[\w.-]+\.dll', re.IGNORECASE)
ORIGINAL_REG = re.compile(r'(?:HKEY_[\w]+|SOFTWARE|CurrentVersion|Run|Services)\\[\w\\]+')


def _fill(unit: bytes, n: int = ARTIFACT_SCAN_BYTES) -> bytes:
    return (unit * (n // len(unit) + 1))[:n]


# Each shape the probe ran, at the read cap. The comment is what it cost before.
HOSTILE = {
    "word run 'a'": lambda n: _fill(b"a", n),                               # 5.6 s
    "'MZ' repeated": lambda n: _fill(b"MZ", n),                             # 6.8 s
    "'a.' run": lambda n: _fill(b"a.", n),                                  # 9.8 s
    "'.dl' run": lambda n: _fill(b".dl", n),                                # 11.4 s
    "C:\\ then '.' run": lambda n: b"C:\\" + _fill(b".", n - 3),            # 13.0 s
    "'1.' run": lambda n: _fill(b"1.", n),                                  # 9.1 s
    "'HKEY_' repeated": lambda n: _fill(b"HKEY_", n),                       # 11.2 s
    "HKEY_ then word run": lambda n: b"HKEY_" + _fill(b"a", n - 5),        # 6.9 s
    "SOFTWARE\\ then word run": lambda n: b"SOFTWARE\\" + _fill(b"a", n - 9),  # 6.7 s
    "Mozilla/ then digits": lambda n: b"Mozilla/" + _fill(b"1", n - 9) + b'"',  # 6.4 s
    "MZ+e_lfanew+PE overlapping": lambda n: _fill(
        b"MZ" + b"\x00" * 0x3a + b"\x40\x00\x00\x00" + b"PE\0\0", n),
    "'PE\\0\\0' repeated": lambda n: _fill(b"PE\0\0", n),
    "'http://' repeated": lambda n: _fill(b"http://", n),
    "'Global\\' repeated": lambda n: _fill(b"Global\\", n),
    "short strings 'ab\\0'": lambda n: _fill(b"ab\0", n),
    "all of the above, interleaved": lambda n: _fill(
        b"a" * 3000 + b".dl" * 1000 + b"HKEY_" * 600 + b"MZ" * 1500 + b"C:\\" + b"." * 2000, n),
    "random bytes": lambda n: random.Random(678).randbytes(n),
    "zeros": lambda n: bytes(n),
}


@pytest.mark.parametrize("label", list(HOSTILE))
def test_no_hostile_region_stalls_or_raises(label, tmp_path):
    """Through the file entry point, at the size the read is capped to. One
    second is about 25x the slowest shape now and a fifth of the fastest
    stall before."""
    path = tmp_path / "region.bin"
    path.write_bytes(HOSTILE[label](ARTIFACT_SCAN_BYTES))
    t0 = time.monotonic()
    out = extract_shellcode_artifacts(path)
    elapsed = time.monotonic() - t0
    assert isinstance(out, dict)
    assert elapsed < 1.0, f"{label}: {elapsed:.2f}s on {ARTIFACT_SCAN_BYTES} bytes"


def _scan_seconds(data: bytes) -> float:
    t0 = time.perf_counter()
    artifacts_from_bytes(data)
    return time.perf_counter() - t0


@pytest.mark.parametrize("label", ["'.dl' run", "'HKEY_' repeated", "'MZ' repeated",
                                   "C:\\ then '.' run", "all of the above, interleaved"])
def test_scan_cost_grows_linearly(label):
    """A wall-clock bound loose enough for CI cannot see a quadratic path come
    back on a small input; the growth rate can. 10x the input must cost well
    under 100x the time — the patterns this replaced cost ~100x (measured:
    0.11 s -> 11.4 s for '.dl', 0.03 s -> 2.7 s for HKEY_ in that regex alone).
    Past the read cap on purpose: `artifacts_from_bytes` is the scan itself."""
    make = HOSTILE[label]
    _scan_seconds(make(4_000))                                    # warm-up
    small = min(_scan_seconds(make(8_000)) for _ in range(3))
    big = min(_scan_seconds(make(80_000)) for _ in range(2))
    assert big / small < 30, f"{label}: 8 KB {small:.4f}s, 80 KB {big:.4f}s"


# --- same answers ---------------------------------------------------------------

def _tokens(rng: random.Random, alphabet: list[str], n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def test_dll_scan_matches_the_regex_it_replaced():
    """Random strings built from the characters the pattern turns on, so
    matches, near-misses and run boundaries are all frequent."""
    rng = random.Random(1)
    alphabet = [".dll", ".DLL", ".Dll", "a", "-", ".", "d", "l", " ", "\x00", "k32", "_", ":"]
    for _ in range(20_000):
        s = _tokens(rng, alphabet, rng.randrange(0, 25))
        assert _dll_names(s) == ORIGINAL_DLL.findall(s), repr(s)


def test_registry_scan_matches_the_regex_it_replaced():
    rng = random.Random(2)
    alphabet = ["HKEY_", "SOFTWARE", "CurrentVersion", "Run", "Services", "\\", "\\\\",
                "a", "_", " ", "\x00", "HKEY", "Ru", "-", "x"]
    for _ in range(20_000):
        s = _tokens(rng, alphabet, rng.randrange(0, 25))
        assert _registry_keys(s) == ORIGINAL_REG.findall(s), repr(s)


def _shellcode_like() -> bytes:
    """What an injected stub carries: a prologue, a resolved import table,
    a dropped path, a C2 URL, an autorun key, a mutex, a user agent, and an
    embedded PE. Synthetic — no sample bytes."""
    pe = bytearray(b"MZ" + b"\x00" * 0x3a + (0x80).to_bytes(4, "little"))
    pe += b"\x00" * (0x80 - len(pe)) + b"PE\0\0" + b"\x00" * 32
    return (b"\x55\x8b\xec\x83\xec\x40" + b"\x00" * 10
            + b"kernel32.dll\x00ntdll.dll\x00ws2_32.DLL\x00"
            + b"LoadLibraryA\x00GetProcAddress\x00VirtualAllocEx\x00"
            + b"WriteProcessMemory\x00CreateRemoteThread\x00InternetOpenUrlA\x00"
            + b"C:\\Users\\Public\\svchost.exe\x00"
            + b"http://198.51.100.7/gate.php\x00203.0.113.9\x00127.0.0.1\x00"
            + b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
            + b"HKEY_CURRENT_USER\\Software\\Classes\x00"
            + b"Global\\QQ-mutex-01\x00"
            + b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\x00"
            + b"\xcc" * 48 + bytes(pe) + b"\x90" * 64)


def test_a_shellcode_like_region_yields_what_it_carries(tmp_path):
    """Every field, by value. Set-derived lists are compared as sets: their
    order is the set's, as before."""
    path = tmp_path / "stub.bin"
    data = _shellcode_like()
    path.write_bytes(data)
    out = extract_shellcode_artifacts(path)
    pe_at = data.index(b"MZ\x00")
    assert out["resolved_apis"] == ["LoadLibraryA", "GetProcAddress", "VirtualAlloc",
                                    "VirtualAllocEx", "CreateRemoteThread",
                                    "WriteProcessMemory", "InternetOpenUrlA"]
    assert set(out["file_paths"]) == {"C:\\Users\\Public\\svchost.exe"}
    assert set(out["dll_names"]) == {"kernel32.dll", "ntdll.dll", "ws2_32.DLL"}
    assert set(out["urls"]) == {"http://198.51.100.7/gate.php"}
    assert set(out["ip_addresses"]) == {"198.51.100.7", "203.0.113.9"}
    assert set(out["registry_keys"]) == {"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                         "HKEY_CURRENT_USER\\Software\\Classes"}
    assert out["embedded_pe"] is True
    assert out["pe_offsets"] == [f"0x{pe_at:x}"]
    assert out["interesting_strings"] == [
        "mutex:Global\\QQ-mutex-01",
        "user-agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]
    assert set(out) == {"resolved_apis", "file_paths", "dll_names", "urls", "ip_addresses",
                        "registry_keys", "embedded_pe", "pe_offsets", "interesting_strings"}


@pytest.mark.parametrize("seed", range(5))
def test_whole_scan_equals_the_scan_with_the_original_regexes(seed, monkeypatch):
    """The function end to end, against itself with the two original patterns
    swapped back in — on the shellcode-like region and on noisy regions dense
    with every pattern's near-misses. Same process, same hash seed, so even the
    set-derived order and the [:20] cuts must agree."""
    rng = random.Random(seed)
    alphabet = ["kernel32.dll", ".dl", "HKEY_", "Run", "\\", "C:\\", "a", ".", "1.",
                "http://", "Global\\", "Mozilla/1.0 ", "MZ", "LoadLibraryA", " ", "\x00"]
    regions = [_shellcode_like()] + [
        _tokens(rng, alphabet, 4000).encode() for _ in range(3)]
    new = [artifacts_from_bytes(r) for r in regions]
    monkeypatch.setattr(volatility, "_dll_names", ORIGINAL_DLL.findall)
    monkeypatch.setattr(volatility, "_registry_keys", ORIGINAL_REG.findall)
    old = [artifacts_from_bytes(r) for r in regions]
    assert new == old


# --- files that are not ordinary --------------------------------------------------

def test_zero_length_missing_and_directory_give_nothing(tmp_path):
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert extract_shellcode_artifacts(empty) == {}
    assert extract_shellcode_artifacts(tmp_path / "missing") == {}
    assert extract_shellcode_artifacts(tmp_path) == {}


def test_an_unreadable_file_gives_nothing(tmp_path):
    path = tmp_path / "locked"
    path.write_bytes(b"LoadLibraryA kernel32.dll")
    path.chmod(0)
    try:
        out = extract_shellcode_artifacts(path)
    finally:
        path.chmod(0o600)
    # root reads it anyway; either way it is an answer, not an exception
    assert out == {} or os.geteuid() == 0


def test_a_fifo_does_not_hang_the_scan(tmp_path):
    """A plain open() on a FIFO with no writer never returns. Run in a thread
    so a regression fails this test instead of hanging the suite."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    box = {}
    t = threading.Thread(target=lambda: box.update(out=extract_shellcode_artifacts(fifo)),
                         daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive(), "extract_shellcode_artifacts blocked opening a FIFO"
    assert box["out"] == {}


def test_only_the_head_of_a_huge_region_is_read(tmp_path):
    """The largest CAPE payload on the host was 61 MB; the scan reads 64 KB of
    it. An API name past the cap is not seen, and the time does not grow."""
    path = tmp_path / "huge.bin"
    with path.open("wb") as fh:
        fh.write(_fill(b".dl"))
        fh.seek(61_145_087 - 16)
        fh.write(b"LoadLibraryA\x00\x00\x00\x00")
    t0 = time.monotonic()
    out = extract_shellcode_artifacts(path)
    assert time.monotonic() - t0 < 1.0
    assert "resolved_apis" not in out


def test_a_str_path_is_accepted(tmp_path):
    path = tmp_path / "stub.bin"
    path.write_bytes(_shellcode_like())
    assert extract_shellcode_artifacts(str(path)) == extract_shellcode_artifacts(path)


# --- one region cannot end the stage ------------------------------------------------

def test_the_never_raising_scan_reports_what_went_wrong(monkeypatch, tmp_path):
    def boom(_p):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(volatility, "extract_shellcode_artifacts", boom)
    assert scan_shellcode_artifacts(tmp_path / "x") == (
        {}, "RecursionError: maximum recursion depth exceeded")


@pytest.fixture(scope="module")
def rp():
    spec = importlib.util.spec_from_file_location("run_pipeline_678", RUN_PIPELINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_stage_25_keeps_going_after_a_region_that_raises(rp, monkeypatch, tmp_path):
    """Three injection buffers and a payload; scanning the second buffer
    raises. Every region still becomes a candidate, the failing one says why,
    and the rest are scanned for real."""
    paths = []
    for i in range(4):
        p = tmp_path / f"region{i}.bin"
        p.write_bytes(_shellcode_like())
        paths.append(p)
    real = volatility.extract_shellcode_artifacts

    def flaky(path):
        if Path(path) == paths[1]:
            raise MemoryError("synthetic")
        return real(path)
    monkeypatch.setattr(volatility, "extract_shellcode_artifacts", flaky)

    def buf(p, i):
        return {"path": str(p), "size": 2048, "source_pid": 10 + i, "source_process": "a.exe",
                "target_pid": 20 + i, "injection_address": f"0x{0x1000 * (i + 1):x}"}
    report = {"cape": {
        "injection_buffers": [buf(p, i) for i, p in enumerate(paths[:3])],
        "large_payloads": [{"path": str(paths[3]), "size": 4096, "cape_type": "Payload",
                            "sha256": "ab" * 32}],
    }}
    cands = rp.build_cape_injection_candidates(report)

    assert [c["path"] for c in cands] == paths
    assert cands[1]["shellcode_artifacts"] == {}
    assert cands[1]["shellcode_artifacts_error"] == "MemoryError: synthetic"
    for c in (cands[0], cands[2], cands[3]):
        assert "shellcode_artifacts_error" not in c
        assert "LoadLibraryA" in c["shellcode_artifacts"]["resolved_apis"]
    assert [c["source"] for c in cands] == ["cape_injection"] * 3 + ["cape_payload"]


def test_run_pipeline_builds_stage_25_through_the_guarded_function():
    """Structural, because run_pipeline needs a host to run: Stage 2.5 must be
    the function tested above, and nothing in run-pipeline may call the raising
    scan directly."""
    import ast
    tree = ast.parse(RUN_PIPELINE.read_text())
    called = {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "build_cape_injection_candidates" in called
    assert "extract_shellcode_artifacts" not in called


def _artifact_only(path: Path, **extra) -> dict:
    return {"path": path, "pid": 7, "process": "p.exe", "injection_address": "0x1000",
            "region_size": 64, "analyze_with_ghidra": False, **extra}


def test_ghidra_records_a_scan_that_raised_and_surfaces_it(monkeypatch, tmp_path):
    """A malfind region reaches its first scan here. It raises; the region still
    gets its result, which carries the error and a warning naming only the type."""
    def boom(_p):
        raise RecursionError("bytes the sample chose")
    monkeypatch.setattr(volatility, "extract_shellcode_artifacts", boom)
    out = ghidra.run_ghidra_shellcode(_artifact_only(tmp_path / "r.bin"), tmp_path, "run-ghidra")
    assert out["shellcode_artifacts_error"] == "RecursionError: bytes the sample chose"
    lifted = ghidra.collect_analysis_warnings([out])
    assert len(lifted) == 1 and "RecursionError" in lifted[0]
    assert "bytes the sample chose" not in lifted[0]


def test_ghidra_does_not_repeat_a_scan_that_already_failed(monkeypatch, tmp_path):
    def must_not_run(_p):
        raise AssertionError("rescanned a region whose scan already failed")
    monkeypatch.setattr(ghidra, "scan_shellcode_artifacts", must_not_run)
    cand = _artifact_only(tmp_path / "r.bin", shellcode_artifacts={},
                          shellcode_artifacts_error="MemoryError: synthetic")
    out = ghidra.run_ghidra_shellcode(cand, tmp_path, "run-ghidra")
    assert out["shellcode_artifacts_error"] == "MemoryError: synthetic"


def test_ghidra_scan_on_a_clean_region_adds_no_warning(tmp_path):
    path = tmp_path / "r.bin"
    path.write_bytes(_shellcode_like())
    out = ghidra.run_ghidra_shellcode(_artifact_only(path), tmp_path, "run-ghidra")
    assert "LoadLibraryA" in out["shellcode_artifacts"]["resolved_apis"]
    assert "shellcode_artifacts_error" not in out
    assert "analysis_warnings" not in out
