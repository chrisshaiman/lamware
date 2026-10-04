# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Stage 4's header peeks answer "not this type" on hostile input; none raises (#677).

The pipeline routes a sample by peeking at its bytes — an MZ check, the CLR
directory of a PE header, a scan for the PyInstaller cookie — and Stage 4 is not
wrapped, so a peek that raises ends the run and the sample's analysis with it.
#677's probe, run against the code before this change, found:

    FIFO where a file is expected          every peek hung (open() waits for a writer)
    parent directory not readable          PermissionError out of is_pyinstaller_binary
                                           and _is_ghidra_compatible_binary (exists())
    2 GiB file under a 1 GiB memory limit  MemoryError out of is_pyinstaller_binary and
                                           _find_embedded_dotnet (whole-file read)
    1 MiB of "MZ"                          _find_embedded_dotnet took 9.7 s (quadratic:
                                           each candidate copied the rest of the file)
    unreadable vol_procdump/               PermissionError out of find_dotnet_extractions
    NumberOfRvaAndSizes=2, junk in slot 14 _has_clr_header and the carve called a native
                                           PE .NET (read the section table as an RVA)

These tests build every input synthetically — minimal headers, sparse files —
and call the real functions. No sample binary is committed.
"""
import os
import signal
import struct
from contextlib import contextmanager
from pathlib import Path

import pytest
from stages import dotnet, ghidra, peek, pyinstaller

MEI = pyinstaller.PYINSTALLER_MAGIC


def pe(magic=0x10B, clr_rva=0x2008, e_lfanew=0x80, nrva=16, size=4096):
    """A minimal PE header: MZ, e_lfanew, PE signature, COFF, optional header
    with NumberOfRvaAndSizes and the CLR (index 14) data directory."""
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, magic)
    struct.pack_into("<I", buf, opt + (92 if magic == 0x10B else 108), nrva)
    clr = opt + (96 if magic == 0x10B else 112) + 14 * 8
    struct.pack_into("<II", buf, clr, clr_rva, 0x48 if clr_rva else 0)
    return bytes(buf)


def _dos(e_lfanew: int, tail: bytes = b"") -> bytes:
    return b"MZ" + b"\0" * 58 + struct.pack("<I", e_lfanew) + tail


def _opt_truncated() -> bytes:
    return _dos(64) + b"PE\0\0" + b"\0" * 21   # magic would sit at byte 88 = EOF


def _overlapping() -> bytes:
    """e_lfanew 2: the PE signature sits inside the DOS header, over "MZ"+2."""
    b = bytearray(_dos(2, b"\0" * 4032))
    b[2:6] = b"PE\0\0"
    return bytes(b)


HOSTILE_BYTES = {
    "zero_length": b"",
    "one_byte": b"M",
    "mz_only": b"MZ",
    "dos_header_truncated": b"MZ" + b"\0" * 58,
    "e_lfanew_past_eof": _dos(0x7FFFFFF0, b"\0" * 600),
    "e_lfanew_all_ones": _dos(0xFFFFFFFF, b"\0" * 600),
    "optional_header_truncated": _opt_truncated(),
    "bad_optional_magic": pe(magic=0x1234),
    "directories_past_eof": pe()[:0x80 + 24 + 100],
    "clr_slot_not_declared": pe(nrva=2, clr_rva=0x41414141),
    "pe_signature_overlaps_dos_header": _overlapping(),
    "native_pe_empty_clr": pe(clr_rva=0),
}


class Hung(BaseException):
    """Not an OSError: TimeoutError is one, and the peeks' own ``except OSError``
    swallowed it, so a hang looked like a clean "not this type"."""


@contextmanager
def deadline(seconds: int = 5):
    """Fail instead of hanging: the pre-fix FIFO case blocked forever."""
    def boom(*_):
        raise Hung(f"peek still running after {seconds}s")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _cape_storage(tmp_path: Path, target: Path) -> Path:
    storage = tmp_path / "storage"
    (storage / "1").mkdir(parents=True)
    (storage / "1" / "binary").symlink_to(target)
    return storage


# Each peek, called as Stage 4 calls it, answering a truthy value for "this type".
PEEKS = {
    "has_clr_header": lambda p, tmp: dotnet._has_clr_header(p),
    "find_embedded_dotnet": lambda p, tmp: dotnet._find_embedded_dotnet(p),
    "is_pyinstaller_binary": lambda p, tmp: pyinstaller.is_pyinstaller_binary({}, p),
    "is_ghidra_compatible_binary": lambda p, tmp: ghidra._is_ghidra_compatible_binary(p),
    "get_original_sample_path": lambda p, tmp: ghidra.get_original_sample_path(
        {"id": 1}, _cape_storage(tmp, p)),
}

# What the MZ-only checks legitimately say "yes" to: they promise only "starts
# with MZ" (Ghidra parses the rest in its own container), so a truncated MZ
# file IS a Ghidra candidate. The question for them is "does not raise".
STARTS_WITH_MZ = {"mz_only", "dos_header_truncated", "e_lfanew_past_eof", "e_lfanew_all_ones",
                  "optional_header_truncated", "bad_optional_magic", "directories_past_eof",
                  "clr_slot_not_declared", "pe_signature_overlaps_dos_header",
                  "native_pe_empty_clr"}
MZ_ONLY_PEEKS = {"is_ghidra_compatible_binary", "get_original_sample_path"}


@pytest.fixture(autouse=True)
def _carves_in_tmp(tmp_path, monkeypatch):
    """Keep carved files out of the shared /tmp between tests."""
    carves = tmp_path / "carves"
    carves.mkdir()
    monkeypatch.setattr(dotnet, "CARVE_DIR", carves)


@pytest.mark.parametrize("shape", sorted(HOSTILE_BYTES))
@pytest.mark.parametrize("peek_name", sorted(PEEKS))
def test_malformed_header_is_not_this_type(tmp_path, peek_name, shape):
    f = tmp_path / "sample"
    f.write_bytes(HOSTILE_BYTES[shape])
    with deadline():
        got = PEEKS[peek_name](f, tmp_path)
    if peek_name in MZ_ONLY_PEEKS and shape in STARTS_WITH_MZ:
        assert got, "an MZ-prefixed file is a Ghidra candidate; the peek must still say so"
    else:
        assert not got, f"{peek_name} claimed a {shape} file"


def _make_fifo(tmp_path):
    p = tmp_path / "fifo"
    os.mkfifo(p)
    return p


def _make_dir(tmp_path):
    p = tmp_path / "a_directory"
    p.mkdir()
    return p


def _make_symlink_to_dir(tmp_path):
    p = tmp_path / "link"
    p.symlink_to(_make_dir(tmp_path))
    return p


def _make_dangling(tmp_path):
    p = tmp_path / "dangling"
    p.symlink_to(tmp_path / "nowhere")
    return p


def _make_unreadable(tmp_path):
    p = tmp_path / "unreadable"
    p.write_bytes(pe())
    p.chmod(0)
    return p


def _make_locked_parent(tmp_path):
    d = tmp_path / "locked"
    d.mkdir()
    (d / "f").write_bytes(pe())
    d.chmod(0)
    return d / "f"


NOT_A_READABLE_FILE = {
    "fifo": _make_fifo,
    "directory": _make_dir,
    "symlink_to_directory": _make_symlink_to_dir,
    "dangling_symlink": _make_dangling,
    "missing": lambda tmp: tmp / "missing",
    "unreadable_file": _make_unreadable,
    "unreadable_parent_dir": _make_locked_parent,
}


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores mode 000")
@pytest.mark.parametrize("shape", sorted(NOT_A_READABLE_FILE))
@pytest.mark.parametrize("peek_name", sorted(PEEKS))
def test_something_that_is_not_a_readable_file_is_not_this_type(tmp_path, peek_name, shape):
    p = NOT_A_READABLE_FILE[shape](tmp_path)
    try:
        with deadline():
            got = PEEKS[peek_name](p, tmp_path)
    finally:
        if (tmp_path / "locked").exists():
            (tmp_path / "locked").chmod(0o700)
    assert not got


@pytest.mark.parametrize("peek_name", ["has_clr_header", "find_embedded_dotnet",
                                       "is_pyinstaller_binary"])
def test_a_fifo_with_a_dotnet_header_waiting_in_it_is_still_not_read(tmp_path, peek_name):
    """Non-blocking open alone is not enough: with a writer holding the pipe
    open and a valid header buffered in it, the read succeeds. Only refusing
    non-regular files on the descriptor stops the peek reading a stream."""
    p = tmp_path / "fifo"
    os.mkfifo(p)
    writer = os.open(p, os.O_RDWR | os.O_NONBLOCK)   # Linux: no wait for a reader
    try:
        os.write(writer, pe()[:4000] + MEI)
        with deadline():
            got = PEEKS[peek_name](p, tmp_path)
    finally:
        os.close(writer)
    assert not got


@pytest.fixture
def sparse_2g(tmp_path):
    """2 GiB that occupy no disk: an MZ, then a hole."""
    p = tmp_path / "huge"
    with p.open("wb") as fh:
        fh.write(b"MZ")
        fh.truncate(2 << 30)
    return p


def _peak_heap(fn):
    import tracemalloc
    tracemalloc.start()
    try:
        out = fn()
        return out, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("peek_name", ["find_embedded_dotnet", "is_pyinstaller_binary"])
def test_a_huge_file_is_scanned_in_bounded_memory_and_the_cap_is_logged(
        tmp_path, sparse_2g, peek_name, monkeypatch, caplog):
    """Before #677 both read the whole file: MemoryError under a 1 GiB limit."""
    monkeypatch.setattr(peek, "SCAN_CAP", 8 << 20)
    with deadline(20):
        got, peak = _peak_heap(lambda: PEEKS[peek_name](sparse_2g, tmp_path))
    assert not got
    assert peak < 4 * peek.CHUNK, f"peak heap {peak} bytes for a capped scan"
    assert any("scan cap" in r.getMessage() for r in caplog.records), \
        "a capped scan must say so in the run's log"


def test_the_embedded_scan_stops_at_the_cap(tmp_path, monkeypatch, caplog):
    """Bounded memory is not enough: without the cap a 2 GiB blob is still read
    end to end. A header planted past the cap must not be found."""
    monkeypatch.setattr(peek, "SCAN_CAP", 64 << 10)
    f = tmp_path / "blob"
    f.write_bytes(b"\0" * (200 << 10) + pe() + b"\0" * (64 << 10))
    assert dotnet._find_embedded_dotnet(f) is None
    assert any("scan cap" in r.getMessage() for r in caplog.records)


def test_an_mz_flood_stops_at_the_candidate_limit_and_says_so(tmp_path, caplog):
    """1 MiB of "MZ" took 9.7 s before #677 and grows with the square of the size."""
    f = tmp_path / "flood"
    f.write_bytes(b"MZ" * (512 * 1024))
    import time
    t0 = time.monotonic()
    assert dotnet._find_embedded_dotnet(f) is None
    assert time.monotonic() - t0 < 2.0
    assert any("MZ candidates" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Real headers are still detected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("magic", [0x10B, 0x20B], ids=["PE32", "PE32+"])
def test_a_dotnet_header_is_detected(tmp_path, magic):
    f = tmp_path / "net.exe"
    f.write_bytes(pe(magic=magic))
    assert dotnet._has_clr_header(f) is True


def test_a_native_header_is_not_dotnet(tmp_path):
    f = tmp_path / "native.exe"
    f.write_bytes(pe(clr_rva=0))
    assert dotnet._has_clr_header(f) is False


def test_the_clr_slot_counts_only_when_the_header_declares_it(tmp_path):
    """nrva 15 is the smallest count that includes index 14."""
    yes, no = tmp_path / "15", tmp_path / "14"
    yes.write_bytes(pe(nrva=15))
    no.write_bytes(pe(nrva=14))
    assert dotnet._has_clr_header(yes) is True
    assert dotnet._has_clr_header(no) is False


def test_a_symlinked_sample_is_still_read(tmp_path):
    """CAPE's analyses/<id>/binary is a symlink; refusing links would hide it."""
    target = tmp_path / "net.exe"
    target.write_bytes(pe())
    assert ghidra.get_original_sample_path({"id": 1}, _cape_storage(tmp_path, target)) is not None
    link = tmp_path / "link"
    link.symlink_to(target)
    assert dotnet._has_clr_header(link) is True


@pytest.mark.parametrize("magic,want", [(b"MZ\0\0", True), (b"\x7fELF", True),
                                         (b"\xcf\xfa\xed\xfe", True), (b"#!/b", False)])
def test_ghidra_magic_still_routes(tmp_path, magic, want):
    f = tmp_path / "s"
    f.write_bytes(magic + b"\0" * 60)
    assert ghidra._is_ghidra_compatible_binary(f) is want


# A small read chunk puts headers and cookies across read boundaries, which a
# 1 MiB chunk never would with test-sized files.
SMALL_CHUNK = 8192


@pytest.mark.parametrize("at", [0, 100_000, SMALL_CHUNK - 1, SMALL_CHUNK - 2000, 3 * SMALL_CHUNK - 4352,
                                3 * SMALL_CHUNK - 4351, 3 * SMALL_CHUNK + 1])
def test_an_embedded_dotnet_pe_is_carved_from_its_mz_to_eof(tmp_path, monkeypatch, at):
    monkeypatch.setattr(peek, "CHUNK", SMALL_CHUNK)
    blob = os.urandom(at).replace(b"MZ", b"mz") + pe() + b"\xAA" * 2000
    f = tmp_path / "blob"
    f.write_bytes(blob)
    carved = dotnet._find_embedded_dotnet(f)
    assert carved is not None
    assert carved.read_bytes() == blob[at:]


def test_the_embedded_answer_matches_the_pre_677_search(tmp_path, monkeypatch):
    """Differential: random blobs with planted headers and decoys, compared with
    the whole-file search this replaced (kept below verbatim in logic)."""
    import random
    rng = random.Random(677)
    monkeypatch.setattr(peek, "CHUNK", SMALL_CHUNK)
    decoys = [pe(clr_rva=0), pe(magic=0x1234), _dos(0x7FFFFFF0), _dos(5000), b"MZ", b"MZMZ"]
    for i in range(150):
        parts = []
        for _ in range(rng.randint(1, 8)):
            parts.append(rng.randbytes(rng.randint(0, 9000)))
            r = rng.random()
            if r < 0.5:
                parts.append(rng.choice(decoys))
            elif r < 0.6:
                e_lfanew = rng.choice([0x40, 0x80, 2000, 4000])
                parts.append(pe(magic=rng.choice([0x10B, 0x20B]), e_lfanew=e_lfanew,
                                size=8192 if e_lfanew >= 2000 else 4096))
        blob = b"".join(parts)
        if rng.random() < 0.3:
            blob = blob[:rng.randint(0, len(blob))]
        f = tmp_path / f"b{i}"
        f.write_bytes(blob)
        with f.open("rb") as fh:
            got, _ = dotnet._embedded_clr_offset(fh, len(blob))
        assert got == _pre_677_offset(blob), f"blob {i}, {len(blob)} bytes"


def _pre_677_offset(data: bytes):
    """The pre-#677 _find_embedded_dotnet search, minus the carve."""
    offset = 0
    while offset < len(data) - 64:
        pos = data.find(b"MZ", offset)
        if pos == -1:
            break
        chunk = data[pos:]
        if len(chunk) < 512:
            offset = pos + 2
            continue
        try:
            pe_offset = struct.unpack_from("<I", chunk, 0x3C)[0]
            if pe_offset + 24 > len(chunk) or pe_offset > 4096:
                offset = pos + 2
                continue
            if chunk[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                offset = pos + 2
                continue
            magic = struct.unpack_from("<H", chunk, pe_offset + 24)[0]
            if magic == 0x10b:
                clr_off = pe_offset + 24 + 208
            elif magic == 0x20b:
                clr_off = pe_offset + 24 + 224
            else:
                offset = pos + 2
                continue
            if clr_off + 8 > len(chunk):
                offset = pos + 2
                continue
            if struct.unpack_from("<I", chunk, clr_off)[0] > 0:
                return pos
        except (struct.error, IndexError):
            pass
        offset = pos + 2
    return None


@pytest.mark.parametrize("at", [0, SMALL_CHUNK - 3, SMALL_CHUNK - 8, 5 * SMALL_CHUNK - 1])
def test_the_pyinstaller_cookie_is_found_across_read_boundaries(tmp_path, monkeypatch, at):
    monkeypatch.setattr(peek, "CHUNK", SMALL_CHUNK)
    f = tmp_path / "pyi.exe"
    f.write_bytes(b"\0" * at + MEI + b"\0" * 88)
    assert pyinstaller.is_pyinstaller_binary({}, f) is True


def test_an_over_cap_file_still_has_its_cookie_found_in_the_tail(tmp_path, monkeypatch, caplog):
    """The cookie lives 88-9,376 bytes from EOF on every PyInstaller sample on
    the host; a capped head scan alone would miss all of them."""
    monkeypatch.setattr(peek, "SCAN_CAP", 64 << 10)
    f = tmp_path / "big_pyi.exe"
    f.write_bytes(pe(clr_rva=0, size=200 << 10) + MEI + b"\0" * 88)
    assert pyinstaller.is_pyinstaller_binary({}, f) is True
    assert any("scan cap" in r.getMessage() for r in caplog.records)


def test_the_cookie_straddling_the_cap_is_found(tmp_path, monkeypatch):
    cap = 64 << 10
    monkeypatch.setattr(peek, "SCAN_CAP", cap)
    f = tmp_path / "s"
    f.write_bytes(b"\0" * (cap - 3) + MEI + b"\0" * (4 << 20))
    assert peek.contains(f, MEI, tail=1024) == (True, False), "found in the head scan; nothing was missed"


# ---------------------------------------------------------------------------
# find_dotnet_extractions — the stage entry
# ---------------------------------------------------------------------------

def _cape_task(tmp_path: Path) -> Path:
    for d in ("procdump", "CAPE", "dropped"):
        (tmp_path / "analyses" / "7" / d).mkdir(parents=True)
    return tmp_path / "analyses"


def test_pass_one_finds_a_dotnet_procdump(tmp_path):
    storage = _cape_task(tmp_path)
    (storage / "7" / "procdump" / ("a" * 64)).write_bytes(pe(size=8192))
    (storage / "7" / "procdump" / "native").write_bytes(pe(clr_rva=0, size=8192))
    out = dotnet.find_dotnet_extractions({}, 7, storage=storage)
    assert [(r["source_dir"], r["size"]) for r in out] == [("procdump", 8192)]


def test_pass_one_keeps_its_4096_byte_floor(tmp_path):
    """Unchanged by #677: a .NET header in a file under 4 KiB is not an extraction."""
    storage = _cape_task(tmp_path)
    (storage / "7" / "procdump" / "small").write_bytes(pe(size=4095))
    assert dotnet.find_dotnet_extractions({}, 7, storage=storage) == []


def test_pass_two_carves_from_a_large_blob(tmp_path):
    storage = _cape_task(tmp_path)
    blob = b"\0" * 60_000 + pe() + b"\0" * 100
    (storage / "7" / "CAPE" / "blob").write_bytes(blob)
    out = dotnet.find_dotnet_extractions({}, 7, storage=storage)
    assert len(out) == 1 and out[0]["carved_from"].endswith("blob")
    assert Path(out[0]["path"]).read_bytes() == blob[60_000:]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores mode 000")
def test_an_unreadable_extraction_dir_is_skipped_not_fatal(tmp_path, caplog):
    storage = _cape_task(tmp_path)
    (storage / "7" / "CAPE" / "net").write_bytes(pe(size=8192))
    locked = storage / "7" / "procdump"
    (locked / "x").write_bytes(pe(size=8192))
    locked.chmod(0)
    try:
        out = dotnet.find_dotnet_extractions({}, 7, storage=storage)
    finally:
        locked.chmod(0o700)
    assert [r["source_dir"] for r in out] == ["CAPE"], "the readable dir must still be scanned"
    assert any("cannot list" in r.getMessage() for r in caplog.records)


def test_non_regular_entries_in_an_extraction_dir_are_skipped(tmp_path):
    storage = _cape_task(tmp_path)
    d = storage / "7" / "procdump"
    os.mkfifo(d / "fifo")
    (d / "dangling").symlink_to(tmp_path / "nowhere")
    (d / "subdir").mkdir()
    (d / "net").write_bytes(pe(size=8192))
    with deadline():
        out = dotnet.find_dotnet_extractions({}, 7, storage=storage)
    assert [Path(r["path"]).name for r in out] == ["net"]
