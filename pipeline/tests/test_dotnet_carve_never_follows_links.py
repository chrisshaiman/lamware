# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The embedded-.NET carve never writes through a planted link and never outlives its analysis (#537).

Before this change Stage 4 carved to the fixed path
``/tmp/carved_dotnet_<name[:16]>.exe`` with a plain ``open("wb")``. Whoever could
write /tmp could plant that name as a symlink and have the pipeline user write
the sample's bytes wherever it pointed; two carves of names sharing 16
characters overwrote each other; and nothing ever deleted a carve.

These tests call the real functions on synthesized PE bytes (no sample binary
is committed) and look at the filesystem afterwards: the planted link's target
is byte-for-byte unchanged, every carve has its own private directory, and the
carves are gone after analysis whether it succeeded, failed or raised.
"""
import ast
import os
import stat
import threading
from pathlib import Path

import pytest
from stages import dotnet

ROOT = Path(__file__).resolve().parents[2]
RUN_PIPELINE = ROOT / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py"

VICTIM_BYTES = b"the pipeline user must never write here\n"


def pe(size: int = 4096) -> bytes:
    """A minimal PE32 header with a non-empty CLR directory (index 14)."""
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    e_lfanew = 0x80
    buf[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    opt = e_lfanew + 24
    buf[opt:opt + 2] = (0x10B).to_bytes(2, "little")
    buf[opt + 92:opt + 96] = (16).to_bytes(4, "little")
    clr = opt + 96 + 14 * 8
    buf[clr:clr + 8] = (0x2008).to_bytes(4, "little") + (0x48).to_bytes(4, "little")
    return bytes(buf)


def blob_with_embedded_pe(tag: bytes = b"\xAA") -> tuple[bytes, int]:
    """A >50 KB blob (pass 2's floor) with a .NET PE at a known offset."""
    at = 60_000
    return b"\0" * at + pe() + tag * 2000, at


@pytest.fixture
def victim(tmp_path) -> Path:
    v = tmp_path / "victim" / "authorized_keys"
    v.parent.mkdir()
    v.write_bytes(VICTIM_BYTES)
    return v


def _assert_untouched(victim: Path, link: Path) -> None:
    assert victim.read_bytes() == VICTIM_BYTES, "the carve was written through the planted symlink"
    assert link.is_symlink() and os.readlink(link) == str(victim), "the planted link was replaced"


def _cape_task(tmp_path: Path, files: dict[str, bytes]) -> Path:
    storage = tmp_path / "analyses"
    for d in ("procdump", "CAPE", "dropped"):
        (storage / "7" / d).mkdir(parents=True)
    for rel, data in files.items():
        (storage / "7" / rel).write_bytes(data)
    return storage


# ---------------------------------------------------------------------------
# A planted symlink is never followed
# ---------------------------------------------------------------------------

def test_a_symlink_at_the_old_fixed_path_is_not_followed(tmp_path, monkeypatch, victim):
    """The pre-#537 exploit, replayed: plant carved_dotnet_<name[:16]>.exe in the
    shared temp dir as a link to a file the attacker wants overwritten."""
    shared_tmp = tmp_path / "shared_tmp"
    shared_tmp.mkdir()
    monkeypatch.setattr(dotnet, "CARVE_DIR", shared_tmp)
    name = "f" * 64
    old_path = shared_tmp / f"carved_dotnet_{name[:16]}.exe"
    old_path.symlink_to(victim)
    blob, at = blob_with_embedded_pe()
    src = tmp_path / name
    src.write_bytes(blob)

    carved = dotnet._find_embedded_dotnet(src)

    _assert_untouched(victim, old_path)
    assert carved is not None and carved != old_path
    assert carved.read_bytes() == blob[at:]


def test_the_stage_entry_does_not_follow_a_link_at_the_old_path_either(tmp_path, monkeypatch, victim):
    """Same plant, through find_dotnet_extractions with the report dir Stage 4 passes:
    the carve lands under the report dir, and both candidate parents keep their link."""
    shared_tmp = tmp_path / "shared_tmp"
    shared_tmp.mkdir()
    monkeypatch.setattr(dotnet, "CARVE_DIR", shared_tmp)
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    name = "b" * 64
    blob, at = blob_with_embedded_pe()
    storage = _cape_task(tmp_path, {f"CAPE/{name}": blob})
    links = [d / f"carved_dotnet_{name[:16]}.exe" for d in (shared_tmp, report_dir)]
    for link in links:
        link.symlink_to(victim)

    out = dotnet.find_dotnet_extractions({}, 7, report_dir=report_dir, storage=storage)

    for link in links:
        _assert_untouched(victim, link)
    assert len(out) == 1
    carved = Path(out[0]["path"])
    assert carved.parent.parent == report_dir
    assert carved.read_bytes() == blob[at:]
    dotnet.remove_carves(out)


def test_a_symlink_at_the_new_carve_path_is_refused_not_followed(tmp_path, monkeypatch, victim):
    """Defence in depth: even if the private directory were predicted or shared,
    the file inside is opened O_EXCL|O_NOFOLLOW. Simulate that by handing the
    carve a directory where the link already waits at its exact file name."""
    raced = tmp_path / ".dotnet-carve-raced"
    raced.mkdir()
    name = "c" * 64
    link = raced / f"carved_dotnet_{name[:16]}.exe"
    link.symlink_to(victim)
    monkeypatch.setattr(dotnet.tempfile, "mkdtemp", lambda **_: str(raced))
    blob, _ = blob_with_embedded_pe()
    src = tmp_path / name
    src.write_bytes(blob)

    assert dotnet._find_embedded_dotnet(src, tmp_path) is None

    _assert_untouched(victim, link)


def test_a_regular_file_at_the_new_carve_path_is_not_overwritten(tmp_path, monkeypatch):
    """O_EXCL as well as O_NOFOLLOW: an existing file is an error, not a target."""
    raced = tmp_path / ".dotnet-carve-raced"
    raced.mkdir()
    name = "d" * 64
    existing = raced / f"carved_dotnet_{name[:16]}.exe"
    existing.write_bytes(VICTIM_BYTES)
    monkeypatch.setattr(dotnet.tempfile, "mkdtemp", lambda **_: str(raced))
    blob, _ = blob_with_embedded_pe()
    src = tmp_path / name
    src.write_bytes(blob)

    assert dotnet._find_embedded_dotnet(src, tmp_path) is None
    assert existing.read_bytes() == VICTIM_BYTES


def test_the_carve_is_private(tmp_path):
    """0700 directory, 0600 file: nobody else on the host reads or swaps it."""
    blob, _ = blob_with_embedded_pe()
    src = tmp_path / "blob"
    src.write_bytes(blob)
    carved = dotnet._find_embedded_dotnet(src, tmp_path)
    assert carved is not None
    assert carved.parent.parent == tmp_path
    assert carved.parent.name.startswith(".dotnet-carve-")
    assert stat.S_IMODE(carved.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(carved.lstat().st_mode) == 0o600
    assert dotnet._remove_carve(carved)


# ---------------------------------------------------------------------------
# Concurrent carves do not collide
# ---------------------------------------------------------------------------

def test_two_concurrent_carves_with_the_same_name_prefix_do_not_collide(tmp_path):
    """Two runs carving files whose names share 16 characters, at the same time,
    into the same parent: the fixed name made the second overwrite the first."""
    parent = tmp_path / "report"
    parent.mkdir()
    srcs = []
    for i, tag in enumerate((b"\x11", b"\x22")):
        blob, at = blob_with_embedded_pe(tag)
        d = tmp_path / f"run{i}"
        d.mkdir()
        f = d / ("e" * 64)     # identical names, different bytes
        f.write_bytes(blob)
        srcs.append((f, blob[at:]))
    barrier = threading.Barrier(len(srcs))
    carved: list[Path | None] = [None] * len(srcs)

    def carve(i: int) -> None:
        barrier.wait()
        carved[i] = dotnet._find_embedded_dotnet(srcs[i][0], parent)

    threads = [threading.Thread(target=carve, args=(i,)) for i in range(len(srcs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert all(c is not None for c in carved)
    assert carved[0] != carved[1] and carved[0].parent != carved[1].parent
    for c, (_, want) in zip(carved, srcs):
        assert c.read_bytes() == want, "one carve overwrote the other"


# ---------------------------------------------------------------------------
# The carve is removed after analysis, however the analysis ends
# ---------------------------------------------------------------------------

def _three_carves(tmp_path: Path) -> tuple[list[dict], Path]:
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    files = {}
    for i, d in enumerate(("procdump", "CAPE", "dropped")):
        blob, _ = blob_with_embedded_pe(bytes([0x30 + i]))
        files[f"{d}/{chr(0x61 + i) * 64}"] = blob + b"\0" * (i * 100)
    storage = _cape_task(tmp_path, files)
    out = dotnet.find_dotnet_extractions({}, 7, report_dir=report_dir, storage=storage)
    assert len(out) == 3 and all(Path(e["path"]).is_file() for e in out)
    return out, report_dir


def _no_carves_left(report_dir: Path, extractions: list[dict]) -> None:
    leftovers = [p.name for p in report_dir.iterdir() if p.name.startswith(".dotnet-carve-")]
    assert leftovers == [], f"carve directories left behind: {leftovers}"
    for ex in extractions:
        assert not os.path.lexists(ex["path"])
        assert ex["carve_removed"] is True


def test_carves_are_removed_after_a_failed_analysis(tmp_path):
    """The real run_dotnet_analysis, with a dotnet command that exits 1 and
    prints nothing — the shape of an ILSpy failure."""
    extractions, report_dir = _three_carves(tmp_path)
    cmd = tmp_path / "fake-dotnet"
    cmd.write_text("#!/bin/sh\necho boom >&2\nexit 1\n")
    cmd.chmod(0o755)

    result = dotnet.analyse_dotnet_extractions(extractions, report_dir, dotnet_cmd=str(cmd))

    assert result["analysis_success"] is False
    _no_carves_left(report_dir, extractions)
    src = result["extraction_source"]
    assert src["carved_to"].startswith(str(report_dir / ".dotnet-carve-"))
    assert src["carve_removed"] is True


def test_carves_are_removed_when_the_analysis_raises(tmp_path, monkeypatch):
    extractions, report_dir = _three_carves(tmp_path)

    def boom(*_a, **_k):
        raise RuntimeError("analysis blew up")

    monkeypatch.setattr(dotnet, "run_dotnet_analysis", boom)
    with pytest.raises(RuntimeError):
        dotnet.analyse_dotnet_extractions(extractions, report_dir, dotnet_cmd="unused")
    _no_carves_left(report_dir, extractions)


def test_the_analysis_sees_the_carve_and_it_is_removed_only_afterwards(tmp_path, monkeypatch):
    """Removal must come after the consumer, not before: the fake analysis
    records what was on disk when it ran."""
    extractions, report_dir = _three_carves(tmp_path)
    best = max(extractions, key=lambda x: x["size"])
    want = Path(best["path"]).read_bytes()
    seen = {}

    def fake(binary_path, output_dir, dotnet_cmd):
        seen["bytes"] = Path(binary_path).read_bytes()
        return {"analysis_success": True}

    monkeypatch.setattr(dotnet, "run_dotnet_analysis", fake)
    result = dotnet.analyse_dotnet_extractions(extractions, report_dir, dotnet_cmd="unused")

    assert seen["bytes"] == want
    assert result["analysis_success"] is True
    assert result["extraction_source"] is best
    _no_carves_left(report_dir, extractions)


def test_files_found_in_place_are_not_deleted(tmp_path, monkeypatch):
    """Pass 1 returns CAPE's and Volatility's own files; those are not carves."""
    storage = _cape_task(tmp_path, {"procdump/" + "a" * 64: pe(size=8192)})
    out = dotnet.find_dotnet_extractions({}, 7, storage=storage)
    assert len(out) == 1 and "carved_from" not in out[0]
    monkeypatch.setattr(dotnet, "run_dotnet_analysis", lambda *a, **k: {"analysis_success": True})
    dotnet.analyse_dotnet_extractions(out, tmp_path, dotnet_cmd="unused")
    assert Path(out[0]["path"]).is_file()
    assert "carve_removed" not in out[0]


def test_remove_carve_refuses_a_path_outside_a_carve_directory(tmp_path, victim):
    assert dotnet._remove_carve(victim) is False
    assert victim.read_bytes() == VICTIM_BYTES


def test_a_failed_copy_leaves_nothing_behind(tmp_path, monkeypatch):
    blob, _ = blob_with_embedded_pe()
    src = tmp_path / "blob"
    src.write_bytes(blob)
    parent = tmp_path / "report"
    parent.mkdir()

    def broken_copy(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(dotnet.shutil, "copyfileobj", broken_copy)
    assert dotnet._find_embedded_dotnet(src, parent) is None
    assert list(parent.iterdir()) == []


# ---------------------------------------------------------------------------
# Stage 4 uses the cleaning entry point
# ---------------------------------------------------------------------------

def test_stage4_hands_extractions_to_the_cleaning_entry_point():
    """Structural, by necessity: run-pipeline.py's Stage 4 cannot be called in
    isolation. Parsed with ast, not grepped: the value find_dotnet_extractions
    returns must reach analyse_dotnet_extractions, and no extraction's path may
    go to run_dotnet_analysis directly (that path skipped the cleanup)."""
    tree = ast.parse(RUN_PIPELINE.read_text(encoding="utf-8"))
    found_into: set[str] = set()
    analysed_with: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                and getattr(node.value.func, "id", None) == "find_dotnet_extractions":
            found_into |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "analyse_dotnet_extractions":
            analysed_with += [a.id for a in node.args[:1] if isinstance(a, ast.Name)]
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "run_dotnet_analysis":
            first = ast.unparse(node.args[0]) if node.args else ""
            assert "best" not in first and "extraction" not in first, (
                f"run_dotnet_analysis({first}, ...) analyses an extraction without removing carves")
    assert found_into and set(analysed_with) == found_into
