"""
Stage 4 (.NET): ILSpy decompilation for .NET/MSIL binaries.

Detects .NET assemblies via YARA matches and file type, then runs
ILSpy to decompile to C# source code. Produces much better output
than Ghidra for .NET binaries since ILSpy understands IL natively.

Also scans Cape-extracted payloads for .NET binaries — handles
dropper scenarios where the original sample is native PE but the
payload extracted during detonation is .NET.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import logging
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from stages import peek
from stages.peek import iter_chunks, open_regular, read_head, regular_size

log = logging.getLogger("pipeline")

CAPE_ANALYSES = Path("/opt/CAPEv2/storage/analyses")

# Where a carve's private directory is made when the caller names no report
# directory. None is the system temp dir. Stage 4 always passes the report dir;
# this is the fallback, and the tests' override. Before #537 every carve went to
# the fixed path /tmp/carved_dotnet_<name[:16]>.exe, opened with a plain
# open("wb"): a symlink planted there was followed, so whoever could write /tmp
# chose where the pipeline user wrote the sample's bytes.
CARVE_DIR: Path | None = None

# Each carve gets its own directory from mkdtemp: a random name created with
# O_EXCL semantics, mode 0700. The prefix marks the directories _remove_carve
# may delete, so it can never be pointed at anything else.
_CARVE_PREFIX = ".dotnet-carve-"
_CARVE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

DOTNET_YARA_INDICATORS = [
    "isnet", "net_exe", "netexecutable", "msil", "dotnet", "csharp",
]

# Max number of extracted .NET payloads to analyze per run
MAX_DOTNET_EXTRACTIONS = 3


def is_dotnet_binary(report: dict) -> bool:
    """Check if the sample is a .NET assembly based on triage data."""
    triage = report.get("triage", {})

    # Check file type
    file_type = (triage.get("file_type", "") or "").lower()
    if "msil" in file_type or ".net" in file_type or "mono" in file_type:
        return True

    # Check YARA matches
    for match in triage.get("yara_matches", []):
        rule = match.get("rule", "").lower()
        if any(indicator in rule for indicator in DOTNET_YARA_INDICATORS):
            return True

    return False


def _clr_rva(view: bytes, max_e_lfanew: int | None = None) -> tuple[int, str]:
    """The CLR (COM descriptor) directory RVA of the PE header at ``view[0]``.

    ``view`` is every byte the check may read — the caller bounds it — and the
    function only peeks at fixed offsets and the one offset the header names
    (e_lfanew), as ADR-021 allows. It never raises: every offset is checked
    against ``len(view)`` before it is read, so a truncated or lying header is
    "not .NET" with a reason, never an IndexError or struct.error (#677).

    Returns ``(rva, why)``; ``rva`` 0 means "not a .NET PE".
    """
    if len(view) < 0x40:
        return 0, f"{len(view)} bytes is shorter than a DOS header"
    if view[:2] != b"MZ":
        return 0, "no MZ signature"
    pe = struct.unpack_from("<I", view, 0x3C)[0]
    if max_e_lfanew is not None and pe > max_e_lfanew:
        return 0, f"e_lfanew {pe:#x} is beyond {max_e_lfanew:#x}"
    if pe + 26 > len(view):
        return 0, f"e_lfanew {pe:#x} points past the {len(view)} bytes read"
    if view[pe:pe + 4] != b"PE\0\0":
        return 0, f"no PE signature at e_lfanew {pe:#x}"
    opt = pe + 24
    magic = struct.unpack_from("<H", view, opt)[0]
    if magic == 0x10B:  # PE32
        count_off, dirs_off = 92, 96
    elif magic == 0x20B:  # PE32+
        count_off, dirs_off = 108, 112
    else:
        return 0, f"optional header magic {magic:#x} is neither PE32 nor PE32+"
    clr = opt + dirs_off + 14 * 8
    if clr + 8 > len(view):
        return 0, f"the CLR directory entry at {clr:#x} is past the {len(view)} bytes read"
    # A header declaring fewer than 15 data directories has no CLR entry: the
    # bytes at its slot belong to whatever follows (the section table), and
    # reading them as an RVA called native PEs .NET. The CLR loader reads the
    # same count, so a real .NET assembly always declares the slot.
    count = struct.unpack_from("<I", view, opt + count_off)[0]
    if count < 15:
        return 0, f"NumberOfRvaAndSizes {count} declares no CLR directory"
    rva = struct.unpack_from("<I", view, clr)[0]
    return rva, ("CLR directory present" if rva else "CLR directory is empty")


def _has_clr_header(file_path: Path) -> bool:
    """Check if a PE file has a CLR runtime header (i.e., is .NET).

    Reads the first 1024 bytes only — a header whose e_lfanew points further
    is not found here, exactly as before #677; _find_embedded_dotnet looks
    further for blobs that pass 1 does not claim.
    """
    head = read_head(file_path, 1024)
    if head is None:
        return False
    rva, why = _clr_rva(head)
    if not rva:
        log.debug(f"  {file_path}: not .NET ({why})")
    return rva > 0


# The furthest byte past an MZ that the embedded check reads: e_lfanew is
# limited to 4096, then PE signature + COFF (24) + the PE32+ directory offset
# of the CLR entry (224) + the entry itself (8).
_CLR_WINDOW = 4096 + 24 + 224 + 8

# An attacker can fill a blob with "MZ" so every second byte is a candidate.
# On the host (2026-10-03) the densest real file seen had 16 per MiB (1,405 in
# a 92 MB sample; 218 in a 193 MB procdump), so this cap trips only on a file
# built to burn time — measured at 9.7 s per MiB of "MZ" before #677, when each
# candidate also copied the rest of the file.
MAX_MZ_CANDIDATES = 65536


def _embedded_clr_offset(fh, size: int, cap: int | None = None,
                         max_candidates: int | None = None) -> tuple[int | None, str | None]:
    """Offset of the first MZ in ``fh`` that heads a .NET PE, streaming.

    Same answer as the whole-file search it replaced — the first MZ, from the
    start, whose next _CLR_WINDOW bytes hold a PE header with a non-empty CLR
    directory, with at least 512 bytes from the MZ to EOF — but memory is one
    read chunk and the bytes read stop at ``cap``. The one deliberate
    difference is _clr_rva's NumberOfRvaAndSizes check. Compared on the host
    against every >50 KB file in CAPE storage and vol_procdump (1,967): the
    same offset for all of them.

    Returns ``(offset, None)`` when found, ``(None, why)`` when the scan stopped
    early (cap or candidate limit), ``(None, None)`` when it read everything.
    """
    cap = peek.SCAN_CAP if cap is None else cap
    max_candidates = MAX_MZ_CANDIDATES if max_candidates is None else max_candidates
    limit = min(size, cap)
    next_abs = 0
    candidates = 0
    for off, window in iter_chunks(fh, limit, _CLR_WINDOW):
        last = off + len(window) >= limit
        # A candidate needs its whole window in hand. Only at the true EOF is a
        # shorter view the real answer; at the cap it would be a truncated one.
        stop = len(window) if last and size <= cap else len(window) - _CLR_WINDOW
        p = max(0, next_abs - off)
        while stop > 0:
            p = window.find(b"MZ", p, stop + 1)
            if p == -1:
                break
            candidates += 1
            if candidates > max_candidates:
                return None, (f"stopped after {max_candidates} MZ candidates at offset "
                              f"{off + p:#x} of {size:#x}")
            view = window[p:p + _CLR_WINDOW]
            if len(view) >= 512 and _clr_rva(view, max_e_lfanew=4096)[0] > 0:
                return off + p, None
            p += 2
        next_abs = off + max(stop, 0)
        if last:
            break
    if size > cap:
        return None, f"scanned the first {cap:#x} of {size:#x} bytes (scan cap)"
    return None, None


def _write_carve(fh, pos: int, name: str, parent: Path | None) -> Path:
    """Copy ``fh`` from ``pos`` to EOF into a new private directory under ``parent``.

    The directory comes from mkdtemp (unpredictable, created exclusively, 0700)
    and the file inside is opened O_CREAT|O_EXCL|O_NOFOLLOW at 0600: an existing
    file or symlink at the path is an error, never a target (#537). On any
    failure, only what this call created is removed, and the error propagates.
    """
    carve_dir = Path(tempfile.mkdtemp(prefix=_CARVE_PREFIX, dir=parent))
    carved_path = carve_dir / f"carved_dotnet_{name[:16]}.exe"
    try:
        fd = os.open(carved_path, _CARVE_FLAGS, 0o600)
    except BaseException:
        # Not ours: whatever is at carved_path was there first. Leave it, and
        # leave a directory that is not empty.
        try:
            carve_dir.rmdir()
        except OSError:
            pass
        raise
    try:
        with os.fdopen(fd, "wb") as out:
            fh.seek(pos)
            shutil.copyfileobj(fh, out, peek.CHUNK)
    except BaseException:
        _remove_carve(carved_path)
        raise
    return carved_path


def _remove_carve(carved_path: Path) -> bool:
    """Delete a carve and the private directory _write_carve made for it.

    Returns True when neither is left. A path whose parent is not a carve
    directory is refused (False), so a wrong path can never remove anything else.
    """
    carve_dir = carved_path.parent
    if not carve_dir.name.startswith(_CARVE_PREFIX):
        log.warning(f"  not removing {carved_path}: not in a {_CARVE_PREFIX}* directory")
        return False
    # rmtree does not follow symlinks inside the tree; the directory is 0700
    # and ours, so nothing else should be in it, but nothing in it survives.
    shutil.rmtree(carve_dir, ignore_errors=True)
    if os.path.lexists(carve_dir):
        log.warning(f"  could not remove the .NET carve directory {carve_dir}")
        return False
    return True


def _find_embedded_dotnet(file_path: Path, carve_parent: Path | None = None) -> Path | None:
    """Search a binary blob for an embedded .NET PE and carve it out.

    Returns the path of the carve — in a new private directory under
    ``carve_parent`` (else CARVE_DIR, else the system temp dir) — or None if
    there is none. The carve is the blob from the MZ to EOF, as before #677,
    copied in chunks rather than held in memory. The caller owns the carve and
    removes it with _remove_carve (remove_carves) once it has been analysed.
    """
    fh = open_regular(file_path)
    if fh is None:
        return None
    try:
        with fh:
            size = os.fstat(fh.fileno()).st_size
            pos, stopped = _embedded_clr_offset(fh, size)
            if pos is None:
                if stopped:
                    log.warning(f"  embedded .NET scan of {file_path.name}: {stopped}; "
                                f"the rest of the file was not searched")
                return None
            parent = carve_parent if carve_parent is not None else CARVE_DIR
            return _write_carve(fh, pos, file_path.name, parent)
    except OSError as e:
        log.warning(f"  embedded .NET scan of {file_path.name} failed: {e}")
        return None


def _regular_entries(subdir: Path) -> list[tuple[Path, int]]:
    """(path, size) for each regular file in ``subdir``, symlinks followed.

    An unreadable directory, or an entry that vanishes or cannot be stat'ed,
    is logged and skipped: before #677 the PermissionError from iterdir() or
    stat() left Stage 4 and took the run with it.
    """
    try:
        names = sorted(subdir.iterdir())
    except OSError as e:
        log.warning(f"  cannot list {subdir}: {e}; not scanning it for .NET")
        return []
    out = []
    for entry in names:
        size = regular_size(entry)
        if size is not None:
            out.append((entry, size))
    return out


def find_dotnet_extractions(cape_data: dict, cape_task_id: int | str | None,
                            report_dir: Path | None = None,
                            storage: Path = CAPE_ANALYSES) -> list[dict]:
    """Scan Cape extraction directories and Volatility procdumps for .NET binaries.

    Checks procdump/, CAPE/, dropped/ in the Cape storage, plus vol_procdump/
    in the pipeline report directory. First checks for proper PE files with
    CLR headers, then scans larger blobs for embedded .NET PEs.

    Returns a list of dicts with path and metadata for each .NET binary
    found, capped at MAX_DOTNET_EXTRACTIONS. A carved entry (``carved_from``
    set) is a file this call wrote, in a private directory under ``report_dir``
    when given; the caller must hand the list to remove_carves (as
    analyse_dotnet_extractions does) once it is done with them.
    """
    results = []

    # Build list of directories to scan
    scan_dirs: list[tuple[str, Path]] = []
    if report_dir:
        vol_procdump = report_dir / "vol_procdump"
        if vol_procdump.is_dir():
            scan_dirs.append(("vol_procdump", vol_procdump))
    if cape_task_id:
        base_dir = storage / str(cape_task_id)
        for subdir_name in ["procdump", "CAPE", "dropped"]:
            subdir = base_dir / subdir_name
            if subdir.is_dir():
                scan_dirs.append((subdir_name, subdir))

    if not scan_dirs:
        return []

    listed = [(name, _regular_entries(subdir)) for name, subdir in scan_dirs]

    # Pass 1: check for proper PE files with CLR headers
    for subdir_name, entries in listed:
        for entry, size in entries:
            if size < 4096:
                continue
            if _has_clr_header(entry):
                results.append({
                    "path": str(entry),
                    "source_dir": subdir_name,
                    "sha256": entry.name,
                    "size": size,
                })
                if len(results) >= MAX_DOTNET_EXTRACTIONS:
                    return results

    # Pass 2: scan large blobs for embedded .NET PEs (dropper payloads)
    # Every carve in results is a file on disk; an exception out of this loop
    # would leave them there with nobody holding the list, so remove them first.
    try:
        if not results:
            for subdir_name, entries in listed:
                # Only check files > 50KB (plausible .NET payload size)
                large_files = sorted(
                    [(e, s) for e, s in entries if s > 51200],
                    key=lambda es: es[1],
                    reverse=True,
                )
                for entry, _ in large_files[:10]:  # cap scan to 10 largest
                    carved = _find_embedded_dotnet(entry, report_dir)
                    if carved:
                        carved_size = regular_size(carved)
                        if carved_size is None:
                            _remove_carve(carved)
                            continue
                        results.append({
                            "path": str(carved),
                            "source_dir": subdir_name,
                            "sha256": entry.name,
                            "size": carved_size,
                            "carved_from": str(entry),
                            "carved_to": str(carved.parent),
                        })
                        if len(results) >= MAX_DOTNET_EXTRACTIONS:
                            return results
    except BaseException:
        remove_carves(results)
        raise

    return results


def remove_carves(extractions: list[dict]) -> None:
    """Delete every carve in ``extractions``; record ``carve_removed`` on each.

    Entries that are not carves (pass 1 found the file as CAPE or Volatility
    wrote it) are left alone: those files are not the pipeline's to delete.
    """
    for ex in extractions:
        if ex.get("carved_from"):
            ex["carve_removed"] = _remove_carve(Path(ex["path"]))


def analyse_dotnet_extractions(extractions: list[dict], output_dir: Path,
                               dotnet_cmd: str) -> dict:
    """Run ILSpy on the largest extraction, then delete every carve.

    The carves are removed in a ``finally``: an analysis that fails, times out
    or raises still leaves no sample bytes behind. The dotnet-analysis wrapper
    copies its input into its own mktemp directory and mounts that, so once
    run_dotnet_analysis returns nothing reads the carve again. The result's
    ``extraction_source`` records where the carve was written and whether it
    was removed.
    """
    best = max(extractions, key=lambda x: x["size"])
    log.info(f"  Analyzing: {best['source_dir']}/{best['sha256'][:16]}... ({best['size']} bytes)")
    try:
        result = run_dotnet_analysis(Path(best["path"]), output_dir, dotnet_cmd=dotnet_cmd)
    finally:
        remove_carves(extractions)
    result["extraction_source"] = best
    return result


def run_dotnet_analysis(binary_path: Path, output_dir: Path,
                        dotnet_cmd: str, timeout: int = 120) -> dict:
    """Run ILSpy decompilation on a .NET assembly.

    Returns structured JSON with decompiled C# source, class listing,
    and extracted strings of interest.
    """
    try:
        result = subprocess.run(
            [dotnet_cmd, str(binary_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"error": f"dotnet analysis command not found: {dotnet_cmd}",
                "analysis_success": False}
    except subprocess.TimeoutExpired:
        return {"error": f"dotnet analysis timed out ({timeout}s)",
                "analysis_success": False}

    # Try parsing stdout as JSON first — de4dotEx may return non-zero
    # for "Unknown Obfuscator" even when deobfuscation succeeded.
    try:
        output = json.loads(result.stdout)
        return output
    except json.JSONDecodeError:
        pass

    if result.returncode != 0:
        return {"error": f"dotnet analysis failed: {result.stderr[:300]}",
                "analysis_success": False}

    return {"error": f"No valid JSON in dotnet output: {result.stdout[:200]}",
            "analysis_success": False}
