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
from pathlib import Path

from stages import peek
from stages.peek import iter_chunks, open_regular, read_head, regular_size

log = logging.getLogger("pipeline")

CAPE_ANALYSES = Path("/opt/CAPEv2/storage/analyses")
CARVE_DIR = Path("/tmp")

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


def _find_embedded_dotnet(file_path: Path) -> Path | None:
    """Search a binary blob for an embedded .NET PE and carve it out.

    Returns path to carved PE in /tmp, or None if not found. The carve is the
    blob from the MZ to EOF, as before #677, copied in chunks rather than held
    in memory.
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
            carved_path = CARVE_DIR / f"carved_dotnet_{file_path.name[:16]}.exe"
            fh.seek(pos)
            with open(carved_path, "wb") as out:
                shutil.copyfileobj(fh, out, peek.CHUNK)
            return carved_path
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
    found, capped at MAX_DOTNET_EXTRACTIONS.
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
    if not results:
        for subdir_name, entries in listed:
            # Only check files > 50KB (plausible .NET payload size)
            large_files = sorted(
                [(e, s) for e, s in entries if s > 51200],
                key=lambda es: es[1],
                reverse=True,
            )
            for entry, _ in large_files[:10]:  # cap scan to 10 largest
                carved = _find_embedded_dotnet(entry)
                if carved:
                    carved_size = regular_size(carved)
                    if carved_size is None:
                        continue
                    results.append({
                        "path": str(carved),
                        "source_dir": subdir_name,
                        "sha256": entry.name,
                        "size": carved_size,
                        "carved_from": str(entry),
                    })
                    if len(results) >= MAX_DOTNET_EXTRACTIONS:
                        return results

    return results


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
