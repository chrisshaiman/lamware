"""
Stage 4 (PyInstaller): Extract and decompile PyInstaller executables.

Detects PyInstaller binaries via MEI magic bytes, YARA rules, or
file type strings, then runs pyinstxtractor + decompyle3 to recover
the original Python source code.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import logging
import subprocess
from pathlib import Path

from stages import peek

log = logging.getLogger("pipeline")

PYINSTALLER_YARA_INDICATORS = [
    "pyinstaller", "py_installer", "python_compiled",
]

# MEI magic bytes that identify PyInstaller archives
PYINSTALLER_MAGIC = b"MEI\014\013\012\013\016"

# How much of the end of an over-cap file the cookie scan also reads.
PYINSTALLER_TAIL = 1 << 20


def is_pyinstaller_binary(report: dict, sample_path: Path = None) -> bool:
    """Check if the sample is a PyInstaller executable."""
    triage = report.get("triage", {})

    # Check file type
    file_type = (triage.get("file_type", "") or "").lower()
    if "pyinstaller" in file_type:
        return True

    # Check YARA matches
    for match in triage.get("yara_matches", []):
        rule = match.get("rule", "").lower()
        if any(indicator in rule for indicator in PYINSTALLER_YARA_INDICATORS):
            return True

    # Check for MEI magic bytes in the binary. Streamed and capped (#677): this
    # used to read the whole sample into memory, so a large enough file raised
    # MemoryError out of Stage 4, and a FIFO or an unreadable parent directory
    # hung or raised before the read was attempted. The cookie sits at the end
    # of the archive (88-9,376 bytes from EOF in all 36 PyInstaller samples in
    # CAPE storage on 2026-10-03), so a file longer than the cap also has its
    # tail scanned.
    if sample_path:
        found, capped = peek.contains(sample_path, PYINSTALLER_MAGIC, tail=PYINSTALLER_TAIL)
        if capped:
            log.warning(f"  PyInstaller cookie scan of {Path(sample_path).name}: file is "
                        f"longer than the {peek.SCAN_CAP:#x}-byte scan cap; scanned the head "
                        f"and the last {PYINSTALLER_TAIL:#x} bytes only "
                        f"({'found' if found else 'not found'})")
        if found:
            return True

    return False


def run_pyinstaller_analysis(binary_path: Path, output_dir: Path,
                             pyinstaller_cmd: str, timeout: int = 120) -> dict:
    """Run PyInstaller extraction and decompilation.

    Returns structured JSON with decompiled Python source, bundled
    file list, and strings of interest.
    """
    try:
        result = subprocess.run(
            [pyinstaller_cmd, str(binary_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"error": f"pyinstaller analysis command not found: {pyinstaller_cmd}",
                "analysis_success": False}
    except subprocess.TimeoutExpired:
        return {"error": f"pyinstaller analysis timed out ({timeout}s)",
                "analysis_success": False}

    # Try parsing stdout as JSON first
    try:
        output = json.loads(result.stdout)
        return output
    except json.JSONDecodeError:
        pass

    if result.returncode != 0:
        return {"error": f"pyinstaller analysis failed: {result.stderr[:300]}",
                "analysis_success": False}

    return {"error": f"No valid JSON in pyinstaller output: {result.stdout[:200]}",
            "analysis_success": False}
