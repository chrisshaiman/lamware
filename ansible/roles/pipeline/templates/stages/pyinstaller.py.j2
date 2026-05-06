"""
Stage 4 (PyInstaller): Extract and decompile PyInstaller executables.

Detects PyInstaller binaries via MEI magic bytes, YARA rules, or
file type strings, then runs pyinstxtractor + decompyle3 to recover
the original Python source code.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import subprocess
from pathlib import Path


PYINSTALLER_YARA_INDICATORS = [
    "pyinstaller", "py_installer", "python_compiled",
]

# MEI magic bytes that identify PyInstaller archives
PYINSTALLER_MAGIC = b"MEI\014\013\012\013\016"


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

    # Check for MEI magic bytes in the binary
    if sample_path and sample_path.exists():
        try:
            with open(sample_path, "rb") as f:
                data = f.read()
            if PYINSTALLER_MAGIC in data:
                return True
        except OSError:
            pass

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
