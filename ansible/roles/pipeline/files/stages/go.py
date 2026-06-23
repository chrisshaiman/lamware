"""
Stage 4 (Go): GoReSym analysis for Go binaries.

Detects Go binaries via file type and section names, then runs
GoReSym to extract function names, types, and build metadata.
Produces much better output than Ghidra for Go binaries since
GoReSym understands the pclntab metadata structure natively.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import subprocess
from pathlib import Path


GO_YARA_INDICATORS = [
    "golang", "go_binary", "gobinary", "goresym",
]


def is_go_binary(report: dict) -> bool:
    """Check if the sample is a Go binary based on triage data."""
    triage = report.get("triage", {})

    # Check file type — Go binaries often show "Go BuildID" in file output
    file_type = (triage.get("file_type", "") or "").lower()
    if "go buildid" in file_type:
        return True

    # Check YARA matches
    for match in triage.get("yara_matches", []):
        rule = match.get("rule", "").lower()
        if any(indicator in rule for indicator in GO_YARA_INDICATORS):
            return True

    # Check PE sections for Go-specific names
    sections = triage.get("sections", [])
    section_names = [s.get("name", "").lower() for s in sections if isinstance(s, dict)]
    go_sections = [".symtab", ".gopclntab", ".go.buildinfo"]
    if any(gs in section_names for gs in go_sections):
        return True

    return False


def run_go_analysis(binary_path: Path, output_dir: Path,
                    go_cmd: str, timeout: int = 120) -> dict:
    """Run GoReSym analysis on a Go binary.

    Returns structured JSON with function names, types, build info,
    and strings of interest.
    """
    try:
        result = subprocess.run(
            [go_cmd, str(binary_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"error": f"go analysis command not found: {go_cmd}",
                "analysis_success": False}
    except subprocess.TimeoutExpired:
        return {"error": f"go analysis timed out ({timeout}s)",
                "analysis_success": False}

    # Try parsing stdout as JSON first (GoReSym may return non-zero
    # for warnings while still producing valid output)
    try:
        output = json.loads(result.stdout)
        return output
    except json.JSONDecodeError:
        pass

    if result.returncode != 0:
        return {"error": f"go analysis failed: {result.stderr[:300]}",
                "analysis_success": False}

    return {"error": f"No valid JSON in go analysis output: {result.stdout[:200]}",
            "analysis_success": False}
