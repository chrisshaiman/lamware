"""PowerShell script detection, CAPE command extraction, and analysis execution.

Author: Christopher Shaiman
License: Apache 2.0
"""
import base64
import json
import logging
import os
import re
import subprocess
from pathlib import Path

log = logging.getLogger("pipeline")

POWERSHELL_YARA_INDICATORS = [
    "powershell", "ps1", "invoke_expression", "downloadstring",
    "encodedcommand", "empire", "cobaltstrike_ps",
]


def is_powershell_script(report: dict) -> bool:
    """Detect submitted PowerShell scripts."""
    triage = report.get("triage", {})
    file_type = (triage.get("file_type", "") or "").lower()

    # Extension check
    sample_name = report.get("sample_name", "")
    ps_exts = (".ps1", ".psm1", ".psd1")
    if sample_name.lower().endswith(ps_exts):
        return True

    # File type + content indicators
    if "text" in file_type or "script" in file_type or "ascii" in file_type:
        sample_path = report.get("_sample_path", "")
        if sample_path and os.path.isfile(sample_path):
            try:
                with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
                    head = f.read(2048).lower()
                ps_keywords = [
                    "param(", "function ", "[system.", "$env:",
                    "invoke-", "new-object", "set-variable",
                    "write-host", "get-content", "start-process",
                    "downloadstring", "downloadfile", "invoke-expression",
                    "[convert]::frombase64", "powershell",
                ]
                if sum(1 for kw in ps_keywords if kw in head) >= 2:
                    return True
            except Exception:
                pass

    # MIME type
    file_mime = (triage.get("file_mime", "") or "").lower()
    if "powershell" in file_mime:
        return True

    # YARA indicators
    for match in triage.get("yara_matches", []):
        rule = match.get("rule", "").lower()
        if any(ind in rule for ind in POWERSHELL_YARA_INDICATORS):
            return True

    return False


def extract_powershell_from_cape(report: dict) -> list[dict]:
    """Extract encoded PowerShell commands from CAPE process command lines.

    Scans all process command lines for powershell.exe invocations with
    encoding flags (-enc, -encodedcommand, -e) and decodes the base64 blob.

    Returns:
        List of dicts with keys: encoded, decoded, pid, command_line
    """
    cape = report.get("cape", {})
    cmdlines = cape.get("process_cmdlines", {})
    if not cmdlines:
        return []

    results = []
    enc_pattern = re.compile(
        r'(?:powershell|pwsh)(?:\.exe)?\s+.*?'
        r'-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+'
        r'([A-Za-z0-9+/=]{20,})',
        re.IGNORECASE,
    )

    for pid_str, cmdline in cmdlines.items():
        if not cmdline:
            continue
        match = enc_pattern.search(cmdline)
        if match:
            b64_blob = match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64_blob)
                decoded_text = decoded_bytes.decode("utf-16-le", errors="replace").strip('\x00')
                results.append({
                    "encoded": b64_blob[:500],
                    "decoded": decoded_text,
                    "pid": pid_str,
                    "command_line": cmdline[:500],
                })
            except Exception:  # nosec B112 - skip un-decodable base64/UTF-16 PowerShell blobs
                continue

    return results


def run_powershell_analysis(
    script_path: Path,
    output_dir: Path,
    powershell_cmd: str,
    timeout: int = 120,
) -> dict:
    """Run containerized PowerShell deobfuscation.

    Args:
        script_path: Path to the PowerShell script
        output_dir: Directory for output artifacts
        powershell_cmd: Path to the wrapper script
        timeout: Subprocess timeout in seconds

    Returns:
        dict with analysis results
    """
    try:
        proc = subprocess.run(
            [powershell_cmd, str(script_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd="/tmp",
        )
        if proc.returncode != 0:
            return {
                "analysis_success": False,
                "analysis_type": "powershell",
                "error": f"PowerShell analysis exited {proc.returncode}: {proc.stderr[:500]}",
            }
        result = json.loads(proc.stdout)
        return result
    except subprocess.TimeoutExpired:
        return {
            "analysis_success": False,
            "analysis_type": "powershell",
            "error": f"PowerShell analysis timed out after {timeout}s",
        }
    except json.JSONDecodeError as e:
        return {
            "analysis_success": False,
            "analysis_type": "powershell",
            "error": f"Failed to parse PowerShell analysis JSON: {e}",
        }
    except Exception as e:
        return {
            "analysis_success": False,
            "analysis_type": "powershell",
            "error": f"PowerShell analysis error: {e}",
        }
