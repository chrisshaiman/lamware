"""
Stage 4: Generic script/text analysis — catch-all for readable source files.

Handles any text-based sample that doesn't have a specialized handler
(PowerShell has PSDecode, Office has olevba, etc.). Reads the raw source
and sends it to the LLM for single-shot analysis and deobfuscation.

Covers: JavaScript (.js/.jse/.wsf), VBScript (.vbs/.vbe), batch (.bat/.cmd),
HTA (.hta), Python (.py), and any other readable text file.

Author: Christopher Shaiman
License: Apache 2.0
"""

import re
from pathlib import Path

# Max source size to send to LLM (chars)
MAX_SOURCE_SIZE = 50000

# Known script extensions — checked first for fast detection
SCRIPT_EXTENSIONS = {
    ".js", ".jse", ".wsf", ".wsh",       # JavaScript
    ".vbs", ".vbe", ".ws",               # VBScript
    ".bat", ".cmd",                       # Batch
    ".hta",                               # HTML Application
    ".py", ".pyw",                        # Python (standalone, not PyInstaller)
    ".rb",                                # Ruby
    ".pl", ".pm",                         # Perl
    ".sh", ".bash",                       # Shell
    ".lua",                               # Lua
}

# MIME types that indicate text/script content
TEXT_MIMES = {
    "text/plain", "text/html", "text/x-shellscript", "text/x-python",
    "text/x-perl", "text/x-ruby", "text/x-script.python",
    "application/javascript", "text/javascript", "application/x-javascript",
    "text/jscript", "application/x-msdos-program", "text/x-msdos-batch",
    "application/hta", "application/x-hta",
}


def _detect_script_language(name: str, file_type: str, file_mime: str,
                            source_head: str) -> str:
    """Identify the scripting language from available metadata."""
    name_lower = name.lower()

    # Extension-based
    if any(name_lower.endswith(ext) for ext in (".js", ".jse", ".wsf", ".wsh")):
        return "javascript"
    if any(name_lower.endswith(ext) for ext in (".vbs", ".vbe", ".ws")):
        return "vbscript"
    if any(name_lower.endswith(ext) for ext in (".bat", ".cmd")):
        return "batch"
    if name_lower.endswith(".hta"):
        return "hta"
    if any(name_lower.endswith(ext) for ext in (".py", ".pyw")):
        return "python"
    if any(name_lower.endswith(ext) for ext in (".sh", ".bash")):
        return "shell"

    # MIME-based
    if file_mime in ("application/javascript", "text/javascript"):
        return "javascript"
    if "batch" in file_type or "dos batch" in file_type:
        return "batch"

    # Content-based heuristics
    if source_head:
        if "WScript" in source_head or "ActiveXObject" in source_head:
            if "Sub " in source_head or "Dim " in source_head or "Function " in source_head:
                return "vbscript"
            return "javascript"
        if source_head.lstrip().startswith(("@echo", "rem ", "set ", "REM ")):
            return "batch"
        if source_head.lstrip().startswith(("<HTA:", "<html")):
            return "hta"
        if source_head.lstrip().startswith(("#!/", "import ", "def ", "class ")):
            return "python"

    return "unknown_script"


def is_text_script(report: dict, sample_path: Path = None) -> bool:
    """Detect text-based script files that should get LLM analysis.

    Returns True for any readable text file that wasn't already handled
    by a specialized stage (PowerShell, Office macros, PyInstaller).
    """
    triage = report.get("triage", {})
    file_type = triage.get("file_type", "").lower()
    file_mime = triage.get("file_mime", "")

    # Extension check
    name = report.get("sample_name", "").lower()
    if any(name.endswith(ext) for ext in SCRIPT_EXTENSIONS):
        return True

    # MIME type check
    if file_mime in TEXT_MIMES:
        return True

    # file_type string patterns
    script_keywords = ("javascript", "jscript", "vbscript", "batch",
                       "ascii text", "unicode text", "utf-8 text",
                       "script text")
    if any(kw in file_type for kw in script_keywords):
        return True

    # Last resort: try reading as text
    if sample_path and sample_path.exists():
        try:
            with sample_path.open("rb") as fh:
                head = fh.read(512)
                # Check if it's mostly printable ASCII/UTF-8
                printable = sum(1 for b in head if 32 <= b <= 126 or b in (9, 10, 13))
                if len(head) > 0 and printable / len(head) > 0.85:
                    return True
        except (OSError, PermissionError):
            pass

    return False


def read_script_source(sample_path: Path, report: dict) -> dict:
    """Read a text-based script file and extract metadata for LLM analysis.

    Returns a dict with source, language detection, size, and detected patterns.
    """
    result = {
        "analysis_success": False,
        "source": "",
        "source_language": "unknown_script",
        "file_size": 0,
        "detected_patterns": [],
    }

    if not sample_path or not sample_path.exists():
        result["error"] = f"File not found: {sample_path}"
        return result

    try:
        raw = sample_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        result["error"] = f"Failed to read file: {e}"
        return result

    triage = report.get("triage", {})
    name = report.get("sample_name", "")
    file_type = triage.get("file_type", "").lower()
    file_mime = triage.get("file_mime", "")

    result["file_size"] = len(raw)
    result["source"] = raw[:MAX_SOURCE_SIZE]
    result["source_language"] = _detect_script_language(
        name, file_type, file_mime, raw[:2000])
    if len(raw) > MAX_SOURCE_SIZE:
        result["truncated"] = True
        result["truncated_at"] = MAX_SOURCE_SIZE

    # Detect common malicious patterns across scripting languages
    pattern_checks = {
        "wscript_shell": r"WScript\.Shell|WScript\.CreateObject",
        "activex": r"ActiveXObject",
        "xmlhttp": r"XMLHTTP|WinHttp|ServerXMLHTTP",
        "adodb_stream": r"ADODB\.Stream",
        "filesystem": r"Scripting\.FileSystemObject|\.SaveToFile",
        "char_encoding": r"String\.fromCharCode|charCodeAt|unescape\(",
        "powershell_exec": r"powershell|pwsh",
        "cmd_exec": r"cmd\.exe|cmd\s+/c|WshShell\.Run",
        "registry": r"RegWrite|RegRead|HKCU|HKLM",
        "scheduled_task": r"schtasks|Schedule\.Service",
        "download": r"urlmon|URLDownloadToFile|Invoke-WebRequest|curl|wget",
        "base64": r"atob\(|btoa\(|base64|FromBase64",
        "shell_exec": r"Shell\.Application|ShellExecute",
        "process_create": r"Process\.Start|CreateProcess|subprocess",
    }
    result["detected_patterns"] = [
        name for name, pattern in pattern_checks.items()
        if re.search(pattern, raw[:MAX_SOURCE_SIZE], re.I)
    ]
    result["analysis_success"] = True
    return result
