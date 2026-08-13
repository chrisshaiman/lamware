"""
Stage 4: Ghidra headless static analysis — decompilation of dropped PEs
and shellcode candidates.

SECURITY: When Ghidra output is later sent to an LLM for interpretation,
all strings/code from the binary are adversary-controlled. The LLM
interpretation layer must:
  1. Treat all decompiled code as untrusted (UNTRUSTED_CODE delimiters)
  2. Never let LLM output modify verdicts or trigger pipeline actions
  3. Log raw prompts and responses for audit
  4. Use triage/Cape/Volatility for maliciousness — Ghidra+LLM for understanding

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import subprocess
from pathlib import Path

from lamware_shared.cape_payloads import CAPE_STORAGE, find_pe_payloads

from stages.volatility import extract_shellcode_artifacts

# Cape signatures that indicate dropped/unpacked payloads worth analyzing
GHIDRA_TRIGGERS = [
    "packed_binary",
    "injection_write_process",
    "injection_rwx",
    "reflective_dll_loading",
    "shellcode_execution",
    "drops_exe",
    "creates_exe",
]


def get_dropped_pe_files(cape_data: dict,
                         storage: Path = CAPE_STORAGE) -> list[Path]:
    """Find PE files Cape extracted during detonation.

    Looks across every Cape extraction directory, not just ``dropped/`` —
    which this deployment never writes to, so this function returned an empty
    list for every analysis until #377. Ordered so the caller's ``[:5]`` cap
    keeps Cape's unpacked extractions ahead of raw process dumps.
    """
    task_id = cape_data.get("id") or cape_data.get("task_id")
    return [p.path for p in find_pe_payloads(task_id, storage=storage)]


def get_original_sample_path(cape_data: dict,
                             storage: Path = CAPE_STORAGE) -> Path | None:
    """Get the original submitted sample from Cape's storage."""
    task_id = cape_data.get("id") or cape_data.get("task_id")
    if not task_id:
        return None
    binary_path = storage / str(task_id) / "binary"
    if not binary_path.exists():
        return None
    # Check if it's a PE
    try:
        with binary_path.open("rb") as fh:
            if fh.read(2) == b"MZ":
                return binary_path
    except (OSError, PermissionError):
        pass
    return None


def _is_ghidra_compatible_binary(sample_path: Path) -> bool:
    """Check if the sample is a binary format Ghidra can analyze (PE, ELF, Mach-O)."""
    if not sample_path or not sample_path.exists():
        return False
    try:
        with sample_path.open("rb") as fh:
            magic_bytes = fh.read(4)
            # PE (MZ header)
            if magic_bytes[:2] == b"MZ":
                return True
            # ELF
            if magic_bytes == b"\x7fELF":
                return True
            # Mach-O (32/64-bit, big/little-endian)
            if magic_bytes in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                               b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                return True
    except (OSError, PermissionError):
        pass
    return False


def should_run_ghidra(cape_data: dict, sample_path: Path, ghidra_cmd: str,
                      get_cape_signatures_fn,
                      storage: Path = CAPE_STORAGE) -> bool:
    """Check if Ghidra analysis should run.

    Triggers when:
    1. Cape found dropped PEs + injection/packing signatures, OR
    2. The original sample is a Ghidra-compatible binary (PE, ELF, Mach-O)
    """
    if not Path(ghidra_cmd).exists():
        return False

    # Non-Windows binary with no CAPE data — still analyze with Ghidra
    if cape_data.get("status") in ("skipped", None, ""):
        return _is_ghidra_compatible_binary(sample_path)

    if cape_data.get("status") != "reported":
        return False

    sigs = get_cape_signatures_fn(cape_data)
    has_trigger = any(sig in GHIDRA_TRIGGERS for sig in sigs)
    has_dropped_pes = len(get_dropped_pe_files(cape_data, storage)) > 0
    original_is_pe = get_original_sample_path(cape_data, storage) is not None

    # Also check the submitted sample directly (CAPE storage may have corrupt binary)
    if not original_is_pe:
        original_is_pe = _is_ghidra_compatible_binary(sample_path)

    # Dropped PEs with trigger signatures — highest value analysis
    if has_trigger and has_dropped_pes:
        return True
    # Original sample is a compatible binary — analyze even without dropped files
    if original_is_pe:
        return True

    return False


def run_ghidra_on_file(pe_path: Path, output_dir: Path,
                       ghidra_cmd: str) -> dict:
    """Run Ghidra headless on a single PE file."""
    try:
        result = subprocess.run(
            [ghidra_cmd, str(pe_path), str(output_dir)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:200], "filename": pe_path.name}
        output = json.loads(result.stdout)
        return output
    except subprocess.TimeoutExpired:
        return {"error": "timeout (600s)", "filename": pe_path.name}
    except json.JSONDecodeError:
        return {"error": "invalid JSON output", "filename": pe_path.name,
                "raw": result.stdout[:500]}


def run_ghidra_shellcode(candidate: dict, output_dir: Path,
                         ghidra_cmd: str) -> dict:
    """Run artifact extraction and optionally Ghidra on a shellcode candidate.

    For Cape injection buffers, artifacts may already be extracted (in
    candidate["shellcode_artifacts"]). Ghidra only runs if the candidate
    is >= 1KB (candidate["analyze_with_ghidra"] == True or not set).
    """
    dump_path = Path(candidate["path"])
    base_addr = candidate.get("start_vpn", candidate.get("injection_address", "0x0"))
    if isinstance(base_addr, int):
        base_addr = f"0x{base_addr:x}"
    source = candidate.get("source", "malfind_injection")
    sc_output = output_dir / f"shellcode_{candidate['pid']}_{str(base_addr).replace('0x', '')}"

    # Use pre-extracted artifacts from Cape, or extract from dump file
    artifacts = candidate.get("shellcode_artifacts")
    if not artifacts:
        artifacts = extract_shellcode_artifacts(dump_path)
    if artifacts:
        api_count = len(artifacts.get("resolved_apis", []))
        path_count = len(artifacts.get("file_paths", []))
        dll_count = len(artifacts.get("dll_names", []))
        has_pe = artifacts.get("embedded_pe", False)
        print(f"      Artifacts: {api_count} APIs, {path_count} paths, {dll_count} DLLs, PE={has_pe}")

    # Small buffers (< 1KB): artifact extraction only, skip Ghidra
    if candidate.get("analyze_with_ghidra") is False:
        result = {
            "source": source,
            "pid": candidate.get("pid"),
            "process": candidate.get("process"),
            "injection_address": base_addr,
            "region_size": candidate.get("region_size") or candidate.get("size"),
            "filter_score": candidate.get("score", 0),
            "analysis_success": False,
            "functions_count": 0,
            "note": f"Artifact extraction only ({candidate.get('region_size', candidate.get('size', 0))} bytes, < 1KB threshold)",
        }
        if candidate.get("source_process"):
            result["source_process"] = candidate["source_process"]
            result["source_pid"] = candidate.get("source_pid")
        if artifacts:
            result["shellcode_artifacts"] = artifacts
        return result

    try:
        result = subprocess.run(
            [ghidra_cmd, "--shellcode", str(dump_path), str(sc_output), str(base_addr)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            return {
                "source": "malfind_injection",
                "pid": candidate.get("pid"),
                "process": candidate.get("process"),
                "injection_address": base_addr,
                "region_size": candidate.get("size"),
                "filter_score": candidate.get("score"),
                "shellcode_artifacts": artifacts or {},
                "error": result.stderr[:200],
            }
        analysis = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {
            "source": "malfind_injection",
            "pid": candidate.get("pid"),
            "process": candidate.get("process"),
            "injection_address": base_addr,
            "shellcode_artifacts": artifacts or {},
            "error": "timeout (300s)",
        }
    except json.JSONDecodeError:
        return {
            "source": "malfind_injection",
            "pid": candidate.get("pid"),
            "process": candidate.get("process"),
            "injection_address": base_addr,
            "shellcode_artifacts": artifacts or {},
            "error": "invalid JSON from Ghidra",
        }

    analysis["source"] = source
    analysis["pid"] = candidate.get("pid")
    analysis["process"] = candidate.get("process")
    analysis["injection_address"] = base_addr
    analysis["region_size"] = candidate.get("region_size") or candidate.get("size")
    analysis["filter_score"] = candidate.get("score", 0)
    if candidate.get("source_process"):
        analysis["source_process"] = candidate["source_process"]
        analysis["source_pid"] = candidate.get("source_pid")
    if artifacts:
        analysis["shellcode_artifacts"] = artifacts

    return analysis


def propagate_project_dir(analyzed_files: list[dict],
                          output_dir: Path) -> tuple[str | None, str | None]:
    """Resolve the canonical host project_dir/program_name for the interpret stage.

    run-ghidra.py runs *inside* the container and records the container mount
    path ("/output/project") on every per-file result. The wrapper copies the
    container's /output/* to ``output_dir`` on the host, so the persisted
    project actually lives at ``output_dir/project``.

    This finds the first successfully analyzed file, returns the host project
    path and its program name, and — critically — rewrites that file's
    ``project_dir`` to the host path in place. Downstream consumers (the
    interpret broker at run-pipeline's native-PE path passes this exact dict to
    ``run_ghidra_tool``, which shells out to run-ghidra on the HOST) would
    otherwise inherit "/output/project" and fail every tool call with
    "realpath: No such file or directory".

    Returns (None, None) if no successful analysis produced a project.
    """
    for af in analyzed_files:
        if af.get("analysis_success") and af.get("project_dir"):
            host_project = str(output_dir / "project")
            af["project_dir"] = host_project
            return host_project, af.get("program_name", "")
    return None, None


def run_ghidra(cape_data: dict, output_dir: Path, sample_path: Path,
               ghidra_cmd: str, get_cape_signatures_fn,
               shellcode_candidates: list[dict] | None = None,
               storage: Path = CAPE_STORAGE) -> dict:
    """Run Ghidra headless on dropped PEs and/or the original sample."""
    pe_files = get_dropped_pe_files(cape_data, storage)
    original_pe = get_original_sample_path(cape_data, storage)

    # If no dropped PEs, analyze the original sample
    if not pe_files and original_pe:
        pe_files = [original_pe]
        trigger_reason = "original_sample_is_pe"
    elif pe_files:
        trigger_reason = "dropped_pe_with_signatures"
    else:
        return {"triggered": True, "error": "no PE files found"}

    sigs = get_cape_signatures_fn(cape_data)
    trigger_sigs = [s for s in sigs if s in GHIDRA_TRIGGERS]

    result = {
        "triggered": True,
        "trigger_reason": trigger_reason,
        "trigger_signatures": trigger_sigs,
        "analyzed_files": [],
    }

    # Analyze up to 5 dropped PEs (avoid spending hours on prolific droppers)
    for pe_path in pe_files[:5]:
        print(f"    Analyzing {pe_path.name}...")
        file_result = run_ghidra_on_file(pe_path, output_dir, ghidra_cmd)
        result["analyzed_files"].append(file_result)

    # Analyze shellcode candidates from malfind
    if shellcode_candidates:
        print(f"    Analyzing {len(shellcode_candidates)} shellcode candidates...")
        for candidate in shellcode_candidates:
            print(f"    Shellcode: pid={candidate.get('pid', '?')} {candidate.get('process', '?')} score={candidate.get('score', '-')} source={candidate.get('source', '?')} size={candidate.get('region_size', candidate.get('size', '?'))}")
            sc_result = run_ghidra_shellcode(candidate, output_dir, ghidra_cmd)
            result["analyzed_files"].append(sc_result)

    # Propagate project_dir and program_name from the first successful
    # analysis to the top-level result — the interpret stage needs these to
    # broker tool calls back to Ghidra. This also normalizes the per-file
    # project_dir from the container mount path to the host path (see
    # propagate_project_dir); the native-PE interpret path brokers off that
    # per-file dict, so leaving it as "/output/project" breaks every tool call.
    project_dir, program_name = propagate_project_dir(result["analyzed_files"], output_dir)
    if project_dir:
        result["project_dir"] = project_dir
        result["program_name"] = program_name

    return result
