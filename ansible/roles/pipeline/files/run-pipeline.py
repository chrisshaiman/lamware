#!/opt/pipeline/venv/bin/python
"""
Pipeline orchestrator — runs the five-stage malware analysis pipeline.

Stage 1: Triage (always) — containerized YARA/ssdeep/FLOSS via run-triage
Stage 2: Dynamic (always) — submit to Cape API, poll until complete
Stage 3: Memory forensics (triggered) — Volatility 3
Stage 4: Static deep-dive (triggered) — Ghidra headless on dropped PEs
Stage 4.5: LLM interpretation (optional) — agentic Claude analysis of Ghidra output

Usage:
  run-pipeline <sample_path>
  run-pipeline <sample_path> --task-id <id>

Output: /opt/pipeline/reports/<task_id>/report.json

Author: Christopher Shaiman
License: Apache 2.0
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from stages.triage import run_triage, derive_tags_from_triage, derive_package_from_triage
from stages.cape import (
    derive_filename, submit_to_cape, poll_cape_task,
    get_cape_signatures, extract_cape_intel,
)
from stages.volatility import (
    should_run_volatility, run_volatility, extract_shellcode_artifacts,
)
from stages.pcap import get_cape_pcap, run_pcap_analysis
from stages.dotnet import is_dotnet_binary, find_dotnet_extractions, run_dotnet_analysis
from stages.go import is_go_binary, run_go_analysis
from stages.pyinstaller import is_pyinstaller_binary, run_pyinstaller_analysis
from stages.java import is_java_binary, run_java_analysis
from stages.office import is_office_document, run_office_analysis
from stages.powershell import is_powershell_script, extract_powershell_from_cape, run_powershell_analysis
from stages.script_analysis import is_text_script, read_script_source
from stages.ghidra import should_run_ghidra, run_ghidra
from stages.interpret import run_interpret, run_summarize, run_plain_english
from ioc_extract import extract_iocs, map_iocs_to_techniques
from db_ingest import ingest_to_db, mark_pdf_generated
from pipeline_status import create_analysis_row, update_stage, complete_pipeline
from lamware_pipeline.config import PipelineConfig
from lamware_pipeline.correlation import (
    build_mitre_mapping,
    calculate_severity,
    cross_correlate,
    determine_family,
)


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

log = logging.getLogger("pipeline")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging to stderr. Call add_file_logging() later for per-task log files."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s %(levelname)s %(message)s"
    datefmt = "%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt,
                        handlers=[logging.StreamHandler(sys.stderr)])


def add_file_logging(log_dir: Path) -> None:
    """Add a per-task file handler once the output directory is known."""
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_dir / "pipeline.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                                           datefmt="%H:%M:%S"))
    logging.getLogger().addHandler(handler)


# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------
# Non-secret values come from config.json (rendered by Ansible from config.json.j2)
# via PipelineConfig. CAPE_API_KEY is the one secret — it comes from the environment
# (the run-pipeline wrapper sources /opt/pipeline/pipeline.env; for a direct/local run,
# export CAPE_API_KEY yourself). main() guards a live run when it is unset.

CAPE_API_KEY = os.environ.get("CAPE_API_KEY", "")

_PIPELINE_CONFIG = PipelineConfig.load(
    os.environ.get("LAMWARE_PIPELINE_CONFIG", "/opt/pipeline/config.json")
)

# Analysis-tool command paths
CAPE_API_URL = _PIPELINE_CONFIG.cape_api_url
TRIAGE_CMD = _PIPELINE_CONFIG.triage_cmd
VOLATILITY_CMD = _PIPELINE_CONFIG.volatility_cmd
GHIDRA_CMD = _PIPELINE_CONFIG.ghidra_cmd
DOTNET_CMD = _PIPELINE_CONFIG.dotnet_cmd
GO_CMD = _PIPELINE_CONFIG.go_cmd
PYINSTALLER_CMD = _PIPELINE_CONFIG.pyinstaller_cmd
JAVA_CMD = _PIPELINE_CONFIG.java_cmd
OFFICE_CMD = _PIPELINE_CONFIG.office_cmd
POWERSHELL_CMD = _PIPELINE_CONFIG.powershell_cmd
SCREENSHOT_CMD = _PIPELINE_CONFIG.screenshot_cmd
PDF_CMD = _PIPELINE_CONFIG.pdf_cmd
INTERPRET_CMD = _PIPELINE_CONFIG.interpret_cmd
PCAP_CMD = _PIPELINE_CONFIG.pcap_cmd

# Interpret (LLM stage) — scalars + the INTERPRET_CONFIG dict (from the nested submodel)
INTERPRET_ENABLED = _PIPELINE_CONFIG.interpret_enabled
INTERPRET_TIMEOUT = _PIPELINE_CONFIG.interpret_timeout
INTERPRET_CONFIG = _PIPELINE_CONFIG.interpret.model_dump()

# Cape + report-output scalars
REPORTS_DIR = Path(_PIPELINE_CONFIG.reports_dir)
CAPE_POLL_INTERVAL = _PIPELINE_CONFIG.cape_poll_interval
CAPE_TIMEOUT = _PIPELINE_CONFIG.cape_timeout

# Malfind shellcode analysis config (Phase 1)
MALFIND_ENABLED = _PIPELINE_CONFIG.malfind_enabled
MALFIND_MAX_CANDIDATES = _PIPELINE_CONFIG.malfind_max_candidates
MALFIND_MIN_SIZE = _PIPELINE_CONFIG.malfind_min_size
MALFIND_MAX_SIZE = _PIPELINE_CONFIG.malfind_max_size
MALFIND_MIN_SCORE = _PIPELINE_CONFIG.malfind_min_score
MALFIND_BENIGN_PROCESSES = _PIPELINE_CONFIG.malfind_benign_processes

# PCAP analysis config
PCAP_ENABLED = _PIPELINE_CONFIG.pcap_enabled
PCAP_TIMEOUT = _PIPELINE_CONFIG.pcap_timeout

# Evasion hunter — LLM analysis of low-activity samples
EVASION_HUNTER_ENABLED = _PIPELINE_CONFIG.evasion_hunter_enabled
EVASION_MAX_SIGNATURES = _PIPELINE_CONFIG.evasion_max_signatures
EVASION_MIN_BINARY_SIZE = _PIPELINE_CONFIG.evasion_min_binary_size

# Volatility performance — ramdisk and parallel execution
VOLATILITY_RAMDISK = _PIPELINE_CONFIG.volatility_ramdisk
VOLATILITY_PARALLEL_WORKERS = _PIPELINE_CONFIG.volatility_parallel_workers

# Volatility trigger signatures — Cape signature names that trigger Stage 3
VOLATILITY_TRIGGERS = _PIPELINE_CONFIG.volatility_triggers

# Standard Volatility plugins (always run when triggered)
VOLATILITY_STANDARD_PLUGINS = [
    "windows.psscan",
    "windows.pstree",
    "windows.malfind",
    "windows.cmdline",
    "windows.netscan",
    "windows.dlllist",
]

# Extra plugins mapped by trigger category
VOLATILITY_EXTRA_PLUGINS = _PIPELINE_CONFIG.volatility_extra_plugins


# -------------------------------------------------------------------------
# Report output
# -------------------------------------------------------------------------

def write_report(task_id: str, report: dict, reports_dir: Path) -> Path:
    """Write merged report to disk."""
    report_dir = reports_dir / task_id
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"
    with report_path.open("w") as f:
        json.dump(report, f, indent=2, default=str)
    return report_path


# -------------------------------------------------------------------------
# Main pipeline
# -------------------------------------------------------------------------

def run_pipeline(sample_path: Path, task_id: str, original_name: str = "",
                  bazaar_family: str = "") -> dict:
    """Execute the multi-stage malware analysis pipeline."""
    import time as _time
    pipeline_start = _time.time()
    stage_timings = {}
    if bazaar_family:
        log.info(f"  MalwareBazaar family: {bazaar_family}")

    # Create DB row at pipeline start for real-time status tracking
    analysis_id_early = create_analysis_row(task_id, str(sample_path),
                                            filename=original_name)

    def stage_timer(name):
        """Context manager to time a pipeline stage and update status."""
        class Timer:
            def __enter__(self):
                self.start = _time.time()
                update_stage(analysis_id_early, name, "started")
                return self
            def __exit__(self, exc_type, exc_val, *args):
                elapsed = _time.time() - self.start
                stage_timings[name] = round(elapsed, 1)
                if exc_type:
                    update_stage(analysis_id_early, name, "failed",
                                detail=str(exc_val)[:200])
                    log.info(f"  [{name} FAILED in {elapsed:.0f}s]")
                else:
                    update_stage(analysis_id_early, name, "completed",
                                detail=f"{elapsed:.0f}s")
                    log.info(f"  [{name} completed in {elapsed:.0f}s]")
        return Timer()

    report = {
        "task_id": task_id,
        "sample": str(sample_path),
        "sample_name": original_name or sample_path.name,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "bazaar_family": bazaar_family,
    }

    output_dir = REPORTS_DIR / task_id
    output_dir.mkdir(parents=True, exist_ok=True)
    add_file_logging(output_dir)

    # Stage 1: Triage (always)
    log.info(f"\n[Stage 1] Triage: {report['sample_name']}")
    with stage_timer("triage"):
        triage_result = run_triage(sample_path, output_dir, triage_cmd=TRIAGE_CMD)
        report.update(triage_result)
        cape_tags = derive_tags_from_triage(triage_result)
        cape_package = derive_package_from_triage(triage_result, filename=original_name or sample_path.name)
        cape_filename = derive_filename(sample_path, cape_package, original_name)
        log.info(f"  Tags: {cape_tags}")
        if cape_package:
            log.info(f"  Package: {cape_package}")
        log.info(f"  Filename: {cape_filename}")

    # Stage 2: Cape — skip for non-Windows binaries (ELF, Mach-O)
    _triage_mime = report.get("triage", {}).get("file_mime", "")
    _triage_ftype = report.get("triage", {}).get("file_type", "").lower()
    _skip_cape = (
        _triage_mime in ("application/x-mach-binary", "application/x-elf",
                         "application/x-sharedlib", "application/x-executable",
                         "application/x-pie-executable")
        or "elf " in _triage_ftype
        or "mach-o" in _triage_ftype
    )

    _cape_start = _time.time()
    if _skip_cape:
        log.info(f"\n[Stage 2] Cape: skipped — non-Windows binary ({_triage_mime or _triage_ftype})")
        report["cape"] = {"status": "skipped", "reason": f"non-Windows binary: {_triage_mime or _triage_ftype}"}
        cape_data = {}
    else:
        # Calculate guest VM clock from PE compile timestamp to defeat date/time evasion
        cape_clock = ""
        pe_timestamp = report.get("triage", {}).get("pe_compile_timestamp")
        if pe_timestamp:
            try:
                compile_dt = datetime.fromisoformat(pe_timestamp)
                # Set clock to compile time + 7-30 days (plausible execution window)
                offset_days = random.randint(7, 30)  # nosec B311 — jitter for sandbox guest-clock anti-evasion, not security/crypto
                guest_dt = compile_dt + timedelta(days=offset_days)
                # Don't set clock to the future
                now = datetime.now(timezone.utc)
                if guest_dt > now:
                    guest_dt = now - timedelta(days=random.randint(1, 7))  # nosec B311 — jitter for sandbox guest-clock anti-evasion, not security/crypto
                cape_clock = guest_dt.strftime("%m/%d/%Y %H:%M:%S")
                log.info(f"  Guest clock: {cape_clock} (PE compiled {pe_timestamp[:10]}, +{offset_days}d)")
            except Exception as e:
                log.warning(f"  Could not calculate guest clock: {e}")

        log.info(f"\n[Stage 2] Cape: submitting with tags={cape_tags}, package={cape_package or 'auto'}, memory=1")
        update_stage(analysis_id_early, "cape", "started")
        try:
            cape_task_id = submit_to_cape(
                sample_path,
                tags=cape_tags,
                package=cape_package,
                filename=cape_filename,
                custom=f"pipeline_task_id={task_id}",
                clock=cape_clock,
            )
            log.info(f"  Cape task ID: {cape_task_id}")
            cape_data = poll_cape_task(cape_task_id)
            report["cape"] = {
                "task_id": cape_task_id,
                "status": cape_data.get("status", "unknown"),
            }

            # Extract rich intelligence from Cape's full report
            if cape_data.get("status") == "reported":
                log.info("  Extracting Cape intelligence (signatures, network, configs)...")
                cape_intel = extract_cape_intel(cape_data, output_dir=output_dir)
                report["cape"].update(cape_intel)
                sig_count = len(cape_intel.get("signatures", []))
                ttp_count = len(cape_intel.get("mitre_ttps", []))
                net_keys = list(cape_intel.get("network", {}).keys())
                payloads = cape_intel.get("payloads_extracted", 0)
                injection_bufs = cape_intel.get("injection_buffers", [])
                mutex_count = len(cape_intel.get("mutex_iocs", []))
                log.info(f"  Signatures: {sig_count}, TTPs: {ttp_count}, Network: {net_keys}, Payloads: {payloads}, Mutexes: {mutex_count}")
                if mutex_count:
                    for m in cape_intel["mutex_iocs"][:5]:
                        log.info(f"    Mutex: {m['name'][:60]} ({m['action']} by {m['process']})")
                if injection_bufs:
                    log.info(f"  Injection buffers captured: {len(injection_bufs)}")
                    for inj in injection_bufs:
                        log.info(f"    {inj['source_process']} (pid {inj['source_pid']}) → pid {inj['target_pid']} at {inj['injection_address']} ({inj['size']} bytes)")

        except Exception as e:
            log.error(f"  [!] Cape submission failed: {e}")
            report["cape"] = {"task_id": None, "status": "error", "error": str(e)}
            cape_data = {}
    stage_timings["cape"] = round(_time.time() - _cape_start, 1)
    update_stage(analysis_id_early, "cape", "completed", f"{stage_timings['cape']:.0f}s")
    log.info(f"  [cape completed in {stage_timings['cape']:.0f}s]")

    # Stage 2.5: Process Cape injection buffers
    # Cape captures the exact bytes written during cross-process injection.
    # These are ground truth — no need for Volatility to find them.
    cape_injection_candidates = []
    injection_bufs = report.get("cape", {}).get("injection_buffers", [])
    if injection_bufs:
        log.info(f"\n[Stage 2.5] Processing {len(injection_bufs)} Cape injection buffer(s)...")
        for inj in injection_bufs:
            buf_path = Path(inj["path"])
            if not buf_path.exists():
                continue
            size = inj["size"]
            # Artifact extraction on all buffers
            artifacts = extract_shellcode_artifacts(buf_path)
            api_count = len(artifacts.get("resolved_apis", []))
            path_count = len(artifacts.get("file_paths", []))
            log.info(f"    {inj['source_process']} → pid {inj['target_pid']} at {inj['injection_address']}: {size} bytes, {api_count} APIs, {path_count} paths")

            candidate = {
                "source": "cape_injection",
                "source_pid": inj["source_pid"],
                "source_process": inj["source_process"],
                "pid": inj["target_pid"],
                "process": f"target_of_{inj['source_process']}",
                "injection_address": inj["injection_address"],
                "region_size": size,
                "path": buf_path,
                "shellcode_artifacts": artifacts,
                "cape_confirmed": True,
            }

            # >= 1KB: send to Ghidra + LLM for decompilation
            if size >= 1024:
                candidate["analyze_with_ghidra"] = True
                log.info(f"      → Queued for Ghidra + LLM analysis ({size} bytes)")
            else:
                candidate["analyze_with_ghidra"] = False
                log.info(f"      → Artifact extraction only ({size} bytes, < 1KB)")

            cape_injection_candidates.append(candidate)

    # Also process Cape's large extracted payloads (unpacked shellcode, > 1KB)
    large_payloads = report.get("cape", {}).get("large_payloads", [])
    if large_payloads:
        log.info(f"  Cape large payloads: {len(large_payloads)} (>= 1KB, queued for Ghidra + LLM)")
        for lp in large_payloads:
            lp_path = Path(lp["path"])
            if not lp_path.exists():
                continue
            artifacts = extract_shellcode_artifacts(lp_path)
            cape_injection_candidates.append({
                "source": "cape_payload",
                "pid": 0,
                "process": f"cape_{lp.get('cape_type', 'unknown')}",
                "injection_address": "N/A",
                "region_size": lp["size"],
                "path": lp_path,
                "shellcode_artifacts": artifacts,
                "cape_confirmed": True,
                "analyze_with_ghidra": lp["size"] >= 1024,
                "cape_type": lp.get("cape_type", "unknown"),
                "sha256": lp.get("sha256", ""),
            })
            api_count = len(artifacts.get("resolved_apis", []))
            log.info(f"    {lp.get('cape_type', '?')} ({lp['size']} bytes, sha={lp['sha256'][:12]}...): {api_count} APIs")

    # Stage 2.7: PCAP analysis — Zeek + Suricata on Cape's network capture
    _pcap_start = _time.time()
    update_stage(analysis_id_early, "pcap", "started")
    cape_task_id = report.get("cape", {}).get("task_id")
    pcap_path = get_cape_pcap(cape_task_id) if PCAP_ENABLED else None
    if pcap_path:
        log.info(f"\n[Stage 2.7] PCAP Analysis: running Zeek + Suricata...")
        pcap_output_dir = str(output_dir / "pcap_analysis")
        pcap_result = run_pcap_analysis(
            pcap_path, pcap_output_dir, pcap_cmd=PCAP_CMD, timeout=PCAP_TIMEOUT,
        )
        report["pcap_analysis"] = pcap_result
        if pcap_result.get("error"):
            log.warning(f"{pcap_result['error']}")
        else:
            zeek_summary = pcap_result.get("zeek", {}).get("summary", {})
            suricata_summary = pcap_result.get("suricata", {}).get("summary", {})
            log.info(f"  Zeek: {zeek_summary.get('total_connections', 0)} connections, "
                     f"{zeek_summary.get('dns_queries', 0)} DNS, "
                     f"{zeek_summary.get('http_transactions', 0)} HTTP, "
                     f"{zeek_summary.get('tls_sessions', 0)} TLS")
            alerts = suricata_summary.get('unique_alerts', 0)
            if alerts:
                log.info(f"  Suricata: {alerts} unique alerts")
                for alert in pcap_result.get("suricata", {}).get("alerts", [])[:5]:
                    log.info(f"    [{alert.get('severity', '?')}] {alert.get('signature', '?')}")
    elif PCAP_ENABLED:
        report["pcap_analysis"] = {"skipped": True, "reason": "no PCAP available"}
    else:
        report["pcap_analysis"] = {"enabled": False}
    stage_timings["pcap"] = round(_time.time() - _pcap_start, 1)
    update_stage(analysis_id_early, "pcap", "completed", f"{stage_timings['pcap']:.0f}s")

    # Stage 3: Volatility (triggered by Cape signatures)
    _vol_start = _time.time()
    update_stage(analysis_id_early, "volatility", "started")
    log.info(f"\n[Stage 3] Volatility: checking triggers...")
    if should_run_volatility(cape_data, volatility_cmd=VOLATILITY_CMD,
                             volatility_triggers=VOLATILITY_TRIGGERS,
                             get_cape_signatures_fn=get_cape_signatures):
        log.info("  Triggered — running Volatility 3")
        # Pass Cape's injection PIDs to guide malfind analysis
        cape_injection_pids = report.get("cape", {}).get("injection_pids", [])
        if cape_injection_pids:
            log.info(f"  Cape identified injection PIDs: {cape_injection_pids}")

        import signal

        def _vol_timeout_handler(signum, frame):
            raise TimeoutError("Volatility stage timed out (45 min)")

        old_handler = signal.signal(signal.SIGALRM, _vol_timeout_handler)
        signal.alarm(2700)  # 45 minutes — covers copy + 7 plugins + malfind
        try:
            report["volatility"] = run_volatility(
                cape_data, output_dir,
                volatility_cmd=VOLATILITY_CMD,
                volatility_triggers=VOLATILITY_TRIGGERS,
                volatility_standard_plugins=VOLATILITY_STANDARD_PLUGINS,
                volatility_extra_plugins=VOLATILITY_EXTRA_PLUGINS,
                malfind_enabled=MALFIND_ENABLED,
                malfind_min_size=MALFIND_MIN_SIZE,
                malfind_max_size=MALFIND_MAX_SIZE,
                malfind_min_score=MALFIND_MIN_SCORE,
                malfind_max_candidates=MALFIND_MAX_CANDIDATES,
                malfind_benign_processes=MALFIND_BENIGN_PROCESSES,
                get_cape_signatures_fn=get_cape_signatures,
                cape_injection_pids=cape_injection_pids,
                cape_has_injection_buffers=len(cape_injection_candidates) > 0,
                ramdisk_path=VOLATILITY_RAMDISK,
                parallel_workers=VOLATILITY_PARALLEL_WORKERS,
            )
        except TimeoutError:
            log.error("  [!] Volatility stage timed out after 45 minutes")
            report["volatility"] = {"triggered": True, "error": "timeout (45 min)"}
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Explain why Volatility was skipped
        cape_sigs = get_cape_signatures(cape_data) if cape_data else []
        if not cape_data or cape_data.get("status") != "reported":
            reason = "Cape analysis not available"
        elif not Path(VOLATILITY_CMD).exists():
            reason = "Volatility container not installed"
        elif not cape_sigs:
            reason = "Cape reported no behavioral signatures"
        else:
            reason = (f"Cape signatures ({len(cape_sigs)}) did not match "
                      f"Volatility triggers. Triggers require: injection, "
                      f"hollowing, rootkit, persistence, or packing signatures")
        log.info(f"  Not triggered — {reason}")
        report["volatility"] = {"triggered": False, "reason": reason}
    stage_timings["volatility"] = round(_time.time() - _vol_start, 1)
    update_stage(analysis_id_early, "volatility", "completed", f"{stage_timings['volatility']:.0f}s")

    # Stage 3.5: Shellcode analysis (dump already extracted during Volatility stage)
    # The two-pass approach runs inside run_volatility: JSON filter right after
    # malfind, then targeted dump while the memory dump still exists.
    shellcode_candidates = []
    vol_data = report.get("volatility", {})
    selected_regions = vol_data.get("_malfind_selected", [])
    malfind_dump_dir_str = vol_data.get("_malfind_dump_dir", "")
    malfind_dump_dir = Path(malfind_dump_dir_str) if malfind_dump_dir_str else output_dir / "malfind_dumps"

    if selected_regions:
        log.info(f"\n[Stage 3.5] Shellcode analysis: {len(selected_regions)} candidates from malfind")

        # Match selected regions to their dump files for Ghidra analysis
        for region in selected_regions:
            file_output = region.get("file_output", "")
            if file_output:
                dump_file = malfind_dump_dir / file_output
                if dump_file.exists():
                    region["path"] = dump_file
            # Fallback: construct expected filename from PID and start address
            if "path" not in region:
                pattern = f"pid.{region['pid']}.vad.{region['start_vpn']}*"
                matches = list(malfind_dump_dir.glob(pattern))
                if matches:
                    region["path"] = matches[0]

        shellcode_candidates = [r for r in selected_regions if "path" in r]
        if len(shellcode_candidates) < len(selected_regions):
            missing = len(selected_regions) - len(shellcode_candidates)
            log.info(f"    [!] {missing} selected regions have no dump file")

    # Merge Cape injection candidates with malfind candidates
    # Cape buffers are ground truth — they go first
    if cape_injection_candidates:
        all_candidates = cape_injection_candidates + shellcode_candidates
        log.info(f"\n  Total shellcode candidates: {len(cape_injection_candidates)} from Cape + {len(shellcode_candidates)} from malfind")
    else:
        all_candidates = shellcode_candidates
    shellcode_candidates = all_candidates

    # Memory dump cleanup is handled by a cape-owned cron job.
    # The pipeline user intentionally does not have write access to
    # CAPE storage — that's a security boundary we want to preserve.

    # Stage 4: Static analysis (Ghidra for native PE, ILSpy for .NET)
    _ghidra_start = _time.time()
    update_stage(analysis_id_early, "ghidra", "started")

    # Check if this is an Office document — route to olevba
    dotnet_origin = None
    if is_office_document(report):
        log.info(f"\n[Stage 4] Office document detected — running macro extraction...")
        office_result = run_office_analysis(sample_path, output_dir, office_cmd=OFFICE_CMD)
        report["office_analysis"] = office_result
        if office_result.get("analysis_success"):
            has_macros = office_result.get("has_macros", False)
            module_count = len(office_result.get("vba_modules", []))
            source_len = len(office_result.get("vba_source", ""))
            auto_exec = office_result.get("auto_exec_triggers", [])
            suspicious = len(office_result.get("suspicious_keywords", []))
            mraptor = office_result.get("mraptor_flags", {})
            if has_macros:
                log.info(f"  Macros: {module_count} modules, {source_len} chars VBA source")
                log.info(f"  Auto-exec: {', '.join(auto_exec) if auto_exec else 'none'}")
                log.info(f"  Suspicious keywords: {suspicious}")
                log.info(f"  mraptor: A={'Y' if mraptor.get('auto_exec') else 'N'} "
                         f"W={'Y' if mraptor.get('write') else 'N'} "
                         f"X={'Y' if mraptor.get('execute') else 'N'}")
                if office_result.get("xlm_detected"):
                    log.info(f"  XLM/Excel 4.0 macros detected (no deobfuscation)")
            else:
                log.info(f"  Valid Office document but no macros found")
        else:
            log.warning(f"olevba failed: {office_result.get('error', 'unknown')}")

        report["ghidra"] = {"triggered": True, "office_routed": True,
                            "analyzed_files": []}
    elif is_powershell_script(report):
        log.info(f"\n[Stage 4] PowerShell script detected — running deobfuscation...")
        ps_result = run_powershell_analysis(sample_path, output_dir, powershell_cmd=POWERSHELL_CMD)
        report["powershell_analysis"] = ps_result
        if ps_result.get("analysis_success"):
            layer_count = ps_result.get("layer_count", 0)
            final_len = len(ps_result.get("final_decoded", ""))
            obfuscation = ps_result.get("obfuscation_techniques", [])
            psdecode_ok = ps_result.get("psdecode_success", False)
            strings_count = len(ps_result.get("strings_of_interest", []))
            log.info(f"  PSDecode: {'success' if psdecode_ok else 'failed (fallback)'}, {layer_count} layers, {final_len} chars decoded")
            if obfuscation:
                log.info(f"  Obfuscation: {', '.join(obfuscation)}")
            log.info(f"  Interesting strings: {strings_count}")
        else:
            log.warning(f"PowerShell analysis failed: {ps_result.get('error', 'unknown')}")

        report["ghidra"] = {"triggered": True, "powershell_routed": True,
                            "analyzed_files": []}
    elif is_text_script(report, sample_path):
        script_result = read_script_source(sample_path, report)
        lang = script_result.get("source_language", "unknown")
        log.info(f"\n[Stage 4] Script file detected ({lang}) — extracting source...")
        report["script_analysis"] = script_result
        if script_result.get("analysis_success"):
            patterns = script_result.get("detected_patterns", [])
            log.info(f"  Source: {script_result['file_size']} chars, language: {lang}")
            if patterns:
                log.info(f"  Detected patterns: {', '.join(patterns)}")
            if script_result.get("truncated"):
                log.info(f"  Truncated at {script_result['truncated_at']} chars")
        else:
            log.warning(f"Script source read failed: {script_result.get('error', 'unknown')}")

        report["ghidra"] = {"triggered": True, "script_routed": True,
                            "analyzed_files": []}
    # Check if this is a .NET binary — route to ILSpy instead
    elif is_dotnet_binary(report):
        dotnet_origin = "original"
        log.info(f"\n[Stage 4] .NET detected — running ILSpy decompilation...")
        dotnet_result = run_dotnet_analysis(
            sample_path, output_dir, dotnet_cmd=DOTNET_CMD)
        report["dotnet_analysis"] = dotnet_result
        if dotnet_result.get("analysis_success"):
            source_len = dotnet_result.get("decompilation", {}).get("source_length", 0)
            class_count = dotnet_result.get("class_count", 0)
            strings_count = len(dotnet_result.get("strings_of_interest", []))
            log.info(f"  Decompiled: {source_len} chars C# source, {class_count} classes, {strings_count} interesting strings")
        else:
            log.warning(f"ILSpy failed: {dotnet_result.get('error', 'unknown')}")

        report["ghidra"] = {"triggered": True, "dotnet_routed": True,
                            "analyzed_files": []}
    elif is_go_binary(report):
        log.info(f"\n[Stage 4] Go binary detected — running GoReSym analysis...")
        go_result = run_go_analysis(sample_path, output_dir, go_cmd=GO_CMD)
        report["go_analysis"] = go_result
        if go_result.get("analysis_success"):
            build = go_result.get("build_info", {})
            func_count = go_result.get("functions", {}).get("user_count", 0)
            pkg_count = len(go_result.get("packages", []))
            strings_count = len(go_result.get("strings_of_interest", []))
            log.info(f"  Go {build.get('go_version', '?')}, {func_count} user functions, {pkg_count} packages, {strings_count} interesting strings")
            report["ghidra"] = {"triggered": True, "go_routed": True,
                                "analyzed_files": []}
        else:
            # GoReSym failed — likely garble-obfuscated. Fall back to Ghidra
            # for raw pseudocode analysis without function name metadata.
            log.warning(f"GoReSym failed: {go_result.get('error', 'unknown')}")
            log.info(f"  Falling back to Ghidra for obfuscated Go binary...")
            if should_run_ghidra(cape_data, sample_path, ghidra_cmd=GHIDRA_CMD,
                                 get_cape_signatures_fn=get_cape_signatures):
                report["ghidra"] = run_ghidra(
                    cape_data, output_dir, sample_path,
                    ghidra_cmd=GHIDRA_CMD,
                    get_cape_signatures_fn=get_cape_signatures,
                    shellcode_candidates=shellcode_candidates,
                )
                report["ghidra"]["go_goresym_failed"] = True
            else:
                # Force Ghidra even if not triggered — we need SOME analysis
                log.info(f"  Ghidra not triggered but forcing for Go fallback...")
                report["ghidra"] = run_ghidra(
                    cape_data, output_dir, sample_path,
                    ghidra_cmd=GHIDRA_CMD,
                    get_cape_signatures_fn=get_cape_signatures,
                    shellcode_candidates=shellcode_candidates,
                )
                report["ghidra"]["go_goresym_failed"] = True
    elif is_pyinstaller_binary(report, sample_path):
        log.info(f"\n[Stage 4] PyInstaller binary detected — extracting and decompiling...")
        pyinstaller_result = run_pyinstaller_analysis(
            sample_path, output_dir, pyinstaller_cmd=PYINSTALLER_CMD)
        report["pyinstaller_analysis"] = pyinstaller_result
        if pyinstaller_result.get("analysis_success"):
            source_len = pyinstaller_result.get("decompilation", {}).get("source_length", 0)
            bundled = pyinstaller_result.get("bundled_count", 0)
            strings_count = len(pyinstaller_result.get("strings_of_interest", []))
            py_ver = pyinstaller_result.get("python_version", "?")
            log.info(f"  Python {py_ver}, {source_len} chars source, {bundled} bundled files, {strings_count} interesting strings")
        else:
            log.warning(f"PyInstaller analysis failed: {pyinstaller_result.get('error', 'unknown')}")

        report["ghidra"] = {"triggered": True, "pyinstaller_routed": True,
                            "analyzed_files": []}
    elif is_java_binary(report):
        log.info(f"\n[Stage 4] Java JAR detected — running CFR decompilation...")
        java_result = run_java_analysis(sample_path, output_dir, java_cmd=JAVA_CMD)
        report["java_analysis"] = java_result
        if java_result.get("analysis_success"):
            source_len = java_result.get("decompilation", {}).get("source_length", 0)
            class_count = java_result.get("class_summary_count", 0)
            strings_count = len(java_result.get("strings_of_interest", []))
            main_class = java_result.get("main_class", "?")
            log.info(f"  Main-Class: {main_class}, {source_len} chars source, {class_count} classes, {strings_count} interesting strings")
        else:
            log.warning(f"CFR failed: {java_result.get('error', 'unknown')}")

        report["ghidra"] = {"triggered": True, "java_routed": True,
                            "analyzed_files": []}
    else:
        # Original sample is not .NET, Go, PyInstaller, or Java — check Cape extractions for .NET payloads
        cape_task_id = report.get("cape", {}).get("task_id")
        dotnet_extractions = find_dotnet_extractions(cape_data, cape_task_id,
                                                      report_dir=output_dir)

        if dotnet_extractions:
            dotnet_origin = "extraction"
            log.info(f"\n[Stage 4] .NET payload(s) found in Cape extractions ({len(dotnet_extractions)}):")
            # Analyze the first (largest) .NET extraction
            best = max(dotnet_extractions, key=lambda x: x["size"])
            log.info(f"  Analyzing: {best['source_dir']}/{best['sha256'][:16]}... ({best['size']} bytes)")
            dotnet_result = run_dotnet_analysis(
                Path(best["path"]), output_dir, dotnet_cmd=DOTNET_CMD)
            dotnet_result["extraction_source"] = best
            report["dotnet_analysis"] = dotnet_result
            if dotnet_result.get("analysis_success"):
                source_len = dotnet_result.get("decompilation", {}).get("source_length", 0)
                class_count = dotnet_result.get("class_count", 0)
                strings_count = len(dotnet_result.get("strings_of_interest", []))
                log.info(f"  Decompiled: {source_len} chars C# source, {class_count} classes, {strings_count} interesting strings")
            else:
                log.warning(f"ILSpy failed: {dotnet_result.get('error', 'unknown')}")

            # Still run Ghidra on the original native PE sample
            if should_run_ghidra(cape_data, sample_path, ghidra_cmd=GHIDRA_CMD,
                                 get_cape_signatures_fn=get_cape_signatures):
                log.info(f"  Also running Ghidra on original native PE...")
                report["ghidra"] = run_ghidra(
                    cape_data, output_dir, sample_path,
                    ghidra_cmd=GHIDRA_CMD,
                    get_cape_signatures_fn=get_cape_signatures,
                    shellcode_candidates=shellcode_candidates,
                )
            else:
                report["ghidra"] = {"triggered": True, "dotnet_extraction_found": True,
                                    "analyzed_files": []}
        elif should_run_ghidra(cape_data, sample_path, ghidra_cmd=GHIDRA_CMD,
                               get_cape_signatures_fn=get_cape_signatures):
            log.info(f"\n[Stage 4] Ghidra: checking triggers...")
            log.info("  Triggered — running Ghidra headless")
            report["ghidra"] = run_ghidra(
                cape_data, output_dir, sample_path,
                ghidra_cmd=GHIDRA_CMD,
                get_cape_signatures_fn=get_cape_signatures,
                shellcode_candidates=shellcode_candidates,
            )
        else:
            log.info(f"\n[Stage 4] Ghidra: checking triggers...")
            log.info("  Not triggered")
            report["ghidra"] = {"triggered": False}

    # Check CAPE logs for encoded PowerShell commands (any sample type)
    if not report.get("powershell_analysis"):
        ps_commands = extract_powershell_from_cape(report)
        if ps_commands:
            log.info(f"\n[Stage 4] Found {len(ps_commands)} encoded PowerShell command(s) in CAPE logs")
            best = max(ps_commands, key=lambda x: len(x.get("decoded", "")))
            log.info(f"  Largest: {len(best['decoded'])} chars from PID {best['pid']}")
            # Write decoded script to temp file for container analysis
            import os
            import tempfile
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", dir=str(output_dir),
                                              delete=False, encoding="utf-8")
            tmp.write(best["decoded"])
            tmp.close()
            try:
                ps_result = run_powershell_analysis(
                    Path(tmp.name), output_dir, powershell_cmd=POWERSHELL_CMD)
                ps_result["cape_extracted"] = True
                ps_result["extraction_count"] = len(ps_commands)
                ps_result["extraction_pid"] = best["pid"]
                report["powershell_analysis"] = ps_result
                if ps_result.get("analysis_success"):
                    layer_count = ps_result.get("layer_count", 0)
                    log.info(f"  PSDecode: {layer_count} layers decoded")
                else:
                    log.warning(f"  PowerShell analysis failed: {ps_result.get('error', 'unknown')}")
            finally:
                os.unlink(tmp.name)

    stage_timings["ghidra"] = round(_time.time() - _ghidra_start, 1)
    update_stage(analysis_id_early, "ghidra", "completed", f"{stage_timings['ghidra']:.0f}s")

    # Stage 4.5: LLM Interpretation (agentic for Ghidra, single-shot for .NET/Go)
    # Common context passed to all LLM init messages for consistency
    _llm_context = {}
    if report.get("bazaar_family"):
        _llm_context["bazaar_family"] = report["bazaar_family"]
    _interp_start = _time.time()
    update_stage(analysis_id_early, "interpret", "started")
    ghidra_data = report.get("ghidra", {})
    dotnet_data = report.get("dotnet_analysis", {})
    go_data = report.get("go_analysis", {})
    pyinstaller_data = report.get("pyinstaller_analysis", {})
    java_data = report.get("java_analysis", {})
    office_data = report.get("office_analysis", {})
    ps_data = report.get("powershell_analysis", {})
    script_data = report.get("script_analysis", {})
    analyzed_files = ghidra_data.get("analyzed_files", [])
    successful = [f for f in analyzed_files if f.get("analysis_success")]

    if dotnet_data.get("analysis_success") and INTERPRET_ENABLED:
        # .NET path — send C# source directly to LLM (no Ghidra tools needed)
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing .NET decompilation...")
        dotnet_source = dotnet_data.get("decompilation", {}).get("source", "")
        dotnet_classes = dotnet_data.get("classes", [])
        dotnet_strings = dotnet_data.get("strings_of_interest", [])

        # Build init message with C# source instead of Ghidra data
        extraction_source = dotnet_data.get("extraction_source")
        cape_sigs = [s.get("name", "") for s in report.get("cape", {}).get("signatures", [])]
        dotnet_init = {
            **_llm_context,
            "analysis_type": "dotnet",
            "source_language": "csharp",
            "decompiled_source": dotnet_source[:50000],  # cap for LLM context
            "class_count": len(dotnet_classes),
            "classes": dotnet_classes[:50],
            "strings_of_interest": dotnet_strings,
            "analysis_success": True,
            "origin": "extraction" if extraction_source else "original",
            "extraction_context": {
                "source_dir": extraction_source["source_dir"],
                "sha256": extraction_source["sha256"],
                "cape_signatures": cape_sigs[:10],
            } if extraction_source else None,
        }
        report["llm_interpretation"] = run_interpret(
            dotnet_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif java_data.get("analysis_success") and INTERPRET_ENABLED:
        # Java path — send decompiled Java source directly to LLM
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing Java decompilation...")
        java_init = {
            **_llm_context,
            "analysis_type": "java_cfr",
            "source_language": "java",
            "decompiled_source": java_data.get("decompilation", {}).get("source", "")[:50000],
            "main_class": java_data.get("main_class", "?"),
            "class_summary_count": java_data.get("class_summary_count", 0),
            "imports": java_data.get("imports", []),
            "strings_of_interest": java_data.get("strings_of_interest", []),
            "manifest": java_data.get("manifest", {}),
            "file_count": java_data.get("file_count", 0),
            "analysis_success": True,
        }
        report["llm_interpretation"] = run_interpret(
            java_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif office_data.get("analysis_success") and office_data.get("has_macros") and INTERPRET_ENABLED:
        # Office macro path — send VBA source to LLM for deobfuscation + analysis
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing Office macros...")
        cape_sigs = [s.get("name", "") for s in report.get("cape", {}).get("signatures", [])]
        office_init = {
            **_llm_context,
            "analysis_type": "office_macro",
            "source_language": "vba",
            "vba_source": office_data.get("vba_source", "")[:50000],
            "vba_modules": office_data.get("vba_modules", []),
            "auto_exec_triggers": office_data.get("auto_exec_triggers", []),
            "suspicious_keywords": office_data.get("suspicious_keywords", []),
            "iocs_extracted": office_data.get("iocs_extracted", {}),
            "obfuscation_indicators": office_data.get("obfuscation_indicators", []),
            "mraptor_flags": office_data.get("mraptor_flags", {}),
            "metadata": office_data.get("metadata", {}),
            "xlm_detected": office_data.get("xlm_detected", False),
            "file_format": office_data.get("file_format", ""),
            "cape_signatures": cape_sigs[:20],
            "analysis_success": True,
        }
        report["llm_interpretation"] = run_interpret(
            office_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif ps_data.get("analysis_success") and INTERPRET_ENABLED:
        # PowerShell path — send decoded script to LLM
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing PowerShell script...")
        cape_sigs = [s.get("name", "") for s in report.get("cape", {}).get("signatures", [])]
        ps_init = {
            **_llm_context,
            "analysis_type": "powershell",
            "source_language": "powershell",
            "original_script": ps_data.get("original_script", "")[:30000],
            "decoded_layers": ps_data.get("decoded_layers", []),
            "final_decoded": ps_data.get("final_decoded", "")[:50000],
            "layer_count": ps_data.get("layer_count", 0),
            "obfuscation_techniques": ps_data.get("obfuscation_techniques", []),
            "iocs_extracted": ps_data.get("iocs_extracted", {}),
            "strings_of_interest": ps_data.get("strings_of_interest", []),
            "psdecode_success": ps_data.get("psdecode_success", False),
            "cape_extracted": ps_data.get("cape_extracted", False),
            "cape_signatures": cape_sigs[:20],
            "input_mode": ps_data.get("input_mode", "file"),
            "analysis_success": True,
        }
        report["llm_interpretation"] = run_interpret(
            ps_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif script_data.get("analysis_success") and INTERPRET_ENABLED:
        # Generic script path — send source directly to LLM for analysis + deobfuscation
        script_lang = script_data.get("source_language", "unknown")
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing {script_lang} source...")
        cape_sigs = [s.get("name", "") for s in report.get("cape", {}).get("signatures", [])]
        script_init = {
            **_llm_context,
            "analysis_type": "script_analysis",
            "source_language": script_lang,
            "source": script_data.get("source", "")[:50000],
            "file_size": script_data.get("file_size", 0),
            "detected_patterns": script_data.get("detected_patterns", []),
            "truncated": script_data.get("truncated", False),
            "cape_signatures": cape_sigs[:20],
            "analysis_success": True,
        }
        report["llm_interpretation"] = run_interpret(
            script_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif pyinstaller_data.get("analysis_success") and INTERPRET_ENABLED:
        # PyInstaller path — send Python source directly to LLM (no tools needed)
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing PyInstaller decompilation...")
        py_source = pyinstaller_data.get("decompilation", {}).get("source", "")
        py_imports = pyinstaller_data.get("imports", [])
        py_strings = pyinstaller_data.get("strings_of_interest", [])
        py_init = {
            **_llm_context,
            "analysis_type": "pyinstaller",
            "source_language": "python",
            "decompiled_source": py_source[:50000],
            "imports": py_imports,
            "strings_of_interest": py_strings,
            "bundled_files": pyinstaller_data.get("bundled_files", [])[:50],
            "bundled_count": pyinstaller_data.get("bundled_count", 0),
            "python_version": pyinstaller_data.get("python_version", "?"),
            "analysis_success": True,
        }
        report["llm_interpretation"] = run_interpret(
            py_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif go_data.get("analysis_success") and INTERPRET_ENABLED:
        # Go path — send GoReSym metadata directly to LLM (no tools needed)
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing Go binary metadata...")
        go_init = {
            **_llm_context,
            "analysis_type": "go_goresym",
            "build_info": go_data.get("build_info", {}),
            "packages": go_data.get("packages", []),
            "functions": go_data.get("functions", {}),
            "types": go_data.get("types", []),
            "strings_of_interest": go_data.get("strings_of_interest", []),
            "analysis_success": True,
        }
        report["llm_interpretation"] = run_interpret(
            go_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {interp.get('tool_calls_used', 0)}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")

    elif successful:
        # Native PE path — agentic Ghidra investigation
        log.info(f"\n[Stage 4.5] LLM Interpretation: analyzing Ghidra output...")
        report["llm_interpretation"] = run_interpret(
            successful[0], output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        interp = report["llm_interpretation"]
        if interp.get("enabled") and interp.get("analysis"):
            calls = interp.get("tool_calls_used", 0)
            influenced = interp.get("possible_prompt_influence", False)
            family = interp.get("analysis", {}).get("malware_family_guess", "?")
            log.info(f"  Family guess: {family}")
            log.info(f"  Tool calls: {calls}, Influence flag: {influenced}")
        elif interp.get("error"):
            log.warning(f"Error: {interp['error']}")
    else:
        if INTERPRET_ENABLED and (ghidra_data.get("triggered") or dotnet_data):
            log.info(f"\n[Stage 4.5] LLM Interpretation: skipped (no successful analysis)")
            report["llm_interpretation"] = {"enabled": True, "reason": "no_analysis_data"}
        else:
            report["llm_interpretation"] = {"enabled": INTERPRET_ENABLED,
                                            "reason": "not_triggered"}
    stage_timings["interpret"] = round(_time.time() - _interp_start, 1)
    update_stage(analysis_id_early, "interpret", "completed", f"{stage_timings['interpret']:.0f}s")

    # Stage 4.6: Log shellcode artifacts summary (no Ghidra needed)
    # Small injection buffers (< 1KB) with artifacts — data already in
    # shellcode_artifacts dict and included in report JSON for the LLM summary.
    shellcode_with_artifacts = [
        af for af in analyzed_files
        if af.get("shellcode_artifacts") and not af.get("analysis_success")
    ]
    if shellcode_with_artifacts and INTERPRET_ENABLED:
        log.info(f"\n[Stage 4.6] LLM Shellcode Analysis: {len(shellcode_with_artifacts)} artifact-only candidates")
        for sc in shellcode_with_artifacts:
            arts = sc.get("shellcode_artifacts", {})
            apis = arts.get("resolved_apis", [])
            paths = arts.get("file_paths", [])
            if apis or paths:
                log.info(f"    {sc.get('source_process', '?')} → pid {sc.get('pid')}: {len(apis)} APIs, {len(paths)} paths")

    # Stage 4.7: Evasion hunter — when CAPE produces suspiciously low activity,
    # run a focused LLM analysis to identify sandbox evasion techniques.
    cape_sig_count = len(report.get("cape", {}).get("signatures", []))
    sample_size = report.get("triage", {}).get("file_size", 0)
    cape_status = report.get("cape", {}).get("status", "")

    if (EVASION_HUNTER_ENABLED and INTERPRET_ENABLED
            and cape_status == "reported"
            and cape_sig_count < EVASION_MAX_SIGNATURES
            and sample_size > EVASION_MIN_BINARY_SIZE):
        log.info(f"\n[Stage 4.7] Evasion Hunter: {cape_sig_count} signatures on a "
                 f"{sample_size // 1024}KB binary — investigating sandbox evasion...")

        # Build behavioral data for the evasion prompt
        cape_data_local = report.get("cape", {})
        triage = report.get("triage", {})
        beh_processes = []
        # Extract API call summary from Cape signatures
        api_summary = set()
        for sig in cape_data_local.get("signatures", []):
            for data_item in sig.get("data", []):
                if isinstance(data_item, dict):
                    api = data_item.get("api", "")
                    if api:
                        api_summary.add(api)

        evasion_init = {
            **_llm_context,
            "analysis_type": "evasion_hunter",
            "binary_size": sample_size,
            "file_type": triage.get("file_type", "unknown"),
            "signature_count": cape_sig_count,
            "network_activity": "none" if not cape_data_local.get("network", {}).get("dns_queries") else "some",
            "duration": cape_data_local.get("duration", "?"),
            "signatures": [{"name": s.get("name", ""), "description": s.get("description", "")}
                          for s in cape_data_local.get("signatures", [])],
            "api_summary": sorted(api_summary)[:100],
            "processes": beh_processes,
            "yara_matches": [m.get("rule", "") for m in triage.get("yara_matches", [])],
            "sections": triage.get("sections", []),
        }

        report["evasion_analysis"] = run_interpret(
            evasion_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        evasion = report["evasion_analysis"]
        if evasion.get("enabled") and evasion.get("analysis"):
            ea = evasion["analysis"]
            confidence = ea.get("confidence", "?")
            techniques = ea.get("evasion_techniques", [])
            recommendations = ea.get("sandbox_recommendations", [])
            log.info(f"  Confidence: {confidence}")
            log.info(f"  Evasion techniques: {len(techniques)}")
            for t in techniques[:5]:
                log.info(f"    {t.get('mitre_id', '?')}: {t.get('technique', '?')}")
            if recommendations:
                log.info(f"  Recommendations: {len(recommendations)}")
                for r in recommendations[:3]:
                    log.info(f"    - {r[:100]}")
        elif evasion.get("error"):
            log.warning(f"Evasion hunter error: {evasion['error']}")
    else:
        report["evasion_analysis"] = {"enabled": False, "reason": "not_triggered"}

    # Stage 5.5: Screenshot analysis — deduplicate + QR detection
    cape_task_id = report.get("cape", {}).get("task_id")
    if cape_task_id:
        shots_dir = Path(f"/opt/CAPEv2/storage/analyses/{cape_task_id}/shots")
        if shots_dir.is_dir() and any(shots_dir.glob("*.png")):
            log.info(f"\n[Stage 5.5] Screenshot Analysis: dedup + QR detection...")
            try:
                screenshot_result = subprocess.run(
                    [SCREENSHOT_CMD, str(shots_dir), str(output_dir)],
                    capture_output=True, text=True, timeout=60,
                )
                if screenshot_result.returncode == 0:
                    try:
                        screenshot_data = json.loads(screenshot_result.stdout)
                        report["screenshots"] = screenshot_data
                        total = screenshot_data.get("total_screenshots", 0)
                        unique = screenshot_data.get("unique_count", 0)
                        qr_count = len(screenshot_data.get("qr_codes", []))
                        evasion = screenshot_data.get("evasion_signal", False)
                        log.info(f"  {total} total → {unique} unique frames, {qr_count} QR codes")
                        if evasion:
                            log.info(f"  Evasion signal: all screenshots identical — no visual activity")
                        for qr in screenshot_data.get("qr_codes", []):
                            log.info(f"  QR [{qr.get('type')}]: {qr.get('value', '')[:80]}")
                    except json.JSONDecodeError:
                        log.warning(f"Screenshot analysis returned invalid JSON")
                else:
                    log.warning(f"Screenshot analysis failed: {screenshot_result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                log.warning("Screenshot analysis timed out (60s)")
            except FileNotFoundError:
                log.warning("Screenshot analysis command not found — deploy screenshot-analysis role")
        else:
            report["screenshots"] = {"total_screenshots": 0, "unique_count": 0,
                                     "note": "No screenshots captured (QEMU screenshots may not be enabled)"}

    # Cross-tool correlation — must run BEFORE severity calculation
    # (severity reads cross_correlations to boost score for critical findings)
    log.info(f"\n[Cross-Correlation] Comparing Cape and Volatility data...")
    report["cross_correlations"] = cross_correlate(report)
    for finding in report["cross_correlations"]:
        severity = finding.get("severity", "info")
        title = finding.get("title", "?")
        sources = " + ".join(finding.get("sources", []))
        log.info(f"  [{severity.upper()}] {title} ({sources})")
    if not report["cross_correlations"]:
        log.info("  No cross-tool findings detected")

    # Programmatic analysis — deterministic, runs before LLM
    log.info(f"\n[Analysis] Programmatic analysis...")
    report["family"] = determine_family(report)
    report["severity"] = calculate_severity(report)
    report["mitre_mapping"] = build_mitre_mapping(report)
    log.info(f"  Family: {report['family']} (source: {report.get('_family_source', '?')})")
    log.info(f"  Severity: {report['severity']} (score: {report.get('_severity_score', '?')})")
    log.info(f"  MITRE techniques: {len(report['mitre_mapping'])}")

    # IOC extraction — pull actionable indicators from all stages
    log.info(f"\n[IOC Extraction] Scanning all stages for indicators...")
    report["extracted_iocs"] = extract_iocs(report)
    ioc_count = len(report["extracted_iocs"])
    ioc_types = {}
    for ioc in report["extracted_iocs"]:
        t = ioc["type"]
        ioc_types[t] = ioc_types.get(t, 0) + 1
    log.info(f"  Found {ioc_count} IOCs: {ioc_types}")

    # IOC-to-MITRE technique mapping (programmatic rules)
    report["ioc_technique_mappings"] = map_iocs_to_techniques(report, report["extracted_iocs"])
    if report["ioc_technique_mappings"]:
        log.info(f"  Mapped {len(report['ioc_technique_mappings'])} IOCs to MITRE techniques")

    # Clean internal keys with non-serializable objects (Path) before summary/report
    vol_data = report.get("volatility", {})
    for key in list(vol_data.keys()):
        if key.startswith("_"):
            del vol_data[key]

    # Stage 5: Executive summary (single-shot LLM, after all stages)
    # Stage 5.7: Visual screenshot analysis (multimodal LLM)
    screenshot_data = report.get("screenshots", {})
    if (INTERPRET_ENABLED
            and screenshot_data.get("analysis_success")
            and screenshot_data.get("unique_count", 0) > 0
            and screenshot_data.get("frames_base64")):
        log.info(f"\n[Stage 5.7] Visual Analysis: analyzing {screenshot_data['unique_count']} unique screenshots...")
        visual_init = {
            **_llm_context,
            "analysis_type": "visual_analysis",
            "total_screenshots": screenshot_data.get("total_screenshots", 0),
            "unique_count": screenshot_data.get("unique_count", 0),
            "qr_codes": screenshot_data.get("qr_codes", []),
            "frames_base64": screenshot_data.get("frames_base64", []),
        }
        report["visual_analysis"] = run_interpret(
            visual_init, output_dir,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_timeout=INTERPRET_TIMEOUT,
            interpret_config=INTERPRET_CONFIG,
            ghidra_cmd=GHIDRA_CMD,
        )
        visual = report["visual_analysis"]
        if visual.get("enabled") and visual.get("analysis"):
            va = visual["analysis"]
            ransom = va.get("ransom_note_detected", False)
            events = len(va.get("notable_events", []))
            evasion = va.get("evasion_signal", False)
            log.info(f"  Notable events: {events}, Ransom note: {ransom}, Evasion signal: {evasion}")
            if va.get("payment_info"):
                for p in va["payment_info"]:
                    log.info(f"  Payment [{p.get('type')}]: {p.get('value', '')[:60]}")
        elif visual.get("error"):
            log.warning(f"Visual analysis error: {visual['error']}")

    _summary_start = _time.time()
    update_stage(analysis_id_early, "summary", "started")
    if INTERPRET_ENABLED:
        summary_model = INTERPRET_CONFIG.get("summary_model", INTERPRET_CONFIG.get("model", "?"))
        log.info(f"\n[Stage 5] Executive Summary: generating with {summary_model}...")
        report["executive_summary"] = run_summarize(
            report,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_config=INTERPRET_CONFIG,
        )
        summary = report["executive_summary"]
        if summary.get("executive_summary"):
            severity = summary.get("severity", "?")
            findings = len(summary.get("key_findings", []))
            log.info(f"  Severity: {severity}, Key findings: {findings}")
        elif summary.get("error"):
            log.warning(f"Error: {summary['error']}")
    else:
        report["executive_summary"] = {"enabled": False, "reason": "disabled_by_config"}
    stage_timings["summary"] = round(_time.time() - _summary_start, 1)
    update_stage(analysis_id_early, "summary", "completed", f"{stage_timings['summary']:.0f}s")

    # Plain English summary for non-technical audiences
    if INTERPRET_ENABLED and report.get("executive_summary", {}).get("executive_summary"):
        log.info(f"\n[Stage 5.1] Plain English Summary: generating...")
        plain_result = run_plain_english(
            report,
            interpret_cmd=INTERPRET_CMD,
            interpret_enabled=INTERPRET_ENABLED,
            interpret_config=INTERPRET_CONFIG,
        )
        plain_text = plain_result.get("summary", "") if isinstance(plain_result, dict) else plain_result
        if plain_text:
            report["plain_english_summary"] = plain_text
            report["plain_english_usage"] = plain_result.get("usage", {}) if isinstance(plain_result, dict) else {}
            # Store the model so cost tracking prices it correctly (it may be local = $0).
            report["plain_english_model"] = plain_result.get("model", "") if isinstance(plain_result, dict) else ""
            log.info(f"  {plain_text[:100]}...")
        else:
            report["plain_english_summary"] = ""
    else:
        report["plain_english_summary"] = ""

    # Merge LLM-generated IOC-technique links from executive summary
    llm_links = report.get("executive_summary", {}).get("ioc_technique_links", [])
    if llm_links:
        existing_keys = {(m["ioc_value"], m["technique_id"])
                         for m in report.get("ioc_technique_mappings", [])}
        for link in llm_links:
            key = (link.get("ioc_value", ""), link.get("technique_id", ""))
            if key[0] and key[1] and key not in existing_keys:
                report["ioc_technique_mappings"].append({
                    "ioc_type": link.get("ioc_type", ""),
                    "ioc_value": link["ioc_value"],
                    "technique_id": link["technique_id"],
                    "technique_name": link.get("technique_name", ""),
                    "evidence": link.get("evidence", ""),
                    "method": "llm",
                    "confidence": "medium",
                })
                existing_keys.add(key)
        log.info(f"  LLM added {len(llm_links)} IOC-technique links")

    # Timing summary
    total_elapsed = round(_time.time() - pipeline_start, 1)
    stage_timings["total"] = total_elapsed
    report["timing"] = stage_timings
    log.info(f"[Timing] Total: {total_elapsed:.0f}s | " +
             " | ".join(f"{k}: {v:.0f}s" for k, v in stage_timings.items() if k != "total"))

    # Write merged report (includes executive summary)
    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    report_path = write_report(task_id, report, REPORTS_DIR)
    log.info(f"\n[Done] JSON report: {report_path}")

    # Database ingestion — write structured data to PostgreSQL
    log.info(f"\n[DB Ingestion] Writing to database...")
    analysis_id = ingest_to_db(report, existing_analysis_id=analysis_id_early)

    # Stage 6: PDF report generation (containerized)
    log.info(f"\n[Stage 6] PDF Report: generating...")
    _pdf_start = _time.time()
    update_stage(analysis_id_early, "pdf", "started")
    pdf_path = report_path.parent / "report.pdf"
    try:
        result = subprocess.run(
            [PDF_CMD, str(report_path), str(pdf_path)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd="/tmp",
        )
        if result.returncode == 0:
            log.info(f"  PDF written to: {pdf_path}")
            if analysis_id:
                mark_pdf_generated(analysis_id)
        else:
            log.error(f"  [!] PDF generation failed: {result.stderr[:500]}")
    except subprocess.TimeoutExpired:
        log.error("  [!] PDF generation timed out (120s)")
    except Exception as e:
        log.error(f"  [!] PDF generation error: {e}")
    stage_timings["pdf"] = round(_time.time() - _pdf_start, 1)
    update_stage(analysis_id_early, "pdf", "completed", f"{stage_timings['pdf']:.0f}s")

    # Mark pipeline complete — must be AFTER all stages including PDF
    complete_pipeline(analysis_id or analysis_id_early, "completed",
                      stage_timings=stage_timings)

    return report


def run_replay(report_path: Path, stages: list[str] | None = None) -> dict:
    """Re-run analysis stages on a saved report.json.

    Loads collected data from a previous run and re-executes the fast
    post-collection stages. Use this to iterate on reporting, IOC
    extraction, severity logic, and dashboard rendering without waiting
    for Cape/Volatility/Ghidra to re-run.

    Replayable stages (default: all):
      correlate   — cross-tool correlation
      analysis    — programmatic family/severity/MITRE
      iocs        — IOC extraction
      summary     — executive summary (LLM call)
      db          — database ingestion
      pdf         — PDF report generation
    """
    log.info(f"Replay] Loading {report_path}")
    with report_path.open() as f:
        report = json.load(f)

    task_id = report.get("task_id", report_path.parent.name)
    output_dir = REPORTS_DIR / task_id
    output_dir.mkdir(parents=True, exist_ok=True)
    add_file_logging(output_dir)

    all_stages = ["correlate", "analysis", "iocs", "summary", "db", "pdf"]
    run_stages = stages if stages else all_stages

    log.info(f"Replay] Task: {task_id}")
    log.info(f"Replay] Stages: {', '.join(run_stages)}")

    if "correlate" in run_stages:
        log.info(f"\n[Cross-Correlation] Comparing Cape and Volatility data...")
        report["cross_correlations"] = cross_correlate(report)
        for finding in report["cross_correlations"]:
            sev = finding.get("severity", "info")
            title = finding.get("title", "?")
            sources = " + ".join(finding.get("sources", []))
            log.info(f"  [{sev.upper()}] {title} ({sources})")
        if not report["cross_correlations"]:
            log.info("  No cross-tool findings detected")

    if "analysis" in run_stages:
        log.info(f"\n[Analysis] Programmatic analysis...")
        report["family"] = determine_family(report)
        report["severity"] = calculate_severity(report)
        report["mitre_mapping"] = build_mitre_mapping(report)
        log.info(f"  Family: {report['family']} (source: {report.get('_family_source', '?')})")
        log.info(f"  Severity: {report['severity']} (score: {report.get('_severity_score', '?')})")
        log.info(f"  MITRE techniques: {len(report['mitre_mapping'])}")

    if "iocs" in run_stages:
        log.info(f"\n[IOC Extraction] Scanning all stages for indicators...")
        report["extracted_iocs"] = extract_iocs(report)
        ioc_count = len(report["extracted_iocs"])
        ioc_types = {}
        for ioc in report["extracted_iocs"]:
            t = ioc["type"]
            ioc_types[t] = ioc_types.get(t, 0) + 1
        log.info(f"  Found {ioc_count} IOCs: {ioc_types}")

    if "summary" in run_stages:
        if INTERPRET_ENABLED:
            log.info(f"\n[Executive Summary] Generating...")
            report["executive_summary"] = run_summarize(
                report,
                interpret_cmd=INTERPRET_CMD,
                interpret_enabled=INTERPRET_ENABLED,
                interpret_config=INTERPRET_CONFIG,
            )
            summary = report["executive_summary"]
            if summary.get("executive_summary"):
                log.info(f"  Key findings: {len(summary.get('key_findings', []))}")
            elif summary.get("error"):
                log.warning(f"Error: {summary['error']}")

    # Write updated report
    report["replayed_at"] = datetime.now(timezone.utc).isoformat()
    report["replayed_stages"] = run_stages
    new_report_path = write_report(task_id, report, REPORTS_DIR)
    log.info(f"\n[Done] Updated report: {new_report_path}")

    if "db" in run_stages:
        log.info(f"\n[DB Ingestion] Writing to database...")
        analysis_id = ingest_to_db(report)
    else:
        analysis_id = None

    if "pdf" in run_stages:
        log.info(f"\n[PDF Report] Generating...")
        pdf_path = new_report_path.parent / "report.pdf"
        try:
            result = subprocess.run(
                [PDF_CMD, str(new_report_path), str(pdf_path)],
                capture_output=True,
                text=True,
                timeout=120,
                cwd="/tmp",
            )
            if result.returncode == 0:
                log.info(f"  PDF written to: {pdf_path}")
                if analysis_id:
                    mark_pdf_generated(analysis_id)
            else:
                log.error(f"  [!] PDF generation failed: {result.stderr[:500]}")
        except subprocess.TimeoutExpired:
            log.error("  [!] PDF generation timed out (120s)")
        except Exception as e:
            log.error(f"  [!] PDF generation error: {e}")

    return report


def main():
    parser = argparse.ArgumentParser(
        prog="run-pipeline",
        description="Run the multi-stage malware analysis pipeline.",
    )
    parser.add_argument("sample", type=Path,
                        help="Path to the malware sample (or report.json with --replay)")
    parser.add_argument("--task-id", default=None,
                        help="Pipeline task ID (auto-generated if not set)")
    parser.add_argument("--filename", default="",
                        help="Original filename (used for Cape submission and reporting)")
    parser.add_argument("--replay", action="store_true",
                        help="Replay mode: re-run post-collection stages on a saved report.json")
    parser.add_argument("--stages", default=None,
                        help="Comma-separated stages to replay (default: all). "
                             "Options: correlate,analysis,iocs,summary,db,pdf")
    parser.add_argument("--bazaar-family", default="",
                        help="MalwareBazaar signature/family name (passed from auto-feeder)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug-level logging")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)

    if not args.sample.exists():
        log.error(f"Error: file not found: {args.sample}")
        sys.exit(1)

    if args.replay:
        stages = args.stages.split(",") if args.stages else None
        run_replay(args.sample, stages=stages)
    else:
        if not CAPE_API_KEY:
            raise SystemExit(
                "CAPE_API_KEY not set — source /opt/pipeline/pipeline.env "
                "(or export CAPE_API_KEY) before a live run"
            )
        task_id = args.task_id or uuid.uuid4().hex[:12]
        report = run_pipeline(args.sample, task_id, original_name=args.filename,
                              bazaar_family=args.bazaar_family)

        # Print summary
        triage = report.get("triage", {})
        yara_count = len(triage.get("yara_matches", []))
        cape_status = report.get("cape", {}).get("status", "n/a")
        vol_triggered = report.get("volatility", {}).get("triggered", False)
        ghidra_triggered = report.get("ghidra", {}).get("triggered", False)

        llm_enabled = report.get("llm_interpretation", {}).get("enabled", False)
        llm_family = report.get("llm_interpretation", {}).get("analysis", {}).get("malware_family_guess", "n/a")

        log.info(f"\nSummary:")
        log.info(f"  Triage:     {yara_count} YARA matches")
        log.info(f"  Cape:       {cape_status}")
        log.info(f"  Volatility: {'triggered' if vol_triggered else 'not triggered'}")
        log.info(f"  Ghidra:     {'triggered' if ghidra_triggered else 'not triggered'}")
        log.info(f"  LLM:        {llm_family if llm_enabled else 'disabled'}")


if __name__ == "__main__":
    main()
