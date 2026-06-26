# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cross-tool correlation rule registry.

cross_correlate() is the public entrypoint (re-exported from correlation.py for
backward compatibility). It enriches the report with filesystem-gathered inputs
(the only impure step), evaluates a registry of pure rule functions, then strips
the gathered inputs before returning so raw payload bytes are never persisted.

Each rule is a pure function (report: dict) -> list[dict]; findings preserve the
historical key shape (type, severity, title, detail, sources, mitre, ...).
"""
import os

_CAPE_STORAGE_ROOT = "/opt/CAPEv2/storage/analyses"
# Volatility 3 malfind emits a 64-byte hexdump by default; this bound must exceed
# the largest hexdump the pipeline produces, or self-modification past this offset
# is not compared. Kept bounded (not a full-buffer read) so adversary-controlled
# buffers can't force large reads.
_BUFFER_SAMPLE_BYTES = 128
_MAX_DROPPED_FILES = 1000


# -------------------------------------------------------------------------
# Enrichment — the ONLY impure step (filesystem). Idempotent + bounded +
# path-contained. Results land in report["_correlation_inputs"] and are popped
# by cross_correlate() before return so payload bytes never persist.
# -------------------------------------------------------------------------

def _within_storage_root(path: str) -> bool:
    """True if `path` resolves to a location under the CAPE storage root."""
    try:
        real = os.path.realpath(path)
        return os.path.commonpath([real, _CAPE_STORAGE_ROOT]) == _CAPE_STORAGE_ROOT
    except (ValueError, OSError):
        # commonpath raises ValueError across drives / mixed abs-rel paths
        return False


def _gather_dropped_files(report: dict) -> list[str]:
    """Filenames from ghidra shellcode artifacts + the CAPE dropped dir (bounded)."""
    names: list[str] = []
    # Pure: shellcode artifact paths already present in the report
    for af in report.get("ghidra", {}).get("analyzed_files", []):
        for path in af.get("shellcode_artifacts", {}).get("file_paths", []):
            names.append(path)
    # Impure: list the CAPE dropped dir if task_id known and path is contained
    task_id = report.get("cape", {}).get("task_id")
    if task_id:
        dropped_dir = os.path.join(_CAPE_STORAGE_ROOT, str(task_id), "dropped")
        if _within_storage_root(dropped_dir) and os.path.isdir(dropped_dir):
            try:
                for fname in os.listdir(dropped_dir):
                    names.append(fname)
                    if len(names) >= _MAX_DROPPED_FILES:
                        break
            except OSError:
                pass
    return names[:_MAX_DROPPED_FILES]


def _gather_buffer_samples(report: dict) -> dict:
    """Truncated, hex-encoded head bytes of each injection buffer, keyed
    'target_pid:injection_address'. Path-contained + bounded read."""
    samples: dict[str, str] = {}
    for buf in report.get("cape", {}).get("injection_buffers", []):
        buf_path = buf.get("path", "")
        if not buf_path or not _within_storage_root(buf_path):
            continue
        key = f"{buf.get('target_pid', 0)}:{buf.get('injection_address', '')}"
        try:
            with open(buf_path, "rb") as f:
                samples[key] = f.read(_BUFFER_SAMPLE_BYTES).hex()
        except OSError:
            continue
    return samples


def enrich_correlation_inputs(report: dict) -> dict:
    """Populate report['_correlation_inputs'] from the filesystem. Idempotent:
    overwrites wholesale so replay re-runs are safe. Returns the (mutated) report."""
    report["_correlation_inputs"] = {
        "dropped_files": _gather_dropped_files(report),
        "buffer_samples": _gather_buffer_samples(report),
    }
    return report


# -------------------------------------------------------------------------
# Rules — pure functions of the report dict (read _correlation_inputs only).
# -------------------------------------------------------------------------

def rule_dropped_file_loaded(report: dict) -> list[dict]:
    """Dropped file (Cape) confirmed loaded into a process (Volatility dlllist)."""
    findings = []
    dropped_files = report.get("_correlation_inputs", {}).get("dropped_files", [])
    dlllist = report.get("volatility", {}).get("plugins", {}).get("dlllist", [])
    if not (isinstance(dlllist, list) and dropped_files):
        return findings

    loaded_dlls = set()
    for entry in dlllist:
        dll_path = entry.get("Path", "")
        dll_name = entry.get("Name", "")
        if dll_path:
            loaded_dlls.add(dll_path.lower())
            loaded_dlls.add(dll_name.lower() if dll_name else "")

    for dropped in dropped_files:
        dropped_name = dropped.lower().split("\\")[-1].split("/")[-1]
        if dropped_name in loaded_dlls or any(dropped_name in dll for dll in loaded_dlls if dll):
            pid_loaded_by = []
            for entry in dlllist:
                if dropped_name in (entry.get("Path", "") + entry.get("Name", "")).lower():
                    pid_loaded_by.append(f"{entry.get('Process', '?')} (pid {entry.get('PID', '?')})")
            findings.append({
                "type": "dropped_file_loaded",
                "severity": "high",
                "title": f"Dropped file '{dropped_name}' was loaded and executed",
                "detail": f"Cape observed this file being written to disk. Volatility confirms it was loaded by: {', '.join(set(pid_loaded_by[:5]))}",
                "sources": ["Cape", "Volatility"],
                "mitre": "T1059 — Execution",
            })
    return findings


def rule_shellcode_self_modified(report: dict) -> list[dict]:
    """Injected shellcode that differs in memory (Volatility malfind) from the
    bytes Cape captured at injection time → self-modification.

    Byte-comparison preserved from the original: the gathered sample (<=128B) is
    trimmed to the malfind hexdump length, so the compare is identical to the old
    `f.read(len(malfind_bytes))` (malfind hexdumps are always far shorter than 128).
    """
    findings = []
    cape = report.get("cape", {})
    buffer_samples = report.get("_correlation_inputs", {}).get("buffer_samples", {})
    injection_bufs = cape.get("injection_buffers", [])
    malfind = report.get("volatility", {}).get("plugins", {}).get("malfind", [])
    if not (isinstance(malfind, list) and injection_bufs):
        return findings

    for buf in injection_bufs:
        target_pid = buf.get("target_pid", 0)
        inject_addr = buf.get("injection_address", "")
        sample_hex = buffer_samples.get(f"{target_pid}:{inject_addr}", "")
        if not sample_hex:
            continue
        cape_sample = bytes.fromhex(sample_hex)

        for region in malfind:
            region_pid = region.get("PID", 0)
            region_start = region.get("Start VPN", 0)
            if isinstance(region_start, int):
                region_start_hex = f"0x{region_start:08x}"
            else:
                region_start_hex = str(region_start)
            if region_pid != target_pid or inject_addr != region_start_hex:
                continue

            hexdump = region.get("Hexdump", "")
            try:
                malfind_bytes = bytes(
                    int(h, 16) for h in hexdump.split()
                    if h and len(h) == 2 and all(c in "0123456789abcdefABCDEF" for c in h)
                ) if hexdump else b""
            except (ValueError, TypeError):
                malfind_bytes = b""

            cape_bytes = cape_sample[:len(malfind_bytes)]
            if cape_bytes and malfind_bytes and cape_bytes != malfind_bytes[:len(cape_bytes)]:
                findings.append({
                    "type": "shellcode_self_modified",
                    "severity": "high",
                    "title": f"Injected shellcode self-modified in PID {target_pid} at {inject_addr}",
                    "detail": "Memory content differs from what was originally injected.",
                    "before": cape_bytes[:64].hex(),
                    "after": malfind_bytes[:64].hex(),
                    "pid": target_pid,
                    "address": inject_addr,
                    "sources": ["Cape", "Volatility"],
                    "mitre": "T1027 — Obfuscated Files or Information",
                })
            break
    return findings


_BENIGN_CMDLINE_FLAGS = ["-embedding", "-secured", "/prefetch:", "-servername:"]


def _is_benign_cmdline_difference(before: str, after: str) -> bool:
    """True if the only cmdline difference is a known benign flag (e.g. COM -Embedding)."""
    b = before.strip().lower()
    a = after.strip().lower()
    for flag in _BENIGN_CMDLINE_FLAGS:
        if b.replace(flag, "").strip() == a.replace(flag, "").strip():
            return True
        b_no_flag = " ".join(p for p in b.split() if flag not in p.lower())
        a_no_flag = " ".join(p for p in a.split() if flag not in p.lower())
        if b_no_flag == a_no_flag:
            return True
    return False


def rule_cmdline_spoofing(report: dict) -> list[dict]:
    """Process cmdline in memory (Volatility PEB) differs from the launch cmdline
    Cape logged → command-line spoofing. Verbatim logic from the original rule."""
    findings = []
    cape = report.get("cape", {})
    cmdline = report.get("volatility", {}).get("plugins", {}).get("cmdline", [])
    if not isinstance(cmdline, list):
        return findings

    vol_cmdlines = {}
    for entry in cmdline:
        pid = entry.get("PID", 0)
        args = entry.get("Args", "")
        if pid and args:
            vol_cmdlines[pid] = args

    cape_cmdlines = cape.get("process_cmdlines", {})
    for pid, cape_cmd in cape_cmdlines.items():
        vol_cmd = vol_cmdlines.get(pid, "")
        if vol_cmd and cape_cmd and vol_cmd.strip() != cape_cmd.strip():
            if vol_cmd.strip().lower() != cape_cmd.strip().lower():
                if _is_benign_cmdline_difference(cape_cmd, vol_cmd):
                    continue
                findings.append({
                    "type": "cmdline_spoofing",
                    "severity": "critical",
                    "title": f"Command line spoofing detected in PID {pid}",
                    "detail": "Process command line changed between execution and memory dump.",
                    "before": cape_cmd[:300],
                    "after": vol_cmd[:300],
                    "pid": pid,
                    "sources": ["Cape", "Volatility"],
                    "mitre": "T1036 — Masquerading",
                })
    return findings


# -------------------------------------------------------------------------
# Registry + entrypoint
# -------------------------------------------------------------------------

_RULES = [
    rule_dropped_file_loaded,
    rule_shellcode_self_modified,
    rule_cmdline_spoofing,
]


def evaluate_rules(report: dict) -> list[dict]:
    """Pure: concatenate findings from every registered rule, in registry order."""
    return [finding for rule in _RULES for finding in rule(report)]


def cross_correlate(report: dict) -> list[dict]:
    """Public entrypoint. Enrich (filesystem) -> evaluate pure rules -> strip inputs."""
    enrich_correlation_inputs(report)
    try:
        return evaluate_rules(report)
    finally:
        report.pop("_correlation_inputs", None)
