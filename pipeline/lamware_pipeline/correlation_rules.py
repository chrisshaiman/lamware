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
import ipaddress
import os

_CAPE_STORAGE_ROOT = "/opt/CAPEv2/storage/analyses"
_PIPELINE_REPORTS_ROOT = "/opt/pipeline/reports"
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

def _within_allowed_root(path: str) -> bool:
    """True if `path` resolves under an allowed read root (defends against traversal
    via a poisoned path value). Dropped files live under the CAPE storage tree;
    injection-buffer dumps live under the pipeline reports tree
    (output_dir/cape_injections). Both roots are read at call time so tests can
    monkeypatch them. NOTE: hardcoded for parity with the existing storage-root
    constant; a future config-driven version could source these from PipelineConfig."""
    try:
        real = os.path.realpath(path)
    except (ValueError, OSError):
        return False
    for root in (_CAPE_STORAGE_ROOT, _PIPELINE_REPORTS_ROOT):
        try:
            if os.path.commonpath([real, root]) == root:
                return True
        except (ValueError, OSError):
            continue
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
        if _within_allowed_root(dropped_dir) and os.path.isdir(dropped_dir):
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
        if not buf_path or not _within_allowed_root(buf_path):
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

    # PIDs are keyed as STRINGS on both sides. Volatility's json renderer gives
    # ints, and stages/cape.py builds process_cmdlines from int process_id — but
    # json.dump turns dict keys into strings, so on the replay path (run_replay
    # reloads report.json) the CAPE side comes back string-keyed with no
    # coercion. The lookup missed on every process and the rule returned [] no
    # matter how badly a command line was spoofed. Replay is not read-only:
    # write_report() rewrites the same report.json, so a re-run erased the
    # original critical finding from the canonical artifact, and the degraded
    # report is what then feeds db_ingest and the PDF.
    vol_cmdlines = {}
    for entry in cmdline:
        pid = entry.get("PID", 0)
        args = entry.get("Args", "")
        if pid and args:
            vol_cmdlines[str(pid)] = args

    cape_cmdlines = cape.get("process_cmdlines", {})
    for pid, cape_cmd in cape_cmdlines.items():
        vol_cmd = vol_cmdlines.get(str(pid), "")
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


# --- New rule: C2 confirmed live in memory ---

_C2_CONFIG_KEY_HINTS = ("c2", "cnc", "cncs", "address", "host", "server")
_SKIP_FOREIGN = {"", "0.0.0.0", "::", "*", "127.0.0.1"}


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _cape_c2_ip_indicators(cape: dict) -> set:
    """IP literals from Cape config keys that suggest C2 (key-hint match) plus the network hosts list."""
    ips: set[str] = set()

    def _consume(value):
        if isinstance(value, str) and _is_ip_literal(value):
            ips.add(value)
        elif isinstance(value, list):
            for item in value:
                _consume(item)
        elif isinstance(value, dict):
            for v in value.values():
                _consume(v)

    for cfg in cape.get("extracted_configs", []):
        if not isinstance(cfg, dict):
            continue
        for key, value in cfg.items():
            if any(hint in key.lower() for hint in _C2_CONFIG_KEY_HINTS):
                _consume(value)

    network = cape.get("network", {})
    if isinstance(network, dict):
        for host in network.get("hosts", []):
            if isinstance(host, dict):
                _consume(host.get("ip", ""))
            else:
                _consume(host)
    return ips


def rule_c2_live_in_memory(report: dict) -> list[dict]:
    """Cape-identified C2 IP that is also an active foreign connection in
    Volatility netscan → the C2 channel was live at capture. IP-literal match only
    (domain->IP resolution is future work)."""
    findings = []
    cape = report.get("cape", {})
    netscan = report.get("volatility", {}).get("plugins", {}).get("netscan", [])
    if not isinstance(netscan, list) or not netscan:
        return findings

    c2_ips = _cape_c2_ip_indicators(cape)
    if not c2_ips:
        return findings

    seen_ips = set()
    for conn in netscan:
        foreign = conn.get("ForeignAddr", "")
        if foreign in _SKIP_FOREIGN or foreign not in c2_ips or foreign in seen_ips:
            continue
        seen_ips.add(foreign)
        findings.append({
            "type": "c2_live_in_memory",
            "severity": "high",
            "title": f"C2 endpoint {foreign} was live in memory",
            "detail": (f"Cape config/network identified {foreign} as C2; Volatility "
                       f"netscan shows an active connection to it "
                       f"(PID {conn.get('PID', '?')}, {conn.get('State', '?')})."),
            "indicator": foreign,
            "pid": conn.get("PID", 0),
            "sources": ["Cape", "Volatility"],
            "mitre": "T1071 — Application Layer Protocol",
        })
    return findings


# --- New rule: injection corroborated in memory ---

def rule_injection_corroborated(report: dict) -> list[dict]:
    """Cape flagged injection into a PID AND Volatility malfind found an anomalous
    executable region in that same PID → injection confirmed in memory.

    severity=medium (not high): injection is common and malfind is FP-prone, so
    this corroboration is a confidence signal, not an impact escalation; and
    calculate_severity already adds +10 for the presence of injection_buffers, so
    scoring it high would double-count. medium is score-neutral.
    """
    findings = []
    cape = report.get("cape", {})
    malfind = report.get("volatility", {}).get("plugins", {}).get("malfind", [])
    injection_bufs = cape.get("injection_buffers", [])
    if not (isinstance(malfind, list) and injection_bufs):
        return findings

    malfind_pids = {}
    for region in malfind:
        pid = region.get("PID")
        if pid is not None:
            malfind_pids[pid] = malfind_pids.get(pid, 0) + 1

    seen_target_pids: set = set()
    target_pids = []
    for buf in injection_bufs:
        pid = buf.get("target_pid")
        if pid is not None and pid not in seen_target_pids:
            seen_target_pids.add(pid)
            target_pids.append(pid)

    for pid in target_pids:
        if pid in malfind_pids:
            n = malfind_pids[pid]
            findings.append({
                "type": "injection_corroborated",
                "severity": "medium",
                "title": f"Process injection into PID {pid} corroborated in memory",
                "detail": (f"Cape flagged injection into PID {pid}; Volatility malfind "
                           f"found {n} anomalous executable region(s) in that process."),
                "pid": pid,
                "sources": ["Cape", "Volatility"],
                "mitre": "T1055 — Process Injection",
            })
    return findings


# -------------------------------------------------------------------------
# Registry + entrypoint
# -------------------------------------------------------------------------

_RULES = [
    rule_dropped_file_loaded,
    rule_shellcode_self_modified,
    rule_cmdline_spoofing,
    rule_c2_live_in_memory,
    rule_injection_corroborated,
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
