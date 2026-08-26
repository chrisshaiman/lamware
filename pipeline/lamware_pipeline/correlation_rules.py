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
import json
import os
import re
from urllib.parse import urlsplit

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


#: files.json categories that are CAPE's own dump artifacts rather than files
#: the sample wrote. Their `filepath` points into the randomised per-analysis
#: staging directory (C:\<random>\CAPE\<pid>_<ts>), which is not a guest path
#: the sample chose and will never appear in dlllist.
_CAPE_INTERNAL_CATEGORIES = {"CAPE", "procdump", "memory"}
_ABS_WINDOWS_PATH_RE = re.compile(r"^[a-zA-Z]:[\\/]")


def _gather_dropped_files(report: dict) -> tuple[list[str], str | None]:
    """Guest paths of files the sample wrote, from CAPE's files.json manifest.

    Returns (paths, reason_the_manifest_could_not_be_read). Bounded and
    path-contained.

    This used to list ``<task>/dropped/`` and return bare filenames. CAPEv2 does
    not create that directory — it is Cuckoo's layout — so the listing found
    nothing on any of the 1024 analyses on this host, and the only other source
    was ``ghidra.analyzed_files[].shellcode_artifacts.file_paths``. Those are
    Windows path STRINGS scraped by regex out of the first 64KB of a malfind
    dump (see extract_shellcode_artifacts): what injected code mentions while
    resolving imports, not what it wrote to disk. Feeding them to a rule that
    reports "dropped file was loaded and executed" is a category error, and it
    is the mechanism by which shellcode merely referencing a system DLL would
    have produced a HIGH finding once the substring join matched it.

    files.json is JSON Lines, one record per artifact CAPE retained, with the
    guest path in `filepath` and the storage location in `path`. Records whose
    filepath is not an absolute Windows path are CAPE's hash-named entries with
    no known origin, and cannot be correlated against a loaded module.
    """
    cape = report.get("cape")
    if not isinstance(cape, dict) or not cape:
        # Cape did not run. Same treatment as `triggered: False` on the
        # Volatility side: a reported pipeline state, not a silent degradation
        # of correlation, so it produces no warning.
        return [], None
    task_id = cape.get("task_id")
    if not task_id:
        return [], "no Cape task id in report"
    manifest = os.path.join(_CAPE_STORAGE_ROOT, str(task_id), "files.json")
    if not _within_allowed_root(manifest):
        return [], "manifest path outside the allowed storage root"
    if not os.path.isfile(manifest):
        return [], f"{manifest} not found"

    names: list[str] = []
    try:
        with open(manifest, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("category") in _CAPE_INTERNAL_CATEGORIES:
                    continue
                filepath = record.get("filepath")
                if not isinstance(filepath, str) or not _ABS_WINDOWS_PATH_RE.match(filepath):
                    continue
                names.append(filepath)
                if len(names) >= _MAX_DROPPED_FILES:
                    break
    except OSError as exc:
        return [], f"{type(exc).__name__} reading {manifest}"
    return names[:_MAX_DROPPED_FILES], None


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


def _vad_containing(vadinfo: list, pid, address: int) -> dict | None:
    """The VAD of `pid` that contains `address`, or None.

    Containment, not equality. The old rule required Cape's injection address to
    EQUAL malfind's Start VPN, which is a coincidence rather than a relation: a
    cross-process write lands wherever the allocation happens to be, not at a VAD
    boundary. Measured on task 1043 — 31 buffers against 399 malfind regions —
    equality matched 0 and containment matched 0, because malfind reports only
    RWX VADs and these writes went into PAGE_NOACCESS (10) and
    PAGE_EXECUTE_WRITECOPY (16). vadinfo returns every VAD, and containment
    against it matched 27 of 31.
    """
    for vad in vadinfo:
        if not isinstance(vad, dict) or vad.get("PID") != pid:
            continue
        start, end = vad.get("Start VPN"), vad.get("End VPN")
        if isinstance(start, int) and isinstance(end, int) and start <= address <= end:
            return vad
    return None


# vadinfo's "File output" column is a status, not always a path. Besides
# "Disabled" it reports "Error outputting file" — which is what a VAD larger
# than --maxsize returns. Treating that as a filename builds a bogus path and
# leans on OSError to notice; naming the sentinels says what is actually true.
_VAD_NON_DUMP = ("disabled", "error outputting file")


def _is_dump_filename(name: str) -> bool:
    return bool(name) and name.strip().lower() not in _VAD_NON_DUMP


def _gather_vad_samples(report: dict) -> tuple[dict, str | None, int]:
    """Memory bytes at each injection address, from the VAD dumps vadinfo wrote.

    Keyed 'target_pid:injection_address' to match `buffer_samples`, so the rule
    compares two hex strings gathered the same way — Cape's bytes at write time
    against the same offset in memory at capture time.

    Returns (samples, reason_it_is_empty, unresolved_count). The reason is what
    stops a missing dump from reading as "the bytes were identical" (#452); the
    count is the same argument one level finer. A buffer we could not read is
    not evidence of an unmodified buffer, so every bail-out below is counted
    rather than dropped, and a non-zero count is reported even when other
    addresses resolved fine (#460).
    """
    samples: dict[str, str] = {}
    vol = report.get("volatility")
    if not isinstance(vol, dict):
        return samples, None, 0
    vadinfo = (vol.get("plugins") or {}).get("vadinfo")
    if not isinstance(vadinfo, list):
        return samples, "vadinfo did not run", 0
    dump_dir = vol.get("vad_dump_dir")
    if not dump_dir:
        return samples, "vadinfo ran but dumped no regions", 0
    if not _within_allowed_root(dump_dir):
        return samples, "vad dump directory outside the allowed read root", 0

    unresolved = 0
    for buf in report.get("cape", {}).get("injection_buffers", []):
        pid = buf.get("target_pid")
        addr_s = buf.get("injection_address", "")
        try:
            addr = int(str(addr_s), 16)
        except (ValueError, TypeError):
            # An address Cape wrote that we cannot parse is still a write we did
            # not compare.
            unresolved += 1
            continue
        vad = _vad_containing(vadinfo, pid, addr)
        if vad is None:
            # The write landed somewhere vadinfo has no VAD for — most often a
            # process that exited before capture.
            unresolved += 1
            continue
        name = vad.get("File output")
        if not isinstance(name, str) or not _is_dump_filename(name):
            unresolved += 1
            continue
        path = os.path.join(dump_dir, os.path.basename(name))
        if not _within_allowed_root(path):
            unresolved += 1
            continue
        offset = addr - vad["Start VPN"]
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                data = fh.read(_BUFFER_SAMPLE_BYTES)
        except OSError:
            unresolved += 1
            continue
        if not data:
            # Seeking past the end of a truncated dump reads b"". Silently
            # dropping it would let a short dump read as an unmodified buffer.
            unresolved += 1
            continue
        samples[f"{pid}:{addr_s}"] = data.hex()

    reason = None
    if unresolved and not samples:
        reason = f"no injection address resolved to a dumped VAD ({unresolved} unresolved)"
    return samples, reason, unresolved


def enrich_correlation_inputs(report: dict) -> dict:
    """Populate report['_correlation_inputs'] from the filesystem. Idempotent:
    overwrites wholesale so replay re-runs are safe. Returns the (mutated) report."""
    dropped_files, dropped_unavailable = _gather_dropped_files(report)
    vad_samples, vad_unavailable, vad_unresolved = _gather_vad_samples(report)
    report["_correlation_inputs"] = {
        "dropped_files": dropped_files,
        "dropped_files_unavailable": dropped_unavailable,
        "buffer_samples": _gather_buffer_samples(report),
        "vad_samples": vad_samples,
        "vad_samples_unavailable": vad_unavailable,
        "vad_samples_unresolved": vad_unresolved,
        "c2_scan_unavailable": _gather_vad_string_hits(
            report, _cape_c2_string_indicators(report.get("cape", {})))[1],
    }
    return report


# -------------------------------------------------------------------------
# Rules — pure functions of the report dict (read _correlation_inputs only).
# -------------------------------------------------------------------------

def _normalise_win_path(value: str) -> str:
    """Canonical form of a Windows path for equality comparison.

    SysWOW64 folds onto System32 because the two sides record opposite ends of
    WOW64 filesystem redirection: a 32-bit process writing to `System32` is
    transparently redirected to `SysWOW64`, Cape logs the path the API was
    called with, and Volatility reads the mapped file afterwards. Observed on
    task 1023, where the sample dropped
    `System32\\config\\systemprofile\\...\\UltraSuiteSmartCoreware\\ffmpeg.dll` and
    Grape.exe loaded the SysWOW64 form of the same path. Everything below the
    redirected root still has to match exactly, so this is nothing like the
    basename join it replaces.
    """
    return (value.strip().strip('"').replace("/", "\\").lower()
            .replace("\\syswow64\\", "\\system32\\"))


def _basename(path: str) -> str:
    """Last component of a Windows or POSIX path (os.path.basename is POSIX-only
    here — the pipeline runs on Linux and would keep the whole backslash path)."""
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def rule_dropped_file_loaded(report: dict) -> list[dict]:
    """Dropped file (Cape) confirmed loaded into a process (Volatility dlllist)."""
    findings = []
    dropped_files = report.get("_correlation_inputs", {}).get("dropped_files", [])
    dlllist = report.get("volatility", {}).get("plugins", {}).get("dlllist", [])
    if not (isinstance(dlllist, list) and dropped_files):
        return findings

    # Full paths only, on both sides. The rule used to reduce the dropped file
    # to its basename and then accept a SUBSTRING match against any loaded
    # module — so a sample dropping `ntdll.dll` anywhere correlated with the
    # system `c:\windows\system32\ntdll.dll` and reported HIGH. DLL
    # side-loading is the most common reason a dropped name collides with a
    # loaded one, so the rule misfired hardest on the samples it exists for.
    # dlllist entries without a Path cannot establish identity and are skipped:
    # matching a dropped file to a bare module NAME is the basename join again.
    loaded: dict[str, list[dict]] = {}
    for entry in dlllist:
        dll_path = entry.get("Path", "")
        if not dll_path:
            continue
        loaded.setdefault(_normalise_win_path(dll_path), []).append(entry)

    for dropped in dropped_files:
        key = _normalise_win_path(dropped)
        if not key or key not in loaded:
            continue
        pid_loaded_by = []
        for entry in loaded[key]:
            pid_loaded_by.append(f"{entry.get('Process', '?')} (pid {entry.get('PID', '?')})")
        findings.append({
            "type": "dropped_file_loaded",
            "severity": "high",
            "title": f"Dropped file '{_basename(dropped)}' was loaded and executed",
            "detail": f"Cape observed this file being written to {dropped}. Volatility confirms it was loaded by: {', '.join(dict.fromkeys(pid_loaded_by[:5]))}",
            "sources": ["Cape", "Volatility"],
            "mitre": "T1059 — Execution",
        })
    return findings


def rule_shellcode_self_modified(report: dict) -> list[dict]:
    """Injected bytes that differ in memory from what Cape captured at write time.

    Joins on VAD CONTAINMENT via `windows.vadinfo`, not on equality with
    malfind's Start VPN. The old rule required Cape's injection address to equal
    a malfind region's start, and measured against task 1043 that matched 0 of
    31 — not because the tools disagree, but because malfind reports only
    PAGE_EXECUTE_READWRITE VADs by design, and these writes land in
    PAGE_NOACCESS (10 of 27) and PAGE_EXECUTE_WRITECOPY (16 of 27): a region
    allocated non-executable and flipped later, or a copy-on-write patch of a
    mapped module. Stock malfind returns 0 on that dump even with no time limit,
    so the 120s cap was never the cause.

    `windows.vadinfo --pid <targets>` returns every VAD regardless of protection
    and takes 2.84s for two processes in one invocation, which is cheaper than
    the malfind run it replaces.

    Both sides are read at the same offset: Cape's bytes at the moment of the
    write, against `injection_address - Start VPN` within the dumped VAD.
    """
    findings = []
    inputs = report.get("_correlation_inputs", {})
    cape_samples = inputs.get("buffer_samples", {})
    vad_samples = inputs.get("vad_samples", {})
    if not (cape_samples and vad_samples):
        return findings

    for buf in report.get("cape", {}).get("injection_buffers", []):
        pid = buf.get("target_pid")
        addr = buf.get("injection_address", "")
        key = f"{pid}:{addr}"
        cape_hex, mem_hex = cape_samples.get(key), vad_samples.get(key)
        if not (cape_hex and mem_hex):
            continue
        try:
            cape_bytes = bytes.fromhex(cape_hex)
            mem_bytes = bytes.fromhex(mem_hex)
        except ValueError:
            continue

        # Compare only the overlap. Cape truncates its capture (the pipeline logs
        # "injection buffer TRUNCATED by Cape: captured 256 of 336 bytes"), so the
        # shorter side bounds the comparison — otherwise every truncated buffer
        # reads as modified.
        n = min(len(cape_bytes), len(mem_bytes))
        if n == 0 or cape_bytes[:n] == mem_bytes[:n]:
            continue

        findings.append({
            "type": "shellcode_self_modified",
            "severity": "high",
            "title": f"Injected shellcode self-modified in PID {pid} at {addr}",
            "detail": (f"Cape captured {len(cape_bytes)} bytes at write time; memory at "
                       f"the same address differs within the first {n} bytes."),
            "before": cape_bytes[:64].hex(),
            "after": mem_bytes[:64].hex(),
            "pid": pid,
            "address": addr,
            "sources": ["Cape", "Volatility"],
            "mitre": "T1027 — Obfuscated Files or Information",
        })
    return findings


_BENIGN_CMDLINE_FLAGS = ["-embedding", "-secured", "/prefetch:", "-servername:"]


def _is_benign_cmdline_difference(before: str, after: str) -> bool:
    """True if the only cmdline difference is a known benign flag (e.g. COM -Embedding).

    Gated on the flag actually appearing. Without that gate the second branch
    re-split both sides on whitespace and compared the results, which made the
    helper a general whitespace-insensitive comparator: a changed argument whose
    only difference was a space INSIDE quotes came back "benign" no matter which
    flag was being considered, and the rule stayed silent on a real change.
    """
    b = _normalise_cmdline(before)
    a = _normalise_cmdline(after)
    for flag in _BENIGN_CMDLINE_FLAGS:
        if flag not in b and flag not in a:
            continue
        if b.replace(flag, "").strip() == a.replace(flag, "").strip():
            return True
        b_no_flag = " ".join(p for p in b.split() if flag not in p)
        a_no_flag = " ".join(p for p in a.split() if flag not in p)
        if b_no_flag == a_no_flag:
            return True
    return False


#: A path component Windows shortened to 8.3 form: PROGRA~1, DOCUME~1. The two
#: sides of this rule read the same command line from different places — Cape
#: logs what the launcher passed, Volatility reads the PEB later — and either
#: may hold the short form. Resolving one to the other needs the guest
#: filesystem, which is gone by the time correlation runs.
_SHORT_PATH_RE = re.compile(r"~\d")


def _split_cmdline(value: str) -> list[str]:
    """Windows-ish argv split: whitespace-separated, double quotes group.

    Not shlex — shlex is POSIX and treats the backslashes in every Windows path
    as escapes, which mangles exactly the input this rule compares.
    """
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    for ch in value:
        if ch == '"':
            in_quotes = not in_quotes
        elif ch.isspace() and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def _normalise_cmdline(value: str) -> str:
    """Canonical form for comparing two recordings of the same command line.

    Removes the differences that are recording artefacts rather than evidence:
    argv0 quoting (Cape logs `"C:\\x.exe" -a`, the PEB may hold `C:\\x.exe -a`),
    runs of whitespace between arguments, and case. What survives is the
    argument vector, which is what "spoofing" would have to change.
    """
    return " ".join(_split_cmdline(value)).strip().lower()


def rule_cmdline_spoofing(report: dict) -> list[dict]:
    """Process cmdline in memory (Volatility PEB) differs from the launch cmdline
    Cape logged → command-line spoofing."""
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
        if not (vol_cmd and cape_cmd):
            continue
        # Normalise BEFORE comparing. The old rule compared raw strings and then
        # tried to explain the difference away with a four-entry flag deny-list,
        # which is the shape the frontend's DefangedAnchor comment argues
        # against: on a security boundary a deny-list has to enumerate every way
        # of writing the thing, and it never does. Quoting and whitespace are
        # not flags, so no deny-list entry could have covered them, and each one
        # produced a CRITICAL finding plus +10 on the deterministic severity
        # score that ADR-017 exists to keep free of unreliable signal.
        if _normalise_cmdline(vol_cmd) == _normalise_cmdline(cape_cmd):
            continue
        if _is_benign_cmdline_difference(cape_cmd, vol_cmd):
            continue
        # 8.3 vs long form is a recording difference we cannot resolve without
        # the guest filesystem. Staying silent loses a spoof that also happens
        # to involve a short path; firing calls an ordinary Windows path
        # abbreviation critical. For a rule feeding the deterministic score,
        # the miss is the cheaper error — and correlation_warnings is not the
        # right home for it either, since this is one process, not a blind rule.
        if _SHORT_PATH_RE.search(vol_cmd) or _SHORT_PATH_RE.search(cape_cmd):
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



# Scanning bounds for the C2-in-memory search. VAD dumps ran to 182MB for a
# single analysis, and every needle is checked against every byte, so this is
# capped. A truncated scan is REPORTED, never silent — "we stopped looking" must
# not read as "we looked and found nothing" (#460).
_VAD_SCAN_MAX_BYTES = 512 * 1024 * 1024
_VAD_SCAN_CHUNK = 8 * 1024 * 1024

#: An indicator has to be this long before it is worth hunting in memory. Short
#: strings match by accident in 8 GiB of process memory; "1.1.1.1" would hit
#: inside any longer number.
_MIN_INDICATOR_LEN = 7

#: Matching these in memory proves nothing. Everything resolves to the INetSim
#: gateway during detonation (#464), so it is in every dump by construction, and
#: RFC1918/loopback literals are ambient in any Windows image.
_UNROUTABLE_PREFIXES = ("10.", "127.", "169.254.", "192.168.", "0.", "255.")


def _is_routable_ip(value: str) -> bool:
    if not _is_ip_literal(value):
        return False
    if value.startswith(_UNROUTABLE_PREFIXES):
        return False
    if value.startswith("172."):
        try:
            second = int(value.split(".")[1])
        except (IndexError, ValueError):
            return False
        return not (16 <= second <= 31)
    return True


#: A hostname's last label is alphabetic. This is what separates a C2 domain
#: from the URI fragments families pack alongside it — "jquery-3.3.1.min.woff2"
#: has dots and no spaces and would otherwise pass as a host, then match nothing
#: in memory while looking like a real indicator.
_TLD_RE = re.compile(r"\A[a-z]{2,24}\Z", re.IGNORECASE)


def _looks_like_hostname(value: str) -> bool:
    labels = value.split(".")
    if len(labels) < 2 or not all(labels):
        return False
    return bool(_TLD_RE.match(labels[-1]))


def _cape_c2_string_indicators(cape: dict) -> set[str]:
    """C2 hosts worth hunting for in process memory.

    Deliberately narrower than the DNS/host lists. Every query resolves to the
    INetSim gateway, so `network.hosts` is dominated by 192.168.100.1, and the
    domain list carries whatever the sample's OS asked for — telemetry, CDNs,
    certificate checks. Hunting those in memory would produce a finding on every
    sample and mean nothing.

    Config-extracted values are the high-confidence source: Cape only populates
    them when it has decoded a family's configuration, and the key hints already
    filter to C2-ish fields. Domains are included here where the IP-only rule
    excluded them, because a domain string is exactly what survives in memory
    when the resolution itself went nowhere.
    """
    out: set[str] = set()

    def _add(raw: str):
        # Cobalt Strike packs several fields into one string:
        #   "104.207.140.119,/jquery-3.3.1.min.woff2"
        # Kept whole it is a needle that cannot match anything in memory, so
        # split on the separators families use before deciding what each part is.
        if any(sep in raw for sep in ",;|"):
            for part in re.split(r"[,;|]", raw):
                _add(part)
            return
        v = raw.strip()
        if not v:
            return
        # A C2 value is very often a full URL. The hostname is the better needle:
        # a path may not sit contiguously in memory, and the same host appears
        # across every URL a family carries.
        if "://" in v:
            host = urlsplit(v).hostname or ""
            if host:
                v = host
        v = v.strip("/")
        if len(v) < _MIN_INDICATOR_LEN:
            return
        if _is_ip_literal(v):
            if _is_routable_ip(v):
                out.add(v)
        elif " " not in v and len(v) <= 253 and _looks_like_hostname(v):
            out.add(v.lower())

    def _consume(value):
        if isinstance(value, str):
            _add(value)
        elif isinstance(value, list):
            for item in value:
                _consume(item)
        elif isinstance(value, dict):
            for item in value.values():
                _consume(item)

    def _walk(node):
        """Find hint-matching keys at ANY depth.

        Cape nests each config under its family name:

            {"Latrodectus": {"C2": [["https://host/work/", ...]]}}

        Matching hints against the top level only ever saw "Latrodectus",
        "CobaltStrikeBeacon", "Quickbind" — never "C2". Measured across 25
        retained analyses, 4 had extracted_configs and 0 produced a single
        indicator, so no config-derived C2 has EVER reached a correlation rule.
        The IP-only predecessor had the same defect and was carried over
        unnoticed, because its `network.hosts` fallback kept it looking alive.
        """
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and any(
                    hint in key.lower() for hint in _C2_CONFIG_KEY_HINTS
                ):
                    _consume(value)
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(cape.get("extracted_configs", []))
    return out


def _vad_dump_files(report: dict) -> list[tuple]:
    """(pid, path) for every VAD region vadinfo actually dumped."""
    vol = report.get("volatility")
    if not isinstance(vol, dict):
        return []
    vadinfo = (vol.get("plugins") or {}).get("vadinfo")
    dump_dir = vol.get("vad_dump_dir")
    if not isinstance(vadinfo, list) or not dump_dir or not _within_allowed_root(dump_dir):
        return []
    out = []
    for vad in vadinfo:
        if not isinstance(vad, dict):
            continue
        name = vad.get("File output")
        if not isinstance(name, str) or not _is_dump_filename(name):
            continue
        path = os.path.join(dump_dir, os.path.basename(name))
        if _within_allowed_root(path):
            out.append((vad.get("PID"), path))
    return out


def _gather_vad_string_hits(report: dict, needles: set) -> tuple[dict, str | None]:
    """Which indicators appear verbatim in dumped process memory, and in whose.

    Searches both ASCII and UTF-16LE: Windows APIs carry hostnames as wide
    strings, so an ASCII-only search misses the common case.

    Returns (hits, reason_it_is_empty) — the reason is what keeps "no VAD dumps
    existed" distinguishable from "the C2 host was not in memory".
    """
    if not needles:
        return {}, None
    files = _vad_dump_files(report)
    if not files:
        return {}, "no dumped VAD regions to search"

    encoded = {}
    for n in needles:
        raw = n.encode("utf-8", "ignore")
        encoded[n] = (raw.lower(), n.encode("utf-16-le", "ignore").lower())
    longest = max((max(len(a), len(b)) for a, b in encoded.values()), default=0)

    hits: dict = {}
    scanned = 0
    truncated = False
    for pid, path in files:
        if scanned >= _VAD_SCAN_MAX_BYTES:
            truncated = True
            break
        try:
            with open(path, "rb") as fh:
                tail = b""
                while scanned < _VAD_SCAN_MAX_BYTES:
                    chunk = fh.read(_VAD_SCAN_CHUNK)
                    if not chunk:
                        break
                    scanned += len(chunk)
                    window = (tail + chunk).lower()
                    for needle, (ascii_b, wide_b) in encoded.items():
                        if ascii_b and ascii_b in window:
                            hits.setdefault(needle, set()).add(pid)
                        elif wide_b and wide_b in window:
                            hits.setdefault(needle, set()).add(pid)
                    tail = window[-longest:] if longest else b""
        except OSError:
            continue

    reason = None
    if truncated:
        reason = (f"memory scan stopped at {_VAD_SCAN_MAX_BYTES // (1024 * 1024)}MB "
                  f"of dumped VADs; regions past that were not searched")
    return {k: sorted(v, key=lambda x: (x is None, x)) for k, v in hits.items()}, reason


def rule_c2_live_in_memory(report: dict) -> list[dict]:
    """A Cape-extracted C2 host that is also present, verbatim, in process memory.

    This used to join Cape's C2 IPs against `windows.netscan` foreign addresses.
    That join could never match on this platform. netscan selects its structure
    definitions by Windows build, and when none matches it does not fail — it
    logs `going with latest: netscan-win10-20348-x64` at DEBUG and scans with
    Server 2022 offsets. The analysis guests are Windows 11 build 26100, so
    netscan returned 0 rows on 17 of 17 runs while reporting success, and this
    rule was the one correlation that never fired (#469).

    netstat is no escape: it reads only PartitionTable/PartitionCount from
    tcpip.pdb and builds its structures from netscan
    (netstat.py:636 create_netscan_symbol_table), inheriting the same ceiling.
    Upstream's newest table is build 20348 — there is none for any Windows 11
    build, so no version of Volatility can read socket structures here.

    So this asks a question the available evidence can answer. "The C2 channel
    was live" needed sockets; "Cape decoded C2 host X, and X is present in this
    process's memory" needs only bytes, and it is still a genuine cross-tool
    claim — Cape decoded the config, Volatility supplied the memory, and neither
    alone establishes it.

    Weaker than the original in one specific way, stated rather than hidden: a
    string in memory shows the host was *known* to the process, not that a
    connection was established. Severity is medium, not high, for that reason.

    Coverage is bounded by which regions vadinfo dumped, and the stage only
    dumps for Cape's injection target PIDs — so a sample with C2 but no
    injection has nothing to search. That is reported, not silently treated as
    a clean result.
    """
    findings = []
    cape = report.get("cape", {})
    indicators = _cape_c2_string_indicators(cape)
    if not indicators:
        return findings

    hits, _reason = _gather_vad_string_hits(report, indicators)
    for indicator in sorted(hits):
        pids = [p for p in hits[indicator] if p is not None]
        where = ", ".join(str(p) for p in pids[:5]) or "an unattributed region"
        findings.append({
            "type": "c2_live_in_memory",
            "severity": "medium",
            "title": f"C2 host {indicator} found in process memory",
            "detail": (f"Cape decoded {indicator} from the sample's configuration; "
                       f"the same string is present in memory dumped from PID(s) "
                       f"{where}. Presence establishes the host was known to the "
                       f"process, not that a connection was made."),
            "indicator": indicator,
            "pid": pids[0] if pids else 0,
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


# -------------------------------------------------------------------------
# Coverage — which rules could not run, and why
# -------------------------------------------------------------------------

#: Volatility plugin output -> the question the rules reading it answer. Every
#: entry here is a plugin some rule in `_RULES` indexes out of
#: report["volatility"]["plugins"]; test_correlation_coverage asserts the two
#: stay in step, so adding a rule that reads a new plugin without declaring it
#: fails rather than silently going unreported.
_PLUGIN_CONSUMERS = {
    "dlllist": "whether a dropped file was loaded into a process",
    # NOT self-modification any more. #458 moved rule_shellcode_self_modified
    # onto vadinfo, which returns every VAD regardless of protection; malfind
    # reports only PAGE_EXECUTE_READWRITE and matched 0 of 31 buffers. Leaving
    # the old wording here meant a malfind timeout announced that
    # self-modification could not be evaluated while vadinfo was evaluating it
    # fine in the same run — a warning asserting a gap that is not there, which
    # costs the same credibility as a gap reported as clean (#467).
    "malfind": "whether injection is corroborated in memory",
    "cmdline": "whether a process spoofed its command line",
    # netscan is NOT listed. It has no structure table for the Windows 11 build
    # these guests run and returns 0 rows while reporting success (#469), so it
    # no longer runs at all and nothing consumes it. Declaring it would warn
    # about a plugin whose absence costs nothing.
}


def _plugin_state(plugins: dict, name: str) -> tuple[bool, str | None]:
    """(usable, reason_it_is_not) for one Volatility plugin's output.

    `run_single_plugin` returns a LIST on success and ``{"error": ...}`` on
    failure — a timeout, a non-zero exit, or unparseable output. An absent key
    means the plugin was never run at all.
    """
    if name not in plugins:
        return False, "not run"
    value = plugins[name]
    if isinstance(value, list):
        return True, None
    if isinstance(value, dict) and value.get("error"):
        return False, str(value["error"])[:200]
    return False, f"unexpected {type(value).__name__} output"


#: Cape stage statuses that mean it TRIED and failed, as opposed to being
#: skipped by policy. "skipped" carries a reason (a non-Windows binary) and is a
#: reported pipeline state, exactly like Volatility's `triggered: False` — so it
#: stays silent, for the same argument.
_CAPE_FAILED_STATUSES = {"error", "failed_analysis", "failed_processing", "failed_reporting"}


def _cape_unavailable_reason(report: dict) -> str | None:
    """Why the Cape stage produced nothing to correlate, or None if it ran.

    EVERY correlation rule reads Cape data — dropped files, injection buffers,
    process command lines, extracted configs — so a failed Cape stage blinds all
    five at once. Before this, that state persisted as `correlation_warnings =
    '{}'`, which the schema and every base-rate query read as "correlation ran
    and every rule could be evaluated": a failed sandbox run was recorded as a
    clean sample.

    That is not hypothetical. Cape served no task between 2026-08-21 and
    2026-08-24 because its machine pool had emptied (#451), and every submission
    in that window returned `failed_analysis` after 30 seconds while the pipeline
    carried on and wrote a report. A corpus run spanning such an outage would
    report a low correlation fire rate that was really an infrastructure fault.
    """
    cape = report.get("cape")
    if not isinstance(cape, dict):
        return None
    status = cape.get("status")
    if status in _CAPE_FAILED_STATUSES:
        detail = cape.get("error") or status
        return str(detail)[:200]
    return None


def correlation_warnings(report: dict) -> list[str]:
    """The rules that could not be evaluated, and what went missing.

    Every rule guards its Volatility input with ``isinstance(..., list)``, which
    is correct — a plugin that failed hands back ``{"error": ...}`` and must not
    be iterated. But the guard returns ``[]``, which is the same thing the rule
    returns when it ran fine and found nothing. The two states were
    indistinguishable in the report, and `run-pipeline` logged the merged result
    as "No cross-tool findings detected" — a claim it had not established.

    That matters most exactly where it is most likely: `malfind` runs under a
    120s cap documented as "partial results acceptable", so a timeout on a large
    dump is an ordinary outcome, not a rare one. When it times out, both
    injection rules go quiet and the report reads as though injection was
    checked for and not found.

    Same principle as `PayloadAccessError` in lamware_shared.cape_payloads and
    the Ghidra `analysis_warnings` surface (#315/#367): "I could not look" has to
    be its own answer, distinct from "I looked and there was nothing".

    Returns [] when Volatility did not run at all — that is a reported pipeline
    state (the stage is trigger-gated), not a silent degradation of correlation.
    """
    warnings: list[str] = []

    cape_reason = _cape_unavailable_reason(report)
    if cape_reason:
        warnings.append(
            f"Cape stage produced no output ({cape_reason}) — no correlation "
            f"rule could be evaluated, because every rule reads Cape data"
        )

    return warnings + _volatility_warnings(report)


def _volatility_warnings(report: dict) -> list[str]:
    """The Volatility half: which plugins a rule needed and could not get."""
    volatility = report.get("volatility")
    if not isinstance(volatility, dict):
        return []
    plugins = volatility.get("plugins")
    if not isinstance(plugins, dict):
        # No plugin outputs at all, which is the SEVEREST form of this bug rather
        # than an exemption from it: every rule is blind at once. run-pipeline
        # writes {"triggered": True, "error": "timeout (45 min)"} when the whole
        # stage exceeds 45 minutes, and that dict has no "plugins" key for the
        # per-plugin loop below to inspect.
        #
        # Distinguished from never having run: `triggered: False` carries a
        # `reason` and is a reported pipeline state (the stage is signature-gated),
        # so it stays silent.
        if volatility.get("triggered") or volatility.get("error"):
            reason = volatility.get("error") or "stage produced no plugin output"
            return [
                f"Volatility produced no plugin output ({reason}) — could not "
                f"evaluate {_PLUGIN_CONSUMERS[name]}"
                for name in sorted(_PLUGIN_CONSUMERS)
            ]
        return []
    warnings: list[str] = []
    for name in sorted(_PLUGIN_CONSUMERS):
        usable, reason = _plugin_state(plugins, name)
        if not usable:
            warnings.append(
                f"Volatility {name} unavailable ({reason}) — could not evaluate "
                f"{_PLUGIN_CONSUMERS[name]}"
            )
    # The Cape half of rule_dropped_file_loaded needs the same treatment. Its
    # input was silently empty on every run for a different reason than a failed
    # plugin: it read a directory CAPEv2 does not create (see
    # _gather_dropped_files). Only reported when dlllist IS usable — otherwise
    # the dlllist warning above already says the rule could not be evaluated.
    if _plugin_state(plugins, "dlllist")[0]:
        reason = report.get("_correlation_inputs", {}).get("dropped_files_unavailable")
        if reason:
            warnings.append(
                f"Cape dropped-file manifest unavailable ({reason}) — could not "
                f"evaluate {_PLUGIN_CONSUMERS['dlllist']}"
            )

    # vadinfo deliberately is NOT in _PLUGIN_CONSUMERS. Those entries warn
    # whenever the plugin is absent, but the stage only runs vadinfo when Cape
    # captured injection buffers — so declaring it would warn on every sample
    # that has nothing to inject, which is most of them. A warning that fires on
    # ordinary runs is how a channel gets ignored (#453).
    #
    # Gated on there being something to check instead.
    if report.get("cape", {}).get("injection_buffers"):
        inputs = report.get("_correlation_inputs", {})
        reason = inputs.get("vad_samples_unavailable")
        unresolved = inputs.get("vad_samples_unresolved") or 0
        if reason:
            warnings.append(
                f"Injection-address memory unavailable ({reason}) — could not "
                f"evaluate whether injected bytes were modified after the write"
            )
        elif unresolved:
            # A PARTIAL read is not a clean result. Analysis 1072 compared 27 of
            # 32 addresses and reported no warning at all, so those 5 buffers
            # were indistinguishable from "checked and unmodified" — the #452
            # argument one level finer.
            #
            # Worded as coverage rather than failure, because a process exiting
            # before capture is ordinary and this fires on most runs that inject
            # anything. It says what was not compared and why; it does not imply
            # something is broken. An alarming warning on a routine event is how
            # a channel gets tuned out (#453).
            attempted = unresolved + len(inputs.get("vad_samples") or {})
            warnings.append(
                f"Injection-address memory partially covered: {unresolved} of "
                f"{attempted} addresses had no readable VAD dump (most often a "
                f"process that exited before capture) — those writes were not "
                f"compared, so an absence of findings does not cover them"
            )

    # C2-in-memory coverage. Gated on Cape having decoded a C2 host at all: with
    # nothing to hunt for, having nothing to hunt in is not a gap. When there IS
    # an indicator and no dumped memory to search it in, silence would read as
    # "the C2 host was not in memory" when the truth is nobody looked (#460).
    if _cape_c2_string_indicators(report.get("cape", {})):
        reason = report.get("_correlation_inputs", {}).get("c2_scan_unavailable")
        if reason:
            warnings.append(
                f"C2-in-memory search unavailable ({reason}) — could not evaluate "
                f"whether a Cape-decoded C2 host is present in process memory"
            )
    return warnings


def cross_correlate(report: dict) -> list[dict]:
    """Public entrypoint. Enrich (filesystem) -> evaluate pure rules -> strip inputs.

    Also sets ``report["correlation_warnings"]`` so an empty finding list can be
    read correctly: no findings WITH warnings means the evidence was missing, not
    that the sample was clean.
    """
    enrich_correlation_inputs(report)
    report["correlation_warnings"] = correlation_warnings(report)
    try:
        return evaluate_rules(report)
    finally:
        report.pop("_correlation_inputs", None)


# -------------------------------------------------------------------------
# Persistence shaping — pure, so the row shape is testable without a database
# -------------------------------------------------------------------------

#: Columns of the `correlations` table, in the order `correlation_rows` emits.
CORRELATION_COLUMNS = ("type", "severity", "title", "detail", "sources", "mitre", "pid")

_MAX_TITLE = 500
_MAX_DETAIL = 4000
_MAX_MITRE = 200
_MAX_PID = 20
_MAX_SEVERITY = 20
_MAX_TYPE = 100
_MAX_SOURCE = 50


def _clip(value, limit: int) -> str | None:
    """A column-width-safe string, or None. Truncates rather than raising.

    Every field here is derived from adversary-controlled input: a finding's
    title embeds a dropped file's path, and `detail` embeds a command line the
    sample chose. A value longer than the column silently aborts the whole
    ingest transaction in psycopg2, which would lose the IOCs and techniques
    alongside it — so the finding is trimmed instead of the analysis being lost.
    """
    if value is None:
        return None
    text = str(value)
    return text[:limit] if len(text) > limit else text


def correlation_rows(findings: list[dict]) -> list[tuple]:
    """Findings -> row tuples matching CORRELATION_COLUMNS.

    Rules emit a dict whose shape has been stable since the registry was split
    out, but `pid` is an int on some rules and a string on others, `sources` is
    a list, and `detail` carries sample-chosen paths of no bounded length. This
    normalises all three so the ingest is a loop and not a mapping exercise.
    """
    rows = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        sources = f.get("sources")
        if isinstance(sources, (list, tuple)):
            source_list = [_clip(s, _MAX_SOURCE) for s in sources if s]
        elif sources:
            source_list = [_clip(sources, _MAX_SOURCE)]
        else:
            source_list = None
        rows.append((
            _clip(f.get("type", "unknown"), _MAX_TYPE),
            _clip(f.get("severity", "unknown"), _MAX_SEVERITY),
            _clip(f.get("title", ""), _MAX_TITLE),
            _clip(f.get("detail"), _MAX_DETAIL),
            source_list,
            _clip(f.get("mitre"), _MAX_MITRE),
            _clip(f.get("pid"), _MAX_PID),
        ))
    return rows
