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

import hashlib
import json
import re
import subprocess
from pathlib import Path

from lamware_shared.cape_payloads import (
    CAPE_STORAGE,
    PayloadAccessError,
    find_pe_payloads,
)

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


def discover_pe_files(cape_data: dict,
                      storage: Path = CAPE_STORAGE) -> tuple[list[Path], str | None]:
    """Find PE files Cape extracted, and say so if we could not look.

    Looks across every Cape extraction directory, not just ``dropped/`` —
    which this deployment never writes to, so this returned an empty list for
    every analysis until #377. Ordered so the caller's ``MAX_PE_FILES`` cap keeps
    Cape's unpacked extractions ahead of raw process dumps.

    Returns ``(files, access_error)``. An unreadable Cape storage tree yields
    ``([], "<why>")`` rather than raising: one sample's permissions must not
    abort the whole pipeline run, since run-pipeline wraps neither call site.
    But the reason travels back to the report — an empty list on its own would
    read as "the sample dropped nothing", which is the lie #377 was about.
    """
    task_id = cape_data.get("id") or cape_data.get("task_id")
    try:
        return [p.path for p in find_pe_payloads(task_id, storage=storage)], None
    except PayloadAccessError as exc:
        return [], str(exc)


# The analyzed_files a routed sample's agent may read instead of the wrapper:
# CAPE's unpacked payloads (shellcode loader, source "cape_payload") and dropped
# PEs (PE loader, which sets no "source" at all). None can only mean a dropped
# PE here because routed samples run with include_original=False; on the native
# path it would also match the original, which is why select_payload_target is
# only ever called for routed samples. Injection buffers and malfind regions are
# left out: they are fragments of a process, not a program to investigate.
PAYLOAD_SOURCES = frozenset({"cape_payload", None})


# Stage 4 branches that hand the sample to another analyser. Each records its
# flag on report["ghidra"]; run-pipeline then sends CAPE's payloads (never the
# wrapper) to Ghidra (#646). A branch missing from this tuple silently keeps
# the old behaviour, so test_routed_samples_get_payload_ghidra.py derives the
# set from run-pipeline's source and compares.
ROUTED_FLAGS = (
    "office_routed", "powershell_routed", "script_routed", "dotnet_routed",
    "go_routed", "pyinstaller_routed", "java_routed",
)


# CAPE names a payload after the family its config extractor recognised, in
# three forms seen in our corpus (all 33 distinct labels are in the test):
# "Formbook Payload", "Salat Payload: 32-bit executable", "XWorm payload".
# Generic unpacking results are named for their shape instead ("Unpacked PE
# Image: 32-bit DLL", "Injected Shellcode/Data", "Decompressed PE Image: ..."),
# and those are not a family claim.
_FAMILY_PAYLOAD_RE = re.compile(
    r"\A(?!(?:Unpacked|Injected|Extracted|Decompressed)\b)\S.*?\s[Pp]ayload(?::.*)?\Z")


def is_family_payload(cape_type: object) -> bool:
    """True when CAPE labelled this payload with a family, not just a shape."""
    return isinstance(cape_type, str) and bool(_FAMILY_PAYLOAD_RE.match(cape_type.strip()))


def select_payload_target(ghidra_data: dict, verify=None) -> tuple[dict | None, str | None]:
    """The unpacked program the RE agent should read instead of a routed wrapper.

    Option (c) of #646: when a sample was routed to another analyser (.NET,
    Office, script, ...) the agent investigates what CAPE unpacked instead.

    Preference, first match wins:

    1. ``cape_family_label``: a payload CAPE labelled with a family
       ("Formbook Payload"), loaded with functions, whose program ``verify``
       confirms opens (True; None is "could not tell" and does not qualify).
       The first version ranked by function count alone, and on formbook
       (v651, 2026-09-29) that picked an unlabelled 4,064-function DLL over the
       377-function "Formbook Payload"; the agent then described a generic
       loader.
    2. ``canonical``: the program run_ghidra already verified and chose
       (``ghidra_data["program_name"]``), if it is a loaded payload. Never
       ``successful[0]``: list position is not a quality signal.

    Returns ``(file, reason)``, or ``(None, None)`` to keep the routed
    analyser's own interpretation.
    """
    files = ghidra_data.get("analyzed_files") or []

    def loaded_payload(f: dict) -> bool:
        return (bool(f.get("analysis_success"))
                and f.get("in_project") is not False
                and (f.get("functions_count") or 0) > 0
                and f.get("source") in PAYLOAD_SOURCES
                and bool(f.get("project_dir")) and bool(f.get("program_name")))

    if verify is not None:
        labelled = sorted(
            (f for f in files if loaded_payload(f) and is_family_payload(f.get("cape_type"))),
            key=lambda f: -(f.get("functions_count") or 0))
        for f in labelled:
            if verify(f["project_dir"], f["program_name"]) is True:
                return f, "cape_family_label"

    canonical = ghidra_data.get("program_name")
    if canonical and ghidra_data.get("project_dir"):
        for f in files:
            if f.get("program_name") == canonical and loaded_payload(f):
                return f, "canonical"
    return None, None


def select_native_target(ghidra_data: dict) -> tuple[dict | None, str | None]:
    """The analysed file the RE agent reads on the native path.

    The canonical program: the one run_ghidra ranked and verified, whose pair
    is ``ghidra_data["project_dir"]``/``["program_name"]``. Stage 4.5 used to
    hand the agent ``successful[0]``, the first success by LIST POSITION. The
    eval has always passed ``report["ghidra"]`` itself, whose top-level pair is
    the canonical program, so production and the eval read different programs
    (#667's survey); and #651's routed path (``select_payload_target``) already
    refuses list position. Since #649 put the submitted sample first in the
    list, position would also have quietly decided which program the agent
    reads, a choice the owner made explicitly instead: canonical.

    Returns ``(file, "canonical")``, or ``(successful[0], "first_success_fallback")``
    when no analysed file matches the canonical pair (a report with no verified
    program), or ``(None, None)`` when nothing succeeded.
    """
    files = [f for f in (ghidra_data.get("analyzed_files") or []) if isinstance(f, dict)]
    canonical = ghidra_data.get("program_name")
    if canonical and ghidra_data.get("project_dir"):
        for f in files:
            if (f.get("program_name") == canonical and f.get("project_dir")
                    and f.get("analysis_success")
                    and f.get("in_project") is not False):
                return f, "canonical"
    successful = [f for f in files if f.get("analysis_success")]
    if successful:
        return successful[0], "first_success_fallback"
    return None, None


def is_original_sample_entry(ghidra_data: dict, entry: dict) -> bool:
    """True when ``entry`` is the submitted sample's own analysis.

    run_ghidra puts the original first among PE-loader results (source None)
    whenever it was included (#649), or alone under original_sample_is_pe.
    """
    if not (ghidra_data.get("original_sample_included") is True
            or ghidra_data.get("trigger_reason") == "original_sample_is_pe"):
        return False
    pe_entries = [f for f in (ghidra_data.get("analyzed_files") or [])
                  if isinstance(f, dict) and f.get("source") is None]
    return bool(pe_entries) and pe_entries[0] is entry


def native_input_record(ghidra_data: dict, target: dict, reason: str) -> dict:
    """``llm_interpretation.input`` for the native path.

    Same keys as the routed branch's record in run-pipeline, so the flow view
    and the eval read one shape whichever path ran.
    """
    return {
        "kind": reason,
        "program_name": target.get("program_name"),
        "source": ("original_sample" if is_original_sample_entry(ghidra_data, target)
                   else target.get("source") or "dropped_pe"),
        "functions_count": target.get("functions_count"),
        "cape_type": target.get("cape_type"),
        "chosen_because": reason,
    }


def get_dropped_pe_files(cape_data: dict,
                         storage: Path = CAPE_STORAGE) -> list[Path]:
    """PE files Cape extracted, for callers that only need the list."""
    return discover_pe_files(cape_data, storage)[0]


def get_original_sample_path(cape_data: dict,
                             storage: Path = CAPE_STORAGE) -> Path | None:
    """Get the original submitted sample from Cape's storage."""
    task_id = cape_data.get("id") or cape_data.get("task_id")
    if not task_id:
        return None
    binary_path = storage / str(task_id) / "binary"
    # exists() re-raises EACCES rather than returning False, so an unreadable
    # Cape storage tree crashes here instead of falling through to the
    # pipeline's own copy of the sample. The open() below already handles the
    # unreadable case; this check only needs to skip a genuinely absent file.
    try:
        if not binary_path.exists():
            return None
    except OSError:
        return None
    # Check if it's a PE
    try:
        with binary_path.open("rb") as fh:
            if fh.read(2) == b"MZ":
                return binary_path
    except (OSError, PermissionError):
        pass
    return None


def resolve_original_sample(cape_data: dict, sample_path: Path | None,
                            storage: Path = CAPE_STORAGE) -> tuple[Path | None, str, str | None]:
    """The submitted sample, from whichever copy the pipeline can actually read.

    Returns (path, source, note). `source` is "cape_storage", "pipeline_copy" or
    "none"; `note` explains a fallback so the report can say what happened.

    WHY THIS EXISTS (#644). #393 — the fix for #392, samples readable by every
    local account — made every file under storage/binaries `640 cape:cape`. The
    pipeline user is in `lamware`, not `cape`, so CAPE's copy became unreadable
    on 2026-08-15. `get_original_sample_path` swallows the PermissionError and
    returns None, and the stage reported "no PE files found": a claim about the
    SAMPLE, made when the truth was a claim about US. Since then 2 of 106 runs
    analysed the submitted binary, against 367 of 991 before.

    It went unseen because should_run_ghidra ALREADY fell back to the pipeline's
    own copy — so Ghidra was triggered — while run_ghidra did not, so it then
    found nothing. The trigger and the execution asked different questions. Both
    now ask this one.

    The permissions are NOT loosened: #392 stands. The pipeline already holds a
    readable copy of every sample — the file it handed CAPE.

    Identity is checked without read access: CAPE names its stored copy by
    sha256, and resolving a symlink needs only directory traversal, so the
    fallback is refused if the pipeline's copy is not the sample CAPE detonated.
    """
    cape_copy = get_original_sample_path(cape_data, storage)
    if cape_copy is not None:
        return cape_copy, "cape_storage", None

    if not sample_path or not _is_ghidra_compatible_binary(Path(sample_path)):
        return None, "none", None

    import hashlib
    task_id = cape_data.get("id") or cape_data.get("task_id")
    expected = None
    if task_id:
        try:
            expected = (storage / str(task_id) / "binary").resolve().name
        except OSError:
            expected = None
    digest = hashlib.sha256(Path(sample_path).read_bytes()).hexdigest()
    if expected and len(expected) == 64 and expected != digest:
        return None, "none", (
            f"CAPE's copy is unreadable and the pipeline's copy is a DIFFERENT file "
            f"(sha256 {digest[:12]} vs CAPE {expected[:12]}); refusing to analyse it "
            f"as the submitted sample")
    return Path(sample_path), "pipeline_copy", (
        "CAPE's stored copy of the submitted sample is not readable by the pipeline "
        "user (#644); analysed the pipeline's own copy"
        + (f", sha256 matches CAPE's ({digest[:12]})" if expected == digest else
           ", sha256 not cross-checked"))


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
    # Same resolver run_ghidra uses, so triggering and execution cannot disagree
    # about whether there is an original to analyse (#644).
    original_is_pe = resolve_original_sample(cape_data, sample_path, storage)[0] is not None

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
        # Where this analysis's project ACTUALLY lives on the host. run-ghidra
        # reports the container path ("/output/project") on every result, and
        # the two loaders write to different host directories — so the caller
        # cannot reconstruct it from output_dir alone (#390).
        output["host_output_dir"] = str(output_dir)
        return output
    except subprocess.TimeoutExpired:
        return {"error": "timeout (600s)", "filename": pe_path.name}
    except json.JSONDecodeError:
        return {"error": "invalid JSON output", "filename": pe_path.name,
                "raw": result.stdout[:500]}


# Volatility prints "N/A" for a VAD whose Start VPN it cannot resolve, and that
# string used to be formatted straight into a directory name:
#
#     .../shellcode_0_N/A/project
#
# The slash invents a directory level, so the project was written to a path no
# consumer could reconstruct. It reached the eval corpus in three of sixteen
# samples, where the agent's every tool call then failed with
# `realpath: .../shellcode_0_N/A/project: No such file or directory` (#631).
#
# An address we cannot parse is named `unknown` rather than being coerced into
# something address-shaped: a wrong-looking-but-valid name would put two
# unrelated candidates in one directory.
# \Z, not $: Python's $ also matches before a trailing newline, so "400000\n"
# would validate and put a newline in a directory name.
_ADDR_RE = re.compile(r"\A(?:0[xX])?([0-9a-fA-F]+)\Z")


def _addr_token(value: object) -> str:
    """A filesystem-safe directory token for a candidate's base address."""
    m = _ADDR_RE.match(str(value).strip()) if value is not None else None
    return m.group(1).lower() if m else "unknown"


def _path_token(value: object) -> str:
    """A filesystem-safe directory token for any other path component.

    Callers pass a REQUIRED key (`candidate["pid"]`, not `.get`): a candidate
    with no pid is a programming error and must raise, not become a directory
    called "None".
    """
    token = re.sub(r"[^A-Za-z0-9._-]", "_", str(value).strip())
    # "." and ".." survive the character filter and are not names; they would
    # resolve the project to the parent directory.
    return "unknown" if token.strip(".") == "" else token


# pid + address is not an identity. CAPE's extracted payloads have neither (pid
# 0, address "N/A"), so every one of them was named shellcode_0_unknown, and
# each headless run's "Creating project" replaced the one before: of cobalt-
# strike's five payloads only the last program survived, while the report still
# listed all five with function counts the agent could never reach (#648).
# Before #631 the shared name was shellcode_0_N/A, which failed loudly; making
# it filesystem-safe without making it unique turned that into a silent loss.
#
# The content hash is the identity. Two candidates with the same bytes may share
# a directory — they are the same program — and two different ones cannot.
_SHA_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")


def _content_token(candidate: dict) -> str:
    """First 12 hex digits of the candidate's sha256.

    Uses the sha256 the caller recorded when it is a real one; otherwise hashes
    the dump itself. A missing or unreadable dump raises: the headless run
    reads the same file, so there is nothing to analyse under a made-up name.
    """
    sha = str(candidate.get("sha256") or "").strip()
    if not _SHA_RE.match(sha):
        with Path(candidate["path"]).open("rb") as fh:
            sha = hashlib.file_digest(fh, "sha256").hexdigest()
    return sha[:12].lower()


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

    # After the early return: an artifact-only buffer never gets a project, so
    # it must not fail on naming one.
    sc_output = output_dir / (
        f"shellcode_{_path_token(candidate['pid'])}_{_addr_token(base_addr)}"
        f"_{_content_token(candidate)}")

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
    # CAPE's own label for the payload ("Formbook Payload"). The agent's input is
    # chosen by it (select_payload_target), so it must survive to the result.
    if candidate.get("cape_type"):
        analysis["cape_type"] = candidate["cape_type"]
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
    # This loader writes to a per-candidate subdirectory, NOT output_dir. See
    # the note in run_ghidra_on_file (#390).
    analysis["host_output_dir"] = str(sc_output)

    return analysis


def _pick_openable(ranked: list[dict], host_project_of, verify, warnings):
    """Best-ranked candidate the verifier says is openable.

    The verifier is TRI-STATE, and that is the whole design:

      True  — opened it
      False — the project definitively does not hold this program
      None  — could not tell (probe failed to run, timed out, answered
              something unrecognised)

    Only a definitive False rejects a candidate. An inconclusive probe must not,
    because then any transient failure — a busy container, a timeout under load,
    a wrapper too old to report the distinction — would throw away a working
    project and tell the interpret stage Ghidra is unavailable. That trades a
    silent failure for a louder one, which is not the same as fixing it.

    An unverified candidate is still used, and still said out loud. With no
    verifier at all this is `ranked[0]`, the historical behaviour, kept so the
    selection stays pure for callers that cannot run Ghidra.
    """
    if verify is None:
        return ranked[0] if ranked else None

    unverified = None
    for i, af in enumerate(ranked):
        name = af.get("program_name") or ""
        project = host_project_of(af)
        if not name or not project:
            continue
        verdict = verify(project, name)
        if verdict is True:
            if i and warnings is not None:
                warnings.append(
                    f"Ghidra: canonical program fell back to {name[:16]} "
                    f"({af.get('functions_count')} functions) — "
                    f"{i} better-ranked candidate(s) could not be opened")
            return af
        if verdict is False:
            if warnings is not None:
                warnings.append(
                    f"Ghidra: {name[:16]} claims {af.get('functions_count')} "
                    f"functions but is not in {project} — tool calls against it "
                    f"would all fail")
            continue
        if unverified is None:
            unverified = af

    if unverified is not None:
        if warnings is not None:
            warnings.append(
                f"Ghidra: could not verify that {str(unverified.get('program_name'))[:16]} "
                f"is openable — using it unverified; tool calls may all fail")
        return unverified
    return None


def make_ghidra_verifier(ghidra_cmd: str, timeout: int = 180):
    """A tri-state `verify(project_dir, program_name)` that asks Ghidra directly.

    The probe is `list_functions` with a filter matched by nothing: opening the
    program is the expensive part and the part under test, while serialising a
    result is neither — an 18k-function listing would cost seconds and prove no
    more than an empty one.

    Returns False ONLY for the failure this exists to catch, recognised two
    ways so it works against an un-redeployed wrapper as well as a current one:
    the `program_not_in_project` flag, or Ghidra's own "program file(s) not
    found" text wherever it surfaces. Every other failure returns None — the
    probe could not answer, which is not evidence that the program is missing.
    """
    def verify(project_dir: str, program_name: str):
        try:
            proc = subprocess.run(
                [ghidra_cmd, "--tool", project_dir, program_name,
                 "list_functions", json.dumps({"filter": "__lamware_open_probe__"})],
                capture_output=True, text=True, timeout=timeout,
            )
            payload = json.loads(proc.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return None
        if not isinstance(payload, dict):
            return None
        if not payload.get("error"):
            return True
        if payload.get("program_not_in_project"):
            return False
        haystack = f"{payload.get('error', '')} {payload.get('ghidra_stdout', '')}"
        return False if "program file(s) not found" in haystack else None
    return verify


def _project_programs(project: Path) -> set[str] | None:
    """Program names a Ghidra project holds, from its own index, or None.

    ``analysis.rep/idata/~index.dat`` lists one ``  <id>:<name>:<uuid>`` line
    per stored program. None means the index could not be read, which is not
    evidence the program is missing.
    """
    try:
        text = (project / "analysis.rep" / "idata" / "~index.dat").read_text(errors="replace")
    except OSError:
        return None
    names = set()
    for line in text.splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 3 and parts[0].isdigit():
            names.add(parts[1])
    return names


def record_project_presence(analyzed_files: list[dict], output_dir: Path) -> list[str]:
    """Mark every program claiming success with whether its project holds it.

    The #490 verifier opens only the candidates selection reaches, so programs
    lost from their project went unreported: 269 under #648, 36 under #655,
    each still listed with a function count. This checks all of them, cheaply,
    by reading each project's index rather than launching Ghidra per program
    (formbook has seven). Sets ``in_project`` to True, False or None (index
    unreadable) and returns one warning per missing program, worded like the
    verifier's so readers of either (api/app/flow.py) match both.
    """
    warnings: list[str] = []
    cache: dict[Path, set[str] | None] = {}
    for af in analyzed_files:
        name = af.get("program_name")
        if not (af.get("analysis_success") and name):
            continue
        base = af.get("host_output_dir")
        project = (Path(base) if base else output_dir) / "project"
        if project not in cache:
            cache[project] = _project_programs(project)
        held = cache[project]
        af["in_project"] = None if held is None else name in held
        if af["in_project"] is False:
            warnings.append(
                f"Ghidra: {name[:16]} claims {af.get('functions_count') or 0} functions "
                f"but is not in {project} — tool calls against it would all fail")
    return warnings


def propagate_project_dir(analyzed_files: list[dict],
                          output_dir: Path,
                          verify=None,
                          warnings: list | None = None,
                          ) -> tuple[str | None, str | None]:
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

    Two things this must not do, both of which it used to (#390):

    **Assume every project lives at ``output_dir/project``.** The two loaders
    write to different places — ``run_ghidra_on_file`` to ``output_dir``,
    ``run_ghidra_shellcode`` to ``output_dir/shellcode_<pid>_<addr>_<sha12>``. Pointing
    a shellcode analysis at ``output_dir/project`` names a project that holds a
    different program, or none. On latrodectus that project was **empty**, and
    all 5 of the interpret stage's Ghidra tool calls failed with "GhidraTool
    .java did not emit TOOL_RESULT". The model had no decompiler access at all
    and nobody could tell from the report.

    **Take the first success as the best one.** List position is not a quality
    signal. When CAPE payloads reach both loaders, the PE-loaded copy is
    appended first — 15 functions on a payload the raw loader decompiled into
    127. Selection is by function count instead.

    **Name a program the project cannot open.** Selection ranks by function
    count, but the project retains only one program while `analyzed_files`
    claims five or six successes, so the highest-ranked candidate is often
    absent. Ghidra answers "Requested project program file(s) not found" and
    every tool call fails; the report meanwhile says `triggered: true` with 63
    analyzed files and no warning (#490). Pass `verify` to check, and
    `warnings` to collect what was rejected.

    Returns (None, None) if no successful analysis produced a project, or if a
    verifier rejected every candidate.
    """
    def _host_project(af: dict) -> str | None:
        # Prefer the recorded host directory. Fall back to output_dir for
        # results predating it, which can only have come from the PE loader.
        base = af.get("host_output_dir")
        return str(Path(base) / "project") if base else str(output_dir / "project")

    usable = [af for af in analyzed_files
              if af.get("analysis_success") and af.get("project_dir")
              and af.get("in_project") is not False]
    if not usable:
        return None, None

    # Preference order, best first. `max()` would name one candidate; the
    # ordering exists because the best-looking candidate is not always the one
    # the project can actually open (#490).
    ranked = sorted(usable,
                    key=lambda af: (af.get("functions_count") or 0,
                                    len(af.get("imports") or [])),
                    reverse=True)

    best = _pick_openable(ranked, _host_project, verify, warnings)
    if best is None:
        # Every candidate was rejected by the verifier. Returning the top one
        # anyway would hand the interpret stage a pairing known to fail, and it
        # would spend its whole tool budget discovering that one call at a time.
        # `run_ghidra_tool` turns an empty pair into an explicit "unavailable",
        # which is the honest answer and the one a reader can act on.
        return None, None

    host_project = _host_project(best)
    best["project_dir"] = host_project

    # Other SUCCESSFUL analyses keep a container path the host cannot resolve.
    # Rewrite those too — a consumer picking a non-canonical entry should get a
    # real path, not "/output/project". Failed records are deliberately left
    # alone: nothing reads their project, and preserving them unmodified is an
    # existing contract (test_ghidra.py).
    for af in analyzed_files:
        if af is not best and af.get("analysis_success") and af.get("project_dir"):
            af["project_dir"] = _host_project(af)

    return host_project, best.get("program_name", "")


# PE-loader runs per analysis: the original plus up to four dropped PEs.
MAX_PE_FILES = 5


def _sha256_or_none(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            return hashlib.file_digest(fh, "sha256").hexdigest()
    except OSError:
        return None


def _without_copies_of(original: Path, pe_files: list[Path]
                       ) -> tuple[list[Path], list[str]]:
    """Drop dropped PEs that are byte-identical to the original (#649).

    CAPE can extract the sample's own bytes; analysing them twice spends a
    decompiler run and a cap slot on one program. Compared by sha256, not by
    name: CAPE names files by hash, the pipeline's copy by upload name. A file
    that cannot be hashed is kept — the loader will report its own failure.
    """
    original_sha = _sha256_or_none(original)
    if original_sha is None:
        return pe_files, []
    kept, dupes = [], []
    for p in pe_files:
        if _sha256_or_none(p) == original_sha:
            dupes.append(p.name)
        else:
            kept.append(p)
    return kept, dupes


def _drop_already_queued(pe_files: list[Path],
                         shellcode_candidates: list[dict] | None
                         ) -> tuple[list[Path], list[str]]:
    """Remove payloads the shellcode loader is already going to analyse.

    Only candidates that will actually reach Ghidra count: one carrying
    ``analyze_with_ghidra: False`` (under 1KB) gets artifact extraction only,
    so dropping its PE copy would lose the file entirely.

    Returns (kept, skipped_names) — the caller records the skips, because a
    payload silently vanishing from the analysis list is the failure mode this
    whole area keeps reproducing.
    """
    if not shellcode_candidates:
        return pe_files, []

    queued = set()
    for c in shellcode_candidates:
        if c.get("analyze_with_ghidra") is False:
            continue
        path = c.get("path")
        if path:
            try:
                queued.add(Path(path).resolve())
            except OSError:
                queued.add(Path(path))

    kept, skipped = [], []
    for p in pe_files:
        try:
            resolved = p.resolve()
        except OSError:
            resolved = p
        if resolved in queued:
            skipped.append(p.name)
        else:
            kept.append(p)
    return kept, skipped


def run_ghidra(cape_data: dict, output_dir: Path, sample_path: Path,
               ghidra_cmd: str, get_cape_signatures_fn,
               shellcode_candidates: list[dict] | None = None,
               storage: Path = CAPE_STORAGE,
               include_original: bool = True) -> dict:
    """Run Ghidra headless on dropped PEs and/or the original sample.

    ``include_original=False`` is for samples another analyser already owns
    (.NET, Office, scripts, …): the wrapper is not a native program, but what
    it unpacked is, and CAPE extracted it (#646).
    """
    pe_files, access_error = discover_pe_files(cape_data, storage)
    if include_original:
        original_pe, original_source, original_note = resolve_original_sample(
            cape_data, sample_path, storage)
    else:
        original_pe, original_source, original_note = None, None, None

    # Cape's own extracted payloads already reach Ghidra as shellcode
    # candidates (run-pipeline collects cape.large_payloads with
    # source: cape_payload), and that loader handles them far better: on
    # latrodectus, 127 and 124 functions where the PE loader managed 15 and 1.
    # These are memory images, not on-disk files — memory-aligned sections that
    # Ghidra's PE loader misparses. Analysing them twice wasted a decompiler
    # run per payload and, worse, let the poor copy win propagate_project_dir
    # by being appended first (#390).
    pe_files, skipped = _drop_already_queued(pe_files, shellcode_candidates)

    will_analyse_shellcode = any(
        c.get("analyze_with_ghidra") is not False
        for c in (shellcode_candidates or [])
    )

    # The submitted sample goes first, whatever CAPE dropped (#649). It used to
    # be analysed only when CAPE extracted NO dropped PEs, so for a dropper or a
    # stager the agent saw what was dropped and never the code that dropped it
    # (all 32 dropped_pe_with_signatures analyses on the host, 2026-08-19 to
    # 2026-10-02). First, so the MAX_PE_FILES cap below can never cut it.
    had_dropped = bool(pe_files)
    deduplicated: list[str] = []
    if original_pe:
        pe_files, deduplicated = _without_copies_of(original_pe, pe_files)
        pe_files = [original_pe, *pe_files]

    # trigger_reason still says why Ghidra ran: dropped PEs, or a PE original.
    # Whether the original was analysed is original_sample_included, not this.
    if had_dropped:
        trigger_reason = "dropped_pe_with_signatures"
    elif original_pe:
        trigger_reason = "original_sample_is_pe"
    elif will_analyse_shellcode:
        # Everything was deduped into the shellcode loader, which is the point.
        # Returning "no PE files found" here would abandon the payloads that
        # are about to be analysed properly.
        trigger_reason = "cape_payloads_via_shellcode_loader"
    elif not include_original:
        # Nothing unpacked. Not an error: the routed analyser still covers the
        # sample. An unreadable CAPE tree still is one, and must say so.
        result = {"triggered": True, "analyzed_files": []}
        if access_error:
            result["payload_access_error"] = access_error
        return result
    else:
        # "no PE files found" is a claim about the sample. If Cape's storage
        # was unreadable it is a claim about us, and saying the first when the
        # second is true is how a broken feature reads as a clean result.
        if access_error:
            return {"triggered": True, "error": "Cape payloads unreadable",
                    "payload_access_error": access_error}
        if original_note:
            # The fallback was REFUSED (identity mismatch). Say so — never
            # "no PE files found", which is how #644 hid for six weeks.
            return {"triggered": True, "error": "original sample unusable",
                    "original_sample_note": original_note}
        return {"triggered": True, "error": "no PE files found"}

    sigs = get_cape_signatures_fn(cape_data)
    trigger_sigs = [s for s in sigs if s in GHIDRA_TRIGGERS]

    result = {
        "triggered": True,
        "trigger_reason": trigger_reason,
        "trigger_signatures": trigger_sigs,
        "analyzed_files": [],
    }
    if access_error:
        # Reached the original-sample fallback, but only because we could not
        # look at the extracted payloads — the report must not imply we did.
        result["payload_access_error"] = access_error
    if include_original:
        # Explicit on the native path so a reader can tell "not analysed" from
        # a report written before #649, when dropped_pe_with_signatures alone
        # meant the original was skipped.
        result["original_sample_included"] = original_pe is not None
    if original_pe is not None:
        result["original_sample_source"] = original_source
    if original_note:
        # A fallback taken, or one refused: either way the report says so.
        result["original_sample_note"] = original_note
        print(f"    NOTE: {original_note}")
    if deduplicated:
        result["original_sample_deduplicated"] = deduplicated
    if skipped:
        # Say what was not analysed here and why, so a shorter analyzed_files
        # list is legible instead of looking like the payloads went missing.
        result["pe_load_skipped"] = skipped
        result["pe_load_skipped_reason"] = (
            "already queued for the shellcode loader, which handles Cape's "
            "memory-dumped payloads better than the PE loader (#390)"
        )

    # Analyze up to 5 PEs (avoid spending hours on prolific droppers). The
    # original now takes one of the five, so a dropper with five or more PEs
    # loses one it used to keep: name the cut, never drop it silently.
    if len(pe_files) > MAX_PE_FILES:
        result["pe_cap_skipped"] = [p.name for p in pe_files[MAX_PE_FILES:]]
    for pe_path in pe_files[:MAX_PE_FILES]:
        print(f"    Analyzing {pe_path.name}...")
        # Its own project, named by content: every headless run begins with
        # "Creating project", so two PEs sharing output_dir/project left only
        # the last (#655; 36 programs lost across 14 analyses). Same rule as
        # the shellcode loader since #648.
        pe_out = output_dir / f"pe_{_content_token({'path': pe_path})}"
        file_result = run_ghidra_on_file(pe_path, pe_out, ghidra_cmd)
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
    # Verified, not assumed. The pairing is what the interpret stage brokers
    # every tool call through, and a claimed-successful analysis is not proof
    # that its program is still retrievable from the shared project (#490).
    presence_warnings = record_project_presence(result["analyzed_files"], output_dir)

    selection_warnings: list[str] = []
    project_dir, program_name = propagate_project_dir(
        result["analyzed_files"], output_dir,
        verify=make_ghidra_verifier(ghidra_cmd),
        warnings=selection_warnings)
    if project_dir:
        result["project_dir"] = project_dir
        result["program_name"] = program_name

    # A program the presence check found missing is often the same one the
    # verifier rejects; say it once.
    selection_warnings = [w for w in selection_warnings
                          if not any(w.split(" claims ")[0] == p.split(" claims ")[0]
                                     for p in presence_warnings)]
    result["analysis_warnings"] = (collect_analysis_warnings(result["analyzed_files"])
                                   + presence_warnings + selection_warnings)

    return result


# Mirrors `_analysis_warnings` in run-ghidra.py.j2. That function is the
# authority — it runs at analysis time with the sample bytes in hand, so it can
# also check the PE import directory. This side only ever sees stored counts.
# test_analysis_warnings_surface asserts the threshold here still matches the
# template's, because two copies of a rule drift (#380).
LOW_FUNCTION_THRESHOLD = 1
_DERIVED_SUFFIX = " [derived at re-score: this report predates the detector]"


def derive_analysis_warnings(analyzed_file: dict) -> list[str]:
    """Warnings inferable from a stored result, for reports written before #372.

    Every eval-corpus report predates the detector, so six analysed files sit at
    `analysis_success: True` with one function recovered and no warning against
    them — the exact state #367 is about, reading as clean. Re-scoring can
    recover the count-based half of the rule from data already on disk.

    Marked as derived rather than passed off as the analyser's own output: a
    warning the detector never emitted is a different claim, and collapsing the
    two would be its own small lie.
    """
    if not analyzed_file.get("analysis_success"):
        return []
    n = int(analyzed_file.get("functions_count") or 0)
    if n > LOW_FUNCTION_THRESHOLD:
        return []
    return [f"only {n} function(s) recovered — the loader may not have "
            f"resolved an architecture for this binary{_DERIVED_SUFFIX}"]


def collect_analysis_warnings(analyzed_files: list[dict],
                              derive_when_absent: bool = False) -> list[str]:
    """Lift per-file analysis warnings to the top of the ghidra result (#367).

    run-ghidra has emitted `analysis_warnings` on each analysed file since
    #372 — "only 1 function(s) recovered", "the PE declares a non-empty import
    directory but no imports were extracted" — and **nothing has ever read
    them**. They were produced, written to the report, and never surfaced, so
    the state they exist to describe stayed exactly as invisible as before.

    Prefixed with the program name because the interesting case is one file of
    several failing: the 124-function payload and the 1-function one sit in the
    same list, and an unattributed warning cannot tell you which is which.

    `derive_when_absent` is for the offline re-scorer only. The live path leaves
    it False: at analysis time the detector has already run, so deriving would
    second-guess it — and an EMPTY analysis_warnings list is a real answer
    ("checked, nothing wrong"), not a missing one.
    """
    out: list[str] = []
    for af in analyzed_files:
        name = af.get("program_name") or af.get("filename") or "?"
        warnings = af.get("analysis_warnings")
        if warnings is None and derive_when_absent:
            warnings = derive_analysis_warnings(af)
        for w in warnings or []:
            out.append(f"{name}: {w}")
    return out
