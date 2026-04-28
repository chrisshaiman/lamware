# Malfind → Ghidra Shellcode Analysis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract injected code regions from Volatility's malfind `--dump` output, filter heuristically, import into Ghidra as raw shellcode with try-both architecture detection, and feed results to the existing LLM interpretation agent.

**Architecture:** No new containers or roles. Extends three existing components: Volatility wrapper (add `--dump` passthrough), pipeline orchestrator (heuristic filter + shellcode Ghidra import), Ghidra wrapper (`--shellcode` mode with BinaryLoader). Shellcode results go into `ghidra.analyzed_files[]` alongside PE results.

**Tech Stack:** Python 3.12, Volatility 3 (malfind --dump), Ghidra 12.0.4 (BinaryLoader), Podman, Ansible

**Spec:** `docs/superpowers/specs/2026-04-27-malfind-to-ghidra-design.md`

---

## File Structure

### Modified files

```
ansible/roles/volatility/templates/run-volatility-wrapper.sh.j2
  — Accept extra plugin args, pass through to vol command

ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2
  — Add --shellcode mode (BinaryLoader, processor flag, base address)

ansible/roles/ghidra/templates/run-ghidra.py.j2
  — Add --shellcode mode (analyzeHeadless with -loader and -processor)

ansible/roles/pipeline/templates/run-pipeline.py.j2
  — Add filter_malfind_dumps(), run_ghidra_shellcode()
  — Modify run_single_plugin() for --dump on malfind
  — Add Stage 3.5 to run_pipeline()

ansible/roles/pipeline/defaults/main.yml
  — Add pipeline_malfind_* config variables
```

---

### Task 1: Volatility wrapper — extra args passthrough

Add support for passing extra arguments (like `--dump`) through to the Volatility plugin command inside the container.

**Files:**
- Modify: `ansible/roles/volatility/templates/run-volatility-wrapper.sh.j2`

- [ ] **Step 1: Update wrapper to accept extra args**

Replace the entire file with:

```bash
#!/bin/bash
# =============================================================================
# run-volatility — host-side wrapper for containerized Volatility 3
# Runs a single Volatility plugin against a memory dump inside a Podman
# container with full isolation.
#
# Usage: run-volatility <dump_path> <plugin> [output_dir] [extra_args...]
#
# Example:
#   run-volatility /tmp/memdump.raw windows.pslist /tmp/vol-output
#   run-volatility /tmp/memdump.raw windows.malfind /tmp/vol-output --dump
#
# Author: Christopher Shaiman
# License: Apache 2.0
# =============================================================================

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: run-volatility <dump_path> <plugin> [output_dir] [extra_args...]" >&2
    exit 1
fi

DUMP_PATH="$(realpath "$1")"
DUMP_DIR="$(dirname "$DUMP_PATH")"
DUMP_NAME="$(basename "$DUMP_PATH")"
PLUGIN="$2"
OUTPUT_DIR="${3:-{{ volatility_output_dir }}}"
# Extra args (e.g., --dump) are passed through to the plugin
shift 3 2>/dev/null || shift $#
EXTRA_ARGS=("$@")

if [ ! -f "$DUMP_PATH" ]; then
    echo "Error: dump not found: $DUMP_PATH" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Container is read-only with targeted writable tmpfs mounts for
# Volatility's cache and temp files. Memory dump directory mounted
# directly (read-only) — no copy, since dumps are multi-GB.
exec podman run --rm \
    --network=none \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges \
    --memory={{ volatility_container_memory }} \
    --cpus={{ volatility_container_cpus }} \
    --timeout={{ volatility_container_timeout }} \
    --tmpfs /tmp:size=2g \
    --tmpfs /root:size=100m \
    --tmpfs /home:size=100m \
    --tmpfs /var/cache:size=100m \
    --tmpfs /usr/local/lib/python3.12/site-packages/volatility3/framework/plugins:size=50m \
    -v "$DUMP_DIR:/dump:ro" \
    -v "{{ volatility_symbols_dir }}:/symbols:ro" \
    -v "$OUTPUT_DIR:/output:rw" \
    localhost/volatility3:latest \
    -f "/dump/$DUMP_NAME" \
    -s /symbols \
    -r json \
    -o /output \
    "$PLUGIN" \
    "${EXTRA_ARGS[@]}"
```

Key changes from original:
- Added `shift 3` to capture extra args after the first three positional params
- Added `"${EXTRA_ARGS[@]}"` at the end of the podman command
- Added `-o /output` to tell Volatility to write dump files to the output dir (maps to host `$OUTPUT_DIR`)

- [ ] **Step 2: Deploy and test**

```bash
SSH_AUTH_SOCK=/tmp/ssh-agent-sandbox.sock ansible-playbook -i inventory/hosts site.yml --ask-vault-pass --tags volatility
```

Test that normal plugins still work (no extra args):
```bash
ssh sandbox 'cd /tmp && sudo -u cape /opt/volatility/run-volatility /opt/CAPEv2/storage/analyses/1/memory.dmp windows.psscan /tmp/vol-test'
```

Note: This test requires a memory dump to exist. If none available, just verify the deploy succeeds and move on — full testing happens in Task 4.

- [ ] **Step 3: Commit**

```bash
git add ansible/roles/volatility/templates/run-volatility-wrapper.sh.j2
git commit -m "feat(volatility): add extra args passthrough for plugin flags

Supports passing --dump and other plugin-specific flags through to
the Volatility container. Also adds -o /output so dump files land
in the mapped output directory."
```

---

### Task 2: Ghidra wrapper — shellcode import mode

Add a `--shellcode` mode to the Ghidra wrapper that imports raw binary files using BinaryLoader with a specified processor architecture and base address.

**Files:**
- Modify: `ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2`
- Modify: `ansible/roles/ghidra/templates/run-ghidra.py.j2`

- [ ] **Step 1: Add --shellcode mode to wrapper script**

In `ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2`, add a new mode block after the `--tool` block (after line 58, before the Analysis mode comment):

```bash
# ---------------------------------------------------------------------------
# Shellcode mode — import raw binary for analysis
# ---------------------------------------------------------------------------
if [ "$1" = "--shellcode" ]; then
    if [ $# -lt 3 ] || [ $# -gt 4 ]; then
        echo "Usage: run-ghidra --shellcode <dump_file> <output_dir> [base_address]" >&2
        echo "  Imports raw binary using BinaryLoader. Tries x64 then x86, keeps best." >&2
        exit 1
    fi

    DUMP_FILE="$(realpath "$2")"
    DUMP_NAME="$(basename "$DUMP_FILE")"
    OUTPUT_DIR="$3"
    BASE_ADDR="${4:-0x0}"

    if [ ! -f "$DUMP_FILE" ]; then
        echo "Error: file not found: $DUMP_FILE" >&2
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"
    chmod 777 "$OUTPUT_DIR"

    # Copy dump to temp dir for isolation
    WORK_DIR="$(mktemp -d)"
    trap 'rm -rf "$WORK_DIR"' EXIT
    chmod 755 "$WORK_DIR"
    cp "$DUMP_FILE" "$WORK_DIR/$DUMP_NAME"
    chmod 644 "$WORK_DIR/$DUMP_NAME"

    exec podman run --rm \
        --network=none \
        --read-only \
        --cap-drop=ALL \
        --security-opt=no-new-privileges \
        --memory={{ ghidra_container_memory }} \
        --cpus={{ ghidra_container_cpus }} \
        --timeout={{ ghidra_container_timeout }} \
        --tmpfs /tmp:size=1g \
        --tmpfs /nonexistent:size=100m \
        --tmpfs /var/cache:size=100m \
        --user 65534:65534 \
        -v "$WORK_DIR:/sample:ro" \
        -v "$OUTPUT_DIR:/output:rw" \
        localhost/ghidra:latest \
        --shellcode "/sample/$DUMP_NAME" "$BASE_ADDR"
fi
```

- [ ] **Step 2: Add --shellcode mode to run-ghidra.py**

In `ansible/roles/ghidra/templates/run-ghidra.py.j2`, add a new function after `run_tool()`:

```python
def analyze_shellcode(sample_path: Path, processor: str, base_addr: str = "0x0") -> dict:
    """Import and analyze a raw binary (shellcode) using BinaryLoader.

    Unlike PE analysis, this uses -loader BinaryLoader and -processor to
    specify the architecture since raw shellcode has no headers.
    """
    project_dir = Path("/output/project")
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = "analysis"
    export_path = Path("/tmp/ghidra_export.json")

    # Clean any previous export
    if export_path.exists():
        export_path.unlink()

    result = subprocess.run(
        [
            ANALYZE_HEADLESS,
            str(project_dir),
            project_name,
            "-import", str(sample_path),
            "-overwrite",
            "-loader", "BinaryLoader",
            "-processor", processor,
            "-cspec", "gcc" if "64" in processor else "windows_32",
            "-analysisTimeoutPerFile", "120",
            "-postScript", "ExportAnalysis.java",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )

    output = {
        "filename": sample_path.name,
        "sha256": sha256_file(sample_path),
        "processor": processor,
        "base_address": base_addr,
        "analysis_success": False,
        "functions_count": 0,
        "imports": [],
        "strings_of_interest": [],
        "decompiled_functions": [],
        "entry_point": "unknown",
    }

    if export_path.exists():
        try:
            with export_path.open() as f:
                exported = json.load(f)
            output["analysis_success"] = True
            output["functions_count"] = exported.get("functions_count", 0)
            output["imports"] = exported.get("imports", [])
            output["strings_of_interest"] = exported.get("strings_of_interest", [])
            output["entry_point"] = exported.get("entry_point", "unknown")
            output["decompiled_functions"] = exported.get("decompiled_functions", [])
            output["project_dir"] = exported.get("project_dir", "")
            output["program_name"] = sample_path.name
        except (json.JSONDecodeError, KeyError) as e:
            output["parse_error"] = str(e)

    return output
```

- [ ] **Step 3: Update main() for --shellcode mode**

In `main()`, add a shellcode branch before the `--tool` check:

```python
    # Shellcode mode: run-ghidra.py --shellcode <sample_path> <base_address>
    if len(sys.argv) >= 2 and sys.argv[1] == "--shellcode":
        if len(sys.argv) != 4:
            print(json.dumps({
                "error": "Usage: run-ghidra.py --shellcode <sample_path> <base_address>"
            }))
            sys.exit(1)

        sample_path = Path(sys.argv[2])
        base_addr = sys.argv[3]

        if not sample_path.exists():
            print(json.dumps({"error": f"File not found: {sample_path}"}))
            sys.exit(1)

        # Try both architectures, keep whichever finds more functions
        result_x64 = analyze_shellcode(sample_path, "x86:LE:64:default", base_addr)
        result_x86 = analyze_shellcode(sample_path, "x86:LE:32:default", base_addr)

        x64_funcs = result_x64.get("functions_count", 0)
        x86_funcs = result_x86.get("functions_count", 0)

        if x86_funcs > x64_funcs:
            result = result_x86
            result["architecture"] = "x86"
            result["architecture_detection"] = f"x86_had_more_functions ({x86_funcs} vs {x64_funcs})"
        else:
            result = result_x64
            result["architecture"] = "x64"
            if x64_funcs == x86_funcs:
                result["architecture_detection"] = f"tied_at_{x64_funcs}_prefer_x64"
            else:
                result["architecture_detection"] = f"x64_had_more_functions ({x64_funcs} vs {x86_funcs})"

        if x64_funcs == 0 and x86_funcs == 0:
            result["no_functions_detected"] = True

        print(json.dumps(result, indent=2))
        return
```

- [ ] **Step 4: Deploy and test**

```bash
SSH_AUTH_SOCK=/tmp/ssh-agent-sandbox.sock ansible-playbook -i inventory/hosts site.yml --ask-vault-pass --tags ghidra
```

Test with a small binary file (doesn't need to be real shellcode — just verifies import works):
```bash
ssh sandbox 'cd /tmp && echo -ne "\x48\x83\xec\x28\x48\x8b\x05" > /tmp/test_sc.bin && sudo -u cape /opt/ghidra/run-ghidra --shellcode /tmp/test_sc.bin /opt/ghidra/output/sc-test 0x10000'
```

Expected: JSON output with `analysis_success`, `architecture`, `architecture_detection` fields.

- [ ] **Step 5: Commit**

```bash
git add ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2 \
        ansible/roles/ghidra/templates/run-ghidra.py.j2
git commit -m "feat(ghidra): add --shellcode mode for raw binary import

Imports raw shellcode using BinaryLoader with specified processor
architecture. Try-both detection: imports as x64 then x86, keeps
whichever produces more functions. Used by the malfind pipeline
to analyze injected code regions."
```

---

### Task 3: Pipeline defaults — malfind config

Add the malfind shellcode analysis configuration variables.

**Files:**
- Modify: `ansible/roles/pipeline/defaults/main.yml`

- [ ] **Step 1: Add malfind config to defaults**

Append to the end of `ansible/roles/pipeline/defaults/main.yml`:

```yaml

# Malfind shellcode analysis (Stage 3.5)
# Extract and analyze injected code regions from memory dumps
pipeline_malfind_enabled: true
pipeline_malfind_max_candidates: 5       # top N shellcode regions to analyze
pipeline_malfind_min_size: 256           # skip regions smaller than this (bytes)
pipeline_malfind_max_size: 10485760      # skip regions larger than 10MB
pipeline_malfind_min_score: 2            # minimum heuristic score (0-10)
pipeline_malfind_benign_processes:       # processes with commonly legitimate RWX
  - csrss.exe
  - smss.exe
  - MsMpEng.exe
  - fontdrvhost.exe
```

- [ ] **Step 2: Commit**

```bash
git add ansible/roles/pipeline/defaults/main.yml
git commit -m "feat(pipeline): add malfind shellcode analysis config defaults

Configurable thresholds for heuristic filtering: size limits,
benign process allowlist, minimum score, max candidates."
```

---

### Task 4: Pipeline orchestrator — heuristic filter + shellcode analysis

The main integration task. Add the malfind dump extraction, heuristic filtering, and shellcode Ghidra import to the pipeline orchestrator.

**Files:**
- Modify: `ansible/roles/pipeline/templates/run-pipeline.py.j2`

- [ ] **Step 1: Add malfind config constants**

After the existing `INTERPRET_CONFIG` block and before `REPORTS_DIR`, add:

```python
# Malfind shellcode analysis config
MALFIND_ENABLED = {{ (pipeline_malfind_enabled | default(true)) | to_json }}
MALFIND_MAX_CANDIDATES = {{ pipeline_malfind_max_candidates | default(5) }}
MALFIND_MIN_SIZE = {{ pipeline_malfind_min_size | default(256) }}
MALFIND_MAX_SIZE = {{ pipeline_malfind_max_size | default(10485760) }}
MALFIND_MIN_SCORE = {{ pipeline_malfind_min_score | default(2) }}
MALFIND_BENIGN_PROCESSES = {{ (pipeline_malfind_benign_processes | default(['csrss.exe', 'smss.exe', 'MsMpEng.exe', 'fontdrvhost.exe'])) | to_json }}
```

- [ ] **Step 2: Modify run_single_plugin to pass --dump for malfind**

Replace the existing `run_single_plugin` function:

```python
def run_single_plugin(dump_path: Path, plugin: str, output_dir: Path,
                      extra_args: list[str] | None = None) -> dict:
    """Run a single Volatility plugin. Returns parsed JSON or error."""
    # malfind and vadinfo scan every memory region — need longer timeout
    # on 4GB+ dumps these can take 10-15 minutes
    plugin_timeout = 600
    cmd = [VOLATILITY_CMD, str(dump_path), plugin, str(output_dir)]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=plugin_timeout,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:200]}
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": f"timeout ({plugin_timeout}s)"}
    except json.JSONDecodeError:
        # Volatility JSON output may have extra lines — try to extract
        lines = result.stdout.strip().split("\n")
        for line in lines:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return {"error": "invalid JSON output", "raw": result.stdout[:500]}
```

- [ ] **Step 3: Pass --dump when running malfind**

In the `run_volatility` function, modify the plugin loop (around line 382) to pass `--dump` for malfind:

Replace:
```python
    for plugin in all_plugins:
        short_name = plugin.replace("windows.", "")
        print(f"    Running {plugin}...")
        plugin_output = run_single_plugin(dump_path, plugin, output_dir)
```

With:
```python
    # Create malfind dump directory
    malfind_dump_dir = output_dir / "malfind_dumps"
    malfind_dump_dir.mkdir(parents=True, exist_ok=True)

    for plugin in all_plugins:
        short_name = plugin.replace("windows.", "")
        print(f"    Running {plugin}...")
        # Pass --dump for malfind to extract injected VAD regions
        extra = ["--dump"] if short_name == "malfind" and MALFIND_ENABLED else None
        plugin_output = run_single_plugin(dump_path, plugin, output_dir, extra_args=extra)
```

- [ ] **Step 4: Add the heuristic filter function**

Add after the `run_volatility` function (before the Ghidra section):

```python
# -------------------------------------------------------------------------
# Stage 3.5: Malfind shellcode filtering
# -------------------------------------------------------------------------

import hashlib as _hashlib
import math as _math


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * _math.log2(p)
    return entropy


def _score_shellcode(first_bytes: bytes) -> int:
    """Score a memory region for likelihood of being shellcode (0-10)."""
    score = 0
    if len(first_bytes) < 4:
        return 0

    # x86 function prologues
    if first_bytes[:3] == b"\x55\x8b\xec":  # push ebp; mov ebp, esp
        score += 2
    # x64 function prologues
    if first_bytes[:3] in (b"\x48\x83\xec", b"\x48\x89\x5c"):
        score += 2
    # Position-independent code patterns
    if first_bytes[:5] == b"\xe8\x00\x00\x00\x00":  # call $+5
        score += 3
    if first_bytes[:2] == b"\xfc\xe8":  # cld; call
        score += 2
    if first_bytes[:1] == b"\x60" and first_bytes[1:2] == b"\xe8":  # pushad; call
        score += 2
    # Short jmp + pop (common shellcode starter: jmp over; pop reg)
    if first_bytes[0] == 0xeb and len(first_bytes) > first_bytes[1] + 2:
        target = first_bytes[1] + 2
        if target < len(first_bytes) and first_bytes[target] in range(0x58, 0x60):
            score += 3

    # Entropy check
    entropy = _shannon_entropy(first_bytes)
    if entropy > 6.0:
        score += 1  # high entropy — compressed/encrypted
    if entropy < 2.0:
        score -= 2  # low entropy — likely data, not code

    # Check for REX.W prefixes (strong x64 signal, indicates real code)
    rex_count = sum(1 for b in first_bytes[:64] if b in (0x48, 0x4c, 0x4d))
    if rex_count > 5:
        score += 1

    return max(score, 0)


def filter_malfind_dumps(dump_dir: Path, vol_malfind_output: list | dict) -> list[dict]:
    """Filter malfind dump files to find shellcode candidates.

    Returns a list of candidate dicts with path, metadata, and score.
    """
    if not dump_dir.exists():
        print("    [!] Malfind dump directory not found")
        return []

    dump_files = list(dump_dir.glob("*.dmp"))
    if not dump_files:
        print("    [!] No malfind dump files found")
        return []

    print(f"    Starting with {len(dump_files)} malfind dump files")

    # Parse malfind JSON output to get process info per region
    # Volatility malfind JSON is a list of dicts with PID, Process, Start VPN, etc.
    region_info = {}
    if isinstance(vol_malfind_output, list):
        for entry in vol_malfind_output:
            pid = entry.get("PID", 0)
            start_vpn = entry.get("Start VPN", "")
            process = entry.get("Process", "unknown")
            # Build a key matching the dump filename pattern
            if isinstance(start_vpn, str) and start_vpn.startswith("0x"):
                key = f"pid.{pid}.vad.{start_vpn}"
            else:
                key = f"pid.{pid}.vad.0x{start_vpn:x}" if isinstance(start_vpn, int) else ""
            region_info[key] = {
                "pid": pid,
                "process": process,
                "start_vpn": start_vpn,
                "protection": entry.get("Protection", ""),
            }

    # Step 1: Size filter
    candidates = []
    size_filtered = 0
    for f in dump_files:
        size = f.stat().st_size
        if size < MALFIND_MIN_SIZE or size > MALFIND_MAX_SIZE:
            size_filtered += 1
            continue
        # Match dump file to region info
        stem = f.stem  # e.g., "pid.4532.vad.0x7ff612340000"
        info = region_info.get(stem, {"pid": 0, "process": "unknown", "start_vpn": "0x0"})
        candidates.append({"path": f, "size": size, **info})

    print(f"    Size filter: kept {len(candidates)}/{len(dump_files)} (dropped {size_filtered})")

    # Step 2: Benign process filter
    pre_process = len(candidates)
    candidates = [c for c in candidates
                  if c["process"].lower() not in [p.lower() for p in MALFIND_BENIGN_PROCESSES]]
    print(f"    Process filter: kept {len(candidates)}/{pre_process}")

    # Step 3: Content heuristics
    scored = []
    pe_skipped = 0
    padding_skipped = 0
    for c in candidates:
        try:
            with c["path"].open("rb") as fh:
                first_bytes = fh.read(256)
        except OSError:
            continue

        # Skip PE files (already handled by Ghidra PE analysis)
        if first_bytes[:2] == b"MZ":
            pe_skipped += 1
            continue

        # Skip all-zero or single-byte repeating
        if len(set(first_bytes)) <= 2:
            padding_skipped += 1
            continue

        score = _score_shellcode(first_bytes)
        c["score"] = score
        c["first_bytes_hex"] = first_bytes[:32].hex()
        scored.append(c)

    print(f"    Content filter: kept {len(scored)} (PE: {pe_skipped}, padding: {padding_skipped})")

    # Step 4: Deduplicate by first 512 bytes hash
    seen_hashes = set()
    deduped = []
    for c in scored:
        try:
            with c["path"].open("rb") as fh:
                h = _hashlib.sha256(fh.read(512)).hexdigest()
        except OSError:
            continue
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        c["content_hash"] = h
        deduped.append(c)

    print(f"    Dedup: kept {len(deduped)}/{len(scored)}")

    # Step 5: Score filter + select top N
    above_threshold = [c for c in deduped if c["score"] >= MALFIND_MIN_SCORE]
    above_threshold.sort(key=lambda c: c["score"], reverse=True)
    selected = above_threshold[:MALFIND_MAX_CANDIDATES]

    # Log rejected-but-close for tuning
    near_misses = [c for c in deduped if 0 < c["score"] < MALFIND_MIN_SCORE]
    if near_misses:
        print(f"    Near misses (score 1-{MALFIND_MIN_SCORE - 1}): {len(near_misses)} regions")
        for nm in near_misses[:5]:
            print(f"      {nm['process']} pid={nm['pid']} score={nm['score']} first_bytes={nm['first_bytes_hex'][:16]}")

    print(f"    Selected: {len(selected)} candidates (min_score={MALFIND_MIN_SCORE})")
    for c in selected:
        print(f"      {c['process']} pid={c['pid']} score={c['score']} size={c['size']} addr={c.get('start_vpn', '?')}")

    return selected
```

- [ ] **Step 5: Add shellcode Ghidra analysis function**

Add after `filter_malfind_dumps`:

```python
def run_ghidra_shellcode(candidate: dict, output_dir: Path) -> dict:
    """Run Ghidra on a shellcode candidate with try-both architecture detection.

    Returns the analysis result with source metadata for malfind injection.
    """
    dump_path = candidate["path"]
    base_addr = candidate.get("start_vpn", "0x0")
    if isinstance(base_addr, int):
        base_addr = f"0x{base_addr:x}"
    sc_output_dir = output_dir / f"shellcode_{candidate['pid']}_{base_addr.replace('0x', '')}"

    try:
        result = subprocess.run(
            [GHIDRA_CMD, "--shellcode", str(dump_path), str(sc_output_dir), base_addr],
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
                "error": result.stderr[:200],
            }
        analysis = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {
            "source": "malfind_injection",
            "pid": candidate.get("pid"),
            "process": candidate.get("process"),
            "injection_address": base_addr,
            "error": "timeout (300s)",
        }
    except json.JSONDecodeError:
        return {
            "source": "malfind_injection",
            "pid": candidate.get("pid"),
            "process": candidate.get("process"),
            "injection_address": base_addr,
            "error": "invalid JSON from Ghidra",
        }

    # Add malfind source metadata
    analysis["source"] = "malfind_injection"
    analysis["pid"] = candidate.get("pid")
    analysis["process"] = candidate.get("process")
    analysis["injection_address"] = base_addr
    analysis["region_size"] = candidate.get("size")
    analysis["filter_score"] = candidate.get("score")

    return analysis
```

- [ ] **Step 6: Wire Stage 3.5 into run_pipeline**

In the `run_pipeline` function, find the Stage 4 Ghidra section. Before it, add Stage 3.5. Find this code:

```python
    # Stage 4: Ghidra (triggered by dropped payloads)
```

Insert before it:

```python
    # Stage 3.5: Shellcode filtering (from malfind dumps)
    shellcode_candidates = []
    if MALFIND_ENABLED and report.get("volatility", {}).get("triggered"):
        malfind_dump_dir = output_dir / "malfind_dumps"
        malfind_output = report.get("volatility", {}).get("plugins", {}).get("malfind", [])
        print(f"\n[Stage 3.5] Shellcode filtering: scanning malfind dumps...")
        shellcode_candidates = filter_malfind_dumps(malfind_dump_dir, malfind_output)

```

Then in the Ghidra stage, after the existing PE analysis loop, add shellcode analysis. Find:

```python
    # Analyze up to 5 dropped PEs (avoid spending hours on prolific droppers)
    for pe_path in pe_files[:5]:
        print(f"    Analyzing {pe_path.name}...")
        file_result = run_ghidra_on_file(pe_path, output_dir)
        result["analyzed_files"].append(file_result)

    return result
```

Add before `return result`:

```python
    # Analyze shellcode candidates from malfind
    if shellcode_candidates:
        print(f"    Analyzing {len(shellcode_candidates)} shellcode candidates...")
        for candidate in shellcode_candidates:
            print(f"    Shellcode: pid={candidate['pid']} {candidate['process']} score={candidate['score']}")
            sc_result = run_ghidra_shellcode(candidate, output_dir)
            result["analyzed_files"].append(sc_result)
```

Note: The `shellcode_candidates` variable needs to be passed to `run_ghidra`. Modify the `run_ghidra` function signature to accept it:

Change:
```python
def run_ghidra(cape_data: dict, output_dir: Path, sample_path: Path) -> dict:
```
To:
```python
def run_ghidra(cape_data: dict, output_dir: Path, sample_path: Path,
               shellcode_candidates: list[dict] | None = None) -> dict:
```

And update the call in `run_pipeline` to pass the candidates:
```python
        report["ghidra"] = run_ghidra(cape_data, output_dir, sample_path,
                                      shellcode_candidates=shellcode_candidates)
```

- [ ] **Step 7: Deploy and test**

```bash
SSH_AUTH_SOCK=/tmp/ssh-agent-sandbox.sock ansible-playbook -i inventory/hosts site.yml --ask-vault-pass --tags pipeline
```

Full test requires submitting a sample through the pipeline that triggers Volatility (injection signatures). Use the Emotet sample via sample-feeder or direct pipeline invocation.

- [ ] **Step 8: Commit**

```bash
git add ansible/roles/pipeline/templates/run-pipeline.py.j2
git commit -m "feat(pipeline): add malfind shellcode filtering and Ghidra analysis

Stage 3.5 heuristic filter: size → process → content patterns → dedup
→ top N candidates. Shellcode candidates imported into Ghidra with
try-both architecture detection (x64/x86). Results merge into
ghidra.analyzed_files with source: malfind_injection.

Includes debug logging for near-miss candidates to help tune filters."
```

---

## Self-Review

**Spec coverage:**
- Volatility --dump passthrough: Task 1 ✓
- Ghidra shellcode import (BinaryLoader): Task 2 ✓
- Try-both architecture detection: Task 2 (run-ghidra.py --shellcode mode) ✓
- Heuristic filter (5 steps): Task 4 (filter_malfind_dumps) ✓
- Pipeline config: Task 3 ✓
- Malfind dump dir management: Task 4 Step 3 ✓
- Results in ghidra.analyzed_files: Task 4 Step 5-6 ✓
- Memory dump lifecycle: unchanged (delete after Volatility, dump files persist) ✓
- Debug logging for near misses: Task 4 Step 4 (near_misses section) ✓
- LLM interpret unchanged: no tasks needed, reads analyzed_files naturally ✓

**Placeholder scan:** No TBDs or placeholders. All code blocks are complete.

**Type consistency:** `filter_malfind_dumps` returns `list[dict]`, `run_ghidra_shellcode` accepts one dict from that list, returns dict for `analyzed_files`. `run_single_plugin` signature extended with `extra_args` parameter, all callers updated. `run_ghidra` signature extended with `shellcode_candidates`.
