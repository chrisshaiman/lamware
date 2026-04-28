# Malfind → Ghidra Shellcode Analysis — Design Spec

> **Goal:** Extract injected code regions from Volatility's malfind output and
> analyze them with Ghidra headless + the agentic LLM interpretation loop,
> enabling automated reverse engineering of in-memory shellcode payloads.

**Author:** Christopher Shaiman
**Date:** 2026-04-27
**License:** Apache 2.0

---

## Problem

The pipeline currently analyzes PE files (dropped by Cape or the original sample)
with Ghidra. But many malware families inject shellcode into running processes —
this shellcode only exists in memory, not on disk. Volatility's malfind plugin
finds these injected regions (17,474 on the Emotet sample), but the pipeline
doesn't analyze their contents.

The injected shellcode often contains the most interesting malware logic: C2
communication, encryption routines, credential harvesting, and persistence
mechanisms. Without analyzing it, we're only seeing the packer/loader, not
the payload.

---

## Architecture Overview

No new containers or Ansible roles. Changes to three existing components:

```
Volatility stage (malfind --dump)
    │
    │  Dumps injected VAD regions as binary files
    │
    ▼
Pipeline orchestrator (heuristic filter)
    │
    │  17K regions → ~20 candidates → top 5
    │
    ▼
Ghidra stage (--shellcode mode, try-both arch)
    │
    │  Import as raw binary, decompile
    │
    ▼
ghidra.analyzed_files[] with source: "malfind_injection"
    │
    ▼
LLM agent investigates (unchanged — sees shellcode alongside PEs)
```

---

## Data Flow

### Stage 3: Volatility (modified)

When running the `windows.malfind` plugin, add the `--dump` flag. Volatility
extracts each injected VAD region as a separate binary file to the output
directory.

**Wrapper change:** The pipeline orchestrator passes `--dump` as an extra
argument for the malfind plugin only. Other plugins are unchanged.

**File naming:** Volatility names dump files as `pid.{pid}.vad.{start_addr}.dmp`
by default. Volatility 3 writes dump files to its current working directory
or the path specified by `--output-dir`. The pipeline creates
`reports/<task_id>/malfind_dumps/` and passes it as the output directory.
The Volatility wrapper needs a new parameter for the dump output path,
passed through to the container as an additional volume mount.

**Memory dump lifecycle:** The 4GB `memory.dmp` is still deleted immediately
after Volatility completes (existing behavior). The extracted region files are
small (KB each) and persist in the report directory.

### Stage 3.5: Heuristic Filtering (new, in orchestrator)

Pure Python function `filter_malfind_dumps()` in the pipeline orchestrator.
No new container needed.

**Step 1 — Size filter:**
- Skip regions < 256 bytes (too small for meaningful shellcode)
- Skip regions > 10MB (likely mapped DLLs or data sections)
- Configurable: `pipeline_malfind_min_size`, `pipeline_malfind_max_size`

**Step 2 — Known-benign process filter:**
- Skip injections in processes with commonly legitimate RWX memory
- Default allowlist: csrss.exe, smss.exe, MsMpEng.exe, fontdrvhost.exe
- Configurable: `pipeline_malfind_benign_processes`

**Step 3 — Content heuristics:**
- Read first 256 bytes of each dump file
- **Skip** if starts with `MZ` (PE, already handled by existing Ghidra stage)
- **Skip** if all zeros or repeating byte patterns (padding/empty allocations)
- **Score 0-10** based on shellcode indicators:
  - x86 function prologues: `55 8B EC` (push ebp; mov ebp,esp) → +2
  - x64 function prologues: `48 83 EC`, `48 89 5C` → +2
  - Position-independent code: `E8 00 00 00 00` (call $+5), `EB xx 5x` (jmp/pop) → +3
  - Shellcode starters: `FC E8` (cld; call), `60 E8` (pushad; call) → +2
  - API hash constants (ROR13 patterns) → +1
  - High entropy (> 6.0 Shannon) → +1 (compressed/encrypted payload)
  - Low entropy (< 2.0) → -2 (likely data, not code)
- Configurable: `pipeline_malfind_min_score`

**Step 4 — Deduplication:**
- Hash first 512 bytes of each candidate (SHA256)
- Skip duplicates (same shellcode injected into multiple processes)

**Step 5 — Select top N:**
- Sort by score descending
- Take top N candidates (default 5)
- Configurable: `pipeline_malfind_max_candidates`

**Logging:**
- Log summary at each filter step: "size: kept 3200/17474, process: kept 2100/3200, ..."
- Log rejected-but-close candidates (score 1-2) to debug log for tuning
- If 0 candidates survive, log the filter stats so the user can loosen thresholds

### Stage 4: Ghidra (extended)

Existing PE analysis unchanged. New shellcode analysis runs after PEs.

**Ghidra wrapper `--shellcode` mode:**

```
run-ghidra --shellcode <dump_file> <output_dir> <base_address>
```

- Uses `-loader BinaryLoader` (raw binary, no PE parsing)
- Uses `-processor x86:LE:64:default` or `x86:LE:32:default`
- Sets `-baseAddr <addr>` from malfind's Start VPN
- Same container isolation: `--network=none`, `--read-only`, `--cap-drop=ALL`

**Try-both architecture detection:**

For each candidate:
1. Import as x64, run ExportAnalysis.java, count functions
2. Import as x86, run ExportAnalysis.java, count functions
3. Keep whichever produced more functions
4. If tied, prefer x64 (Win11 host is 64-bit)
5. If both 0 functions, keep x64 and flag `"no_functions_detected": true`

**Output metadata per shellcode region:**

```json
{
  "source": "malfind_injection",
  "pid": 4532,
  "process": "explorer.exe",
  "injection_address": "0x7ff612340000",
  "region_size": 8192,
  "architecture": "x64",
  "architecture_detection": "x64_had_more_functions",
  "filter_score": 8,
  "analysis_success": true,
  "functions_count": 12,
  "imports": [],
  "strings_of_interest": [],
  "decompiled_functions": [...],
  "project_dir": "/output/project_sc_0/analysis.rep",
  "program_name": "pid.4532.vad.0x7ff612340000.dmp"
}
```

This goes into `ghidra.analyzed_files[]` alongside PE results.

### Stages 4.5 and 5: LLM Interpret + Summary (unchanged)

The LLM agent sees shellcode entries in `analyzed_files` with
`"source": "malfind_injection"`. It can use all 6 Ghidra tools (decompile,
xrefs, strings, data, list functions) on shellcode projects the same way it
does on PE projects.

The agent's system prompt already handles untrusted data. Shellcode
decompilation is no different from PE decompilation from a safety perspective.

The executive summary stage naturally includes shellcode findings because it
reads the full merged report.

---

## Modified Files

### Volatility wrapper

```
ansible/roles/volatility/templates/run-volatility-wrapper.sh.j2
```
- Accept optional extra args after the plugin name
- Pass through to the `vol` command (e.g., `--dump`)

### Pipeline orchestrator

```
ansible/roles/pipeline/templates/run-pipeline.py.j2
```
- Modify `run_single_plugin()` to pass `--dump` for malfind
- Add `filter_malfind_dumps()` function (heuristic filter)
- Add `run_ghidra_shellcode()` function (try-both import)
- Extend `run_ghidra()` to process shellcode candidates after PEs
- Add malfind dump output directory management

### Pipeline defaults

```
ansible/roles/pipeline/defaults/main.yml
```
- Add `pipeline_malfind_*` configuration variables

### Ghidra wrapper

```
ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2
ansible/roles/ghidra/templates/run-ghidra.py.j2
```
- Add `--shellcode` mode with BinaryLoader and processor flags
- Support base address parameter

---

## Configuration

### New pipeline defaults

```yaml
# Malfind shellcode analysis
pipeline_malfind_enabled: true
pipeline_malfind_max_candidates: 5
pipeline_malfind_min_size: 256
pipeline_malfind_max_size: 10485760  # 10MB
pipeline_malfind_min_score: 2
pipeline_malfind_benign_processes:
  - csrss.exe
  - smss.exe
  - MsMpEng.exe
  - fontdrvhost.exe
```

---

## Security Considerations

**No new attack surface.** Shellcode files are analyzed in the same
`--network=none`, `--cap-drop=ALL` Ghidra container as PE files. The
heuristic filter runs in the pipeline orchestrator on the host (trusted
code, no adversary-controlled execution).

**Malfind dump files are adversary-controlled data** — they're literally
injected code from malware. But they're only ever read by the heuristic
filter (first 256 bytes, no execution) and imported into Ghidra (static
analysis only, no execution). Same threat model as PE analysis.

**LLM prompt injection risk is identical** to PE analysis — decompiled
shellcode is wrapped in UNTRUSTED_CODE delimiters, same safety framing.

---

## Cost Estimates

**Ghidra time:** ~30s per candidate × 2 (try-both) × 5 candidates = ~5 min added to pipeline

**LLM cost:** Shellcode regions produce smaller decompilation than full PEs
(fewer functions, shorter code). The LLM agent may use 2-5 tool calls per
shellcode region. At Sonnet pricing, roughly $0.02-0.10 per region.

**Disk:** Malfind dump files: ~50KB-5MB per region × 20 candidates = ~1-100MB.
Negligible compared to the 4GB memory dump.
