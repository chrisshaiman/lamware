# Automated Malware Analysis Platform

An end-to-end malware analysis platform that doesn't just run tools — it **connects them**. Dynamic sandbox detonation, memory forensics, static analysis, and AI-powered reverse engineering work together, cross-referencing their findings to produce intelligence that no single tool generates alone.

## What Makes This Different

Most malware analysis setups run tools independently — Cape produces a report, Volatility produces a report, Ghidra produces a report, and an analyst manually correlates them. This platform automates that analyst workflow:

**Cross-tool correlation.** When Cape's sandbox observes a process writing shellcode into another process, the platform extracts those exact bytes from Cape's API traces, scans them for resolved API names and file paths, and cross-references against Volatility's memory forensics to detect if the shellcode modified itself after landing. If Cape logged a dropped DLL and Volatility confirms it was loaded by a system process — that's a confirmed second-stage deployment, not just a file write.

**AI-driven investigation.** An agentic LLM autonomously explores the binary using Ghidra's decompiler — listing functions, tracing cross-references, decompiling suspicious code, reading data — and produces a structured analysis with MITRE ATT&CK mappings. It doesn't just describe what it sees; it investigates iteratively like a human analyst would, following leads across function calls.

**Kill chain narrative.** The executive summary organizes findings by behavior (injection, persistence, C2, evasion) not by tool. Each claim cites which tools corroborated it: *"The malware injected identical 235-byte shellcode stubs into 59 system processes (Cape API traces), resolving LoadLibraryA, CreateRemoteThread, and WSAStartup at runtime (Volatility memory artifacts), confirming both process injection and C2 communication capability."*

**Ground-truth shellcode extraction.** Instead of scanning 17,000+ memory regions hoping to find injected code, the platform reads Cape's WriteProcessMemory traces to extract the exact bytes that were injected — with the source process, target process, and injection address. No heuristics needed for what Cape directly observed.

## What It Produces

Submit a malware sample and get back:

- **Structured IOCs** with STIX 2.1 types, source attribution, and context — ready for SIEM searches and block lists
- **MITRE ATT&CK mapping** from multiple sources (Cape behavioral signatures + AI reverse engineering)
- **Cross-tool findings** — dropped files confirmed loaded, shellcode self-modification detected, command line spoofing identified
- **AI reverse engineering narrative** — what the malware does, how it works, traced through decompiled code
- **Kill chain executive summary** — analyst-ready briefing organized by attack phase
- **Memory forensics insights** — suspicious command lines, mutex IOCs, DLLs from unusual paths, anomalous process relationships
- **PDF report** with source attribution badges showing which pipeline stage surfaced each finding
- **PostgreSQL database** with normalized data for cross-sample correlation and evolution tracking
- **Web dashboard** for browsing analyses, IOCs, and MITRE techniques

## Pipeline Architecture

```
Sample
  │
  ├─ Stage 1: Triage ──────────── YARA, ssdeep, FLOSS, entropy, PE analysis
  │  (containerized, --network=none)
  │
  ├─ Stage 2: Dynamic Analysis ── CAPEv2 sandbox, Windows 11 guest VMs
  │  (KVM/QEMU with anti-evasion)   Behavioral signatures, memory dumps, network capture
  │     │
  │     ├─ 2.5: Injection Buffer ── Extract shellcode bytes from WriteProcessMemory
  │     │   Extraction               API traces — ground truth, no scanning needed
  │     │
  │     └─ 2.5: Cape Payload ────── Scan unpacked/extracted payloads for
  │         Analysis                  decrypted APIs, file paths, URLs, IPs
  │
  ├─ Stage 3: Memory Forensics ── Volatility 3 (psscan, malfind, netscan, dlllist...)
  │  (containerized, --network=none)   Process injection detection, connection state,
  │                                     mutex IOCs, DLL loads, command line analysis
  │
  ├─ Cross-Correlation ────────── Compare Cape + Volatility findings:
  │                                 Dropped file loaded? Shellcode self-modified?
  │                                 Command line spoofed?
  │
  ├─ Stage 4: Static Analysis ─── Ghidra headless (decompilation, imports, strings)
  │  (containerized, --network=none)   Functions, pseudocode, cross-references
  │
  ├─ Stage 4.5: AI Investigation ─ Agentic LLM with 6 Ghidra query tools
  │  (containerized, --network=host)   Autonomous investigation, 6-10 tool calls
  │  ↕ orchestrator brokers           MITRE ATT&CK mapping, family identification
  │  (tool arg validation)            Model escalation: Sonnet → Opus for complex samples
  │
  ├─ IOC Extraction ───────────── Structured indicators from ALL stages
  │                                 STIX 2.1 types, source attribution, context
  │
  ├─ Kill Chain Summary ───────── LLM narrative organized by attack phase
  │                                 Cites corroborating sources for each finding
  │
  ├─ Database Ingestion ────────── PostgreSQL with normalized IOCs, techniques,
  │                                 capabilities, network events, MISP-style tags
  │
  └─ PDF Report ───────────────── Formatted report with source attribution badges
```

## Cross-Tool Correlation

Findings that no single tool produces alone:

| Correlation | What it detects | Tools involved |
|---|---|---|
| Dropped file in dlllist | Payload was not just written — it was loaded and executed | Cape + Volatility |
| WriteProcessMemory vs malfind | Shellcode decrypted/unpacked itself after injection | Cape + Volatility |
| Cape cmdline vs PEB cmdline | Process overwrote its own command line to hide | Cape + Volatility |
| Cape DNS vs shellcode APIs | DGA domains + networking APIs = confirmed C2 capability | Cape + Volatility artifacts |
| YARA family + Cape config | Family-specific config extraction guided by signature match | Triage + Cape |

## Security Model

Every analysis tool runs in a Podman container with:
- `--network=none` — no network access (except the AI container which needs the LLM API)
- `--read-only` — immutable filesystem
- `--cap-drop=ALL` — no Linux capabilities
- `--user 65534:65534` — unprivileged nobody user

The detonation network is air-gapped:
- `virbr-det` bridge has no route to `eth0` or `wg0`
- iptables DROP rules enforced before any ACCEPT
- INetSim simulates internet services for the guest VMs
- All admin access via WireGuard VPN

LLM prompt injection mitigations:
- All binary data wrapped in `UNTRUSTED_DATA` / `UNTRUSTED_CODE` delimiters
- LLM output is informational only — never modifies verdicts or triggers actions
- Tool argument validation via regex whitelist before reaching Ghidra
- Post-processing detection for prompt influence keywords
- Full audit logging of prompts and responses
- Triage/Cape/Volatility determine maliciousness — AI explains HOW, not WHETHER

## Infrastructure

```
OVH Bare Metal (RISE-2)
├── Ubuntu 24.04 (hardened — CIS baseline via konstruktoid)
├── KVM/QEMU with DSDT-patched firmware (anti-VM evasion)
├── CAPEv2 dynamic analysis sandbox
├── Windows 11 guest VMs with anti-evasion measures
├── INetSim network simulation
├── WireGuard VPN for admin access
├── Podman (rootless containers for all tool stages)
├── PostgreSQL (analysis database)
├── Flask dashboard (behind WireGuard)
└── 18 Ansible roles for fully automated deployment
```

## Quick Start

### Prerequisites

- Terraform >= 1.6, Packer >= 1.10, Ansible >= 2.14
- OVHcloud API credentials
- WireGuard keypair
- Anthropic API key (for AI reverse engineering)
- WSL2 required on Windows

### Deploy

```bash
# 1. Provision bare metal
cd ovh && terraform init && terraform apply

# 2. Build Windows guest images locally
cd packer && make image

# 3. Upload guest images
scp output-guest/windows11-guest.qcow2 sandbox:/home/ubuntu/
scp output/windows11-office.qcow2 sandbox:/home/ubuntu/

# 4. Configure everything
cd ansible
ansible-galaxy install -r requirements.yml
ansible-vault create vars/secrets.yml  # cape_api_key, anthropic_api_key, etc.
ansible-playbook -i inventory/hosts site.yml --ask-vault-pass

# 5. Submit a sample
ssh sandbox 'sudo -u cape sample-feeder'

# 6. View results
# Dashboard: http://10.200.0.1:5000 (via WireGuard)
# Cape UI:   http://10.200.0.1:8000 (via WireGuard)
# Reports:   /opt/pipeline/reports/<task_id>/report.pdf
```

## AI Reverse Engineering Agent

The interpret stage uses an LLM's tool_use API with 6 Ghidra query tools:

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile a function by name or address |
| `get_xrefs_to` | What calls this function? |
| `get_xrefs_from` | What does this function call? |
| `get_strings_at` | Defined strings near an address |
| `list_functions` | List/search functions with xref counts |
| `get_data_at` | Read raw bytes at an address |

The agent autonomously investigates the binary — listing functions, decompiling suspicious ones, tracing cross-references, reading data — and produces a structured analysis with malware family identification, capabilities, and MITRE ATT&CK technique mapping.

Model escalation: starts with a faster model, escalates to a more capable model after 5 tool calls for deeper investigation.

## Database Schema

Normalized PostgreSQL schema for cross-sample intelligence:
- **IOCs** with STIX 2.1 types — query "which samples share this C2 domain?"
- **MITRE ATT&CK** with tactic context — "show me all T1055 across families"
- **Sample relationships** — dropped/injected file lineage tracking
- **Network events** — structured DNS, HTTP, TCP from sandbox
- **MISP-style tags** — flexible taxonomy on samples, analyses, and IOCs
- **Correlation views** — shared infrastructure, technique frequency, sample lineage

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, provider rationale, deployment topology
- [docs/SECURITY_CONSTRAINTS.md](docs/SECURITY_CONSTRAINTS.md) — non-negotiable security rules with rationale
- [docs/STATUS.md](docs/STATUS.md) — build status and roadmap
- [docs/DECISIONS.md](docs/DECISIONS.md) — architecture decision records (ADR log)
- [docs/COST_ESTIMATE.md](docs/COST_ESTIMATE.md) — monthly cost breakdown

## Cost

~$92/month (OVH RISE-2 bare metal) + ~$0.50-5.00/day LLM API usage depending on sample volume.

## Author

Christopher Shaiman

## License

Apache 2.0. See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for component licenses.
