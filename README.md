# Automated Malware Analysis Platform

An end-to-end malware analysis platform that combines dynamic sandbox detonation, memory forensics, static binary analysis, and AI-powered reverse engineering to produce comprehensive, actionable intelligence reports.

Built on OVH bare metal with full infrastructure-as-code automation (Terraform + Ansible + Packer). Every analysis tool runs in an isolated container. An agentic AI reverse engineer autonomously investigates binaries using Ghidra, producing structured MITRE ATT&CK mappings, IOCs, and narrative analysis.

## What It Does

Submit a malware sample and get back a full analysis report with:

- **28+ YARA signature matches** from community rule sets
- **40+ behavioral signatures** from sandbox detonation (CAPEv2)
- **Memory forensics** — process injection detection, network connections, DLL analysis
- **Static analysis** — function decompilation, import tables, string extraction (Ghidra)
- **AI reverse engineering** — Claude autonomously investigates the binary with 6 Ghidra query tools, producing malware family identification, capability analysis, and MITRE ATT&CK technique mapping
- **Executive summary** — analyst-ready briefing with key findings, IOCs, and recommended defensive actions
- **Structured IOCs** — STIX 2.1 typed indicators (IPs, domains, hashes, URLs) with source attribution
- **PDF report** — formatted report with source badges showing which pipeline stage surfaced each finding

## Pipeline Architecture

```
Sample
  │
  ├─ Stage 1: Triage ──────────── YARA, ssdeep, FLOSS, entropy, PE analysis
  │  (containerized, --network=none)
  │
  ├─ Stage 2: Dynamic Analysis ── CAPEv2 sandbox, Windows 11 guest VMs
  │  (KVM/QEMU with anti-evasion)   Behavioral signatures, memory dumps, network capture
  │
  ├─ Stage 3: Memory Forensics ── Volatility 3 (psscan, malfind, netscan, dlllist...)
  │  (containerized, --network=none)   Process injection detection, 17K+ injected regions
  │
  ├─ Stage 4: Static Analysis ─── Ghidra headless (decompilation, imports, strings)
  │  (containerized, --network=none)   60+ functions, 100+ imports, pseudocode
  │
  ├─ Stage 4.5: AI Reverse Eng ── Claude agentic loop with 6 Ghidra tools
  │  (containerized, --network=host)   Decompile functions, trace xrefs, read data
  │  ↕ orchestrator brokers         Autonomous investigation, 8-10 tool calls
  │  (tool arg validation)           MITRE ATT&CK mapping, family identification
  │
  ├─ IOC Extraction ───────────── Structured indicators from all stages
  │                                 STIX 2.1 types, source attribution, context
  │
  ├─ Executive Summary ────────── LLM-generated analyst briefing
  │                                 Key findings, recommended actions, severity
  │
  ├─ Database Ingestion ────────── PostgreSQL (normalized IOCs, techniques, capabilities)
  │                                 Cross-sample correlation, evolution tracking
  │
  └─ PDF Report ───────────────── Formatted report with source attribution badges
```

## Security Model

Every analysis tool runs in a Podman container with:
- `--network=none` — no network access (except the AI interpret container which needs Claude API)
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
- Post-processing detection for suspicious keywords ("benign", "safe")
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
├── PostgreSQL (analysis database — shared instance, separate DB)
├── Flask dashboard (port 5000, behind WireGuard)
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

## Ansible Roles (18)

| # | Role | Purpose |
|---|------|---------|
| 1 | hardening | CIS-aligned OS hardening (konstruktoid) |
| 2 | kvm | KVM/QEMU/libvirt hypervisor |
| 3 | networking | Detonation bridge, iptables air-gap, INetSim rules |
| 4 | inetsim | Network simulation for guest VM traffic |
| 5 | wireguard | VPN for admin access |
| 6 | qemu-patched | DSDT-patched QEMU binary (anti-VM evasion) |
| 7 | mongodb | MongoDB 8.0 for CAPEv2 |
| 8 | cape | CAPEv2 installer, config, services |
| 9 | cape-guests | Windows 11 guest VMs, libvirt domains, snapshots |
| 10 | podman | Container runtime for analysis tools |
| 11 | triage | Containerized YARA/ssdeep/FLOSS analysis |
| 12 | volatility | Containerized Volatility 3 memory forensics |
| 13 | ghidra | Containerized Ghidra headless static analysis |
| 14 | interpret | Containerized Claude AI reverse engineering agent |
| 15 | postgres | Analysis database (PostgreSQL, shared instance) |
| 16 | pipeline | Pipeline orchestrator, PDF reports, DB ingestion |
| 17 | dashboard | Flask web UI for browsing analysis results |
| 18 | sample-feeder | MalwareBazaar CLI for sample ingestion |

## Database Schema

Normalized PostgreSQL schema for cross-sample intelligence:
- **IOCs** with STIX 2.1 types — query "which samples share this C2 domain?"
- **MITRE ATT&CK** with tactic context — "show me all T1055 across families"
- **Sample relationships** — dropped/injected file lineage tracking
- **Network events** — structured DNS, HTTP, TCP from sandbox
- **MISP-style tags** — flexible taxonomy on samples, analyses, and IOCs
- **Correlation views** — shared infrastructure, technique frequency, sample lineage

## AI Reverse Engineering Agent

The interpret stage uses Claude's tool_use API with 6 Ghidra query tools:

| Tool | Description |
|------|-------------|
| `decompile_function` | Decompile a function by name or address |
| `get_xrefs_to` | What calls this function? |
| `get_xrefs_from` | What does this function call? |
| `get_strings_at` | Defined strings near an address |
| `list_functions` | List/search functions with xref counts |
| `get_data_at` | Read raw bytes at an address |

The agent autonomously investigates the binary — listing functions, decompiling suspicious ones, tracing cross-references, reading data — and produces a structured analysis with malware family identification, capabilities, and MITRE ATT&CK technique mapping.

Model escalation: starts with Claude Sonnet, escalates to Opus after 5 tool calls for deeper analysis.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, provider rationale, deployment topology
- [docs/SECURITY_CONSTRAINTS.md](docs/SECURITY_CONSTRAINTS.md) — non-negotiable security rules with rationale
- [docs/STATUS.md](docs/STATUS.md) — build status and roadmap
- [docs/DECISIONS.md](docs/DECISIONS.md) — architecture decision records (ADR log)
- [docs/COST_ESTIMATE.md](docs/COST_ESTIMATE.md) — monthly cost breakdown

## Cost

~$92/month (OVH RISE-2 bare metal) + ~$0.50-5.00/day Claude API usage depending on sample volume.

## Author

Christopher Shaiman

## License

Apache 2.0. See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for component licenses.
