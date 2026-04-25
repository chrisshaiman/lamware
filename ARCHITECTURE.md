# ARCHITECTURE.md — Malware Analysis Sandbox

Reference document: system design, provider rationale, toolchain split, and decisions table.
For build status see docs/STATUS.md. For security rules see docs/SECURITY_CONSTRAINTS.md.

---

## System diagram

```
┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│  Bare Metal Host (OVH US)        │     │  AWS us-east-1 (optional)        │
│                                  │     │                                  │
│  KVM hypervisor                  │────▶│  S3 (samples + reports)          │
│  Cape Sandbox (CAPEv2)           │     │    Object Lock for evidence      │
│  INetSim (network simulation)    │     │    integrity                     │
│  Detonation VLAN (air-gapped)    │     │                                  │
│  WireGuard VPN (admin only)      │     │                                  │
│  Sample feeder CLI               │     │                                  │
└──────────────────────────────────┘     └──────────────────────────────────┘
```

**Sample flow** — operator-driven via MalwareBazaar CLI tool:
```
Operator → sample-feeder CLI → MalwareBazaar API
                                    ↓ download + review
                              Cape (local API submission)
                                    ↓ analysis complete
                              Cape reports (local)
                                    ↓ optional
                              S3 (evidence archival)
```

**WireGuard** is admin-only: operator laptop → bare metal host for management and
Cape web UI access.

---

## Why AWS + bare metal (not one or the other)

The bare metal host is the **execution plane** — it runs malware and stores analysis
results locally. AWS is optional **evidence archival** — S3 with Object Lock for
tamper-proof sample preservation.

1. **Blast radius containment**: a sandbox escape gives an attacker a stripped-down
   Linux box with no route to cloud services or operator infrastructure.
2. **Disposability**: the bare metal host can be nuked and rebuilt from Ansible alone.
   Secrets are in Ansible Vault, config is in vars — `make configure` rebuilds everything.
3. **Simplicity**: no Lambda, no SQS, no RDS, no API Gateway, no VPC endpoints.
   The operator submits samples directly via the CLI tool on the host.

---

## Provider decisions

**Bare metal: OVHcloud US**
- OVH US locations: Vint Hill VA (us-east), Hillsboro OR (us-west)
- OVH support is slow but not a blocker for a technical operator
- Minimum viable specs for Cape: 4+ physical cores, 32 GB RAM, 500 GB SSD
- Recommended: ADVANCE-1 or equivalent (8c/16t, 32 GB RAM, NVMe)
- Terraform provider block is the only change if switching providers later

**AWS: us-east-1 (optional — evidence archival only)**
- S3 with Object Lock for tamper-proof sample/report preservation
- Separate AWS account if used — do not mix with other personal or work infra
- Most AWS services (Lambda, SQS, RDS, API GW, VPC, Secrets Manager) have been
  removed — see ADR-016

**Jurisdiction: United States only**
- Operator is US-based; malware analysis work requires US jurisdiction for CFAA
  compliance, chain of custody, and law enforcement cooperation if ever needed
- OVHcloud US (Vint Hill VA / Hillsboro OR) satisfies the bare metal requirement
- AWS region must be `us-east-1`, `us-east-2`, or `us-west-2`
- **For open-source users in other jurisdictions**: the architecture is fully portable.
  Swapping to a local AWS region + local bare metal provider is a Terraform provider
  block change only — no other code changes required. This should be documented
  prominently in README so international users can adapt without legal risk.

---

## Host deployment stack

```
Packer  →  builds hardened Ubuntu 24.04 base image
             - konstruktoid/hardened-images as Ansible provisioner foundation
             - KVM deps, Cape repo cloned, Python deps installed
             - NOT hardware-specific — no DSDT values baked in
             - outputs qcow2 / OVH snapshot

Terraform  →  provisions server from Packer snapshot
               - minimal cloud-init: SSH key injection only
               - outputs server IP for Ansible inventory

Ansible  →  configures the host (idempotent, safely re-runnable)
             - roles: hardening, kvm, networking, inetsim, wireguard, cape, sample-feeder
             - secrets from Ansible Vault (vars/secrets.yml)
             - provider-agnostic — only requires SSH access
```

Single entry point: `Makefile` — `make image`, `make infra`, `make configure`

**Why this split:**

| Tool | Responsibility | Why here |
|---|---|---|
| Packer | OS install, packages, repo clones | Slow, one-time work; produces a reusable snapshot |
| Terraform | Cloud resource provisioning | Declarative, stateful, provider-specific |
| Ansible | Runtime configuration, service setup | Idempotent, handles hardware-specific steps, SSH-only |

Hardware-specific steps (DSDT patching via `kvm-qemu.sh`) live in Ansible only and
are never baked into the Packer image. This is intentional — DSDT values are unique
to each physical host and are captured directly from host firmware at configure time.

**Key constraint:** Cape's `kvm-qemu.sh` patches ACPI DSDT tables with host-specific
values to defeat sandbox evasion by malware that inspects ACPI/SMBIOS firmware strings.
These values cannot be pre-determined and cannot be faked in a virtualised environment —
this is the primary reason bare metal is required.

---

## Ansible roles

> **Implementation status:** All roles are complete. See **docs/STATUS.md** for current build state.

| Role | Purpose |
|---|---|
| `hardening` | Wraps konstruktoid/ansible-role-hardening (CIS-aligned baseline) |
| `kvm` | Install KVM, QEMU, libvirt; configure hugepages |
| `networking` | Detonation bridge (`virbr-det`), iptables air-gap rules |
| `inetsim` | Network simulation for guest VM traffic (DNS, HTTP, HTTPS, SMTP, FTP) |
| `wireguard` | WireGuard server config — admin access only (operator laptop → host) |
| `cape` | Run `kvm-qemu.sh` with DSDT vars, run `cape2.sh`, configure Cape services |
| `sample-feeder` | MalwareBazaar CLI tool for interactive sample ingestion |

---

## Key technical decisions

| Decision | Choice | Reason |
|---|---|---|
| Hypervisor | KVM/QEMU | Cape requires it; DSDT patching for evasion bypass |
| Cape version | CAPEv2 (kevoreilly) | Active fork, Cuckoo is unmaintained |
| Host OS | Ubuntu 24.04 LTS | Cape's recommended and tested target |
| Config mgmt | Ansible | Idempotent, SSH-only, provider-agnostic |
| Image build | Packer + QEMU builder | Provider-agnostic qcow2/snapshot output |
| Base hardening | konstruktoid/hardened-images | Well-maintained, CIS-aligned, Ansible-based |
| Detonation network | Isolated KVM bridge (`virbr-det`) | Air-gapped, no NAT, iptables DROP to `eth0` |
| Network simulation | INetSim on host | Logs C2 callbacks without real outbound traffic |
| Secrets | Ansible Vault | Encrypted vars/secrets.yml, no cloud dependency |
| Sample storage | S3 with object lock (optional) | Integrity guarantee, GOVERNANCE mode 90-day retention |
| Sample ingestion | MalwareBazaar CLI | Operator-driven interactive submission via sample-feeder |
| WireGuard scope | Admin access only | Operator laptop → host management |
| Bare metal provider | OVHcloud US | Only cost-competitive bare metal provider with US locations |
| Hosting jurisdiction | US only (OVH US + AWS US region) | CFAA compliance, chain of custody, operator is US-based |
