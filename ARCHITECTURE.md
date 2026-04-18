# ARCHITECTURE.md — Malware Analysis Sandbox

Reference document: system design, provider rationale, toolchain split, and decisions table.
For build status see docs/STATUS.md. For security rules see docs/SECURITY_CONSTRAINTS.md.

---

## System diagram

```
┌──────────────────────────────────┐     ┌──────────────────────────────────┐
│  Bare Metal Host (OVH US)        │     │  AWS us-east-1 (supporting)      │
│                                  │     │                                  │
│  KVM hypervisor                  │────▶│  S3 (samples + reports)          │
│  Cape Sandbox (CAPEv2)           │◀────│  SQS (job queue)                 │
│  FakeNet-NG / INetSim            │     │  RDS PostgreSQL (analysis DB)    │
│  Detonation VLAN (air-gapped)    │     │  Lambda (pipeline triggers)      │
│  WireGuard VPN (admin only)      │     │  API Gateway (agent API)         │
│  SQS polling agent (systemd)     │     │  VPC, KMS, Secrets Manager       │
└──────────────────────────────────┘     └──────────────────────────────────┘
```

**Job flow** — bare metal initiates all outbound connections, nothing inbound from AWS:
```
Client → API GW → sample_submitter Lambda → SQS
                                             ↑ polls
                              bare metal SQS agent
                                             ↓ submits locally
                                          Cape
                                             ↓ analysis complete
                              bare metal → S3 (report JSON)
                                             ↓ S3 event
                              report_processor Lambda → RDS (normalized IOCs)
```

**WireGuard** is admin-only: operator laptop → bare metal host for management and
Cape web UI access. Lambda does not call Cape directly and no EC2 WireGuard gateway
is needed. EC2 t3.nano WireGuard gateway is documented as a fallback if the SQS
approach hits a blocker (see docs/DECISIONS.md — ADR-003).

---

## Why AWS + bare metal (not one or the other)

The bare metal host is the **execution plane** — it runs malware. AWS is the
**data plane** — samples, reports, structured IOCs, secrets. Separating them means:

1. **Blast radius containment**: a sandbox escape gives an attacker a stripped-down
   Linux box with no data on it and no route to the AWS data plane.
2. **Disposability**: the bare metal host can be nuked and rebuilt without losing
   any analysis data. `make infra && make configure` and it reconnects to the same
   S3 buckets, SQS queue, and RDS instance.
3. **Resource efficiency**: bare metal CPU/RAM stays dedicated to running analysis VMs.
   AWS managed services handle storage durability (S3 11-nines), DB failover (RDS),
   and API surface — none of which should compete with the hypervisor for resources.

---

## Provider decisions

**Bare metal: OVHcloud US**
- OVH US locations: Vint Hill VA (us-east), Hillsboro OR (us-west)
- OVH support is slow but not a blocker for a technical operator
- Minimum viable specs for Cape: 4+ physical cores, 32 GB RAM, 500 GB SSD
- Recommended: ADVANCE-1 or equivalent (8c/16t, 32 GB RAM, NVMe)
- Terraform provider block is the only change if switching providers later

**AWS: us-east-1 (preferred) or us-west-2**
- Supporting infra only: S3, SQS, RDS, Lambda, API GW, VPC, KMS, Secrets Manager
- Separate AWS account required — do not mix with other personal or work infra

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
             - roles: hardening, kvm, networking, cape, wireguard, sqs-agent
             - pulls DSDT values from Secrets Manager at runtime
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
to each physical host and must be injected at configure time from Secrets Manager.

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
| `cape` | Run `kvm-qemu.sh` with DSDT vars, run `cape2.sh`, configure Cape services |
| `wireguard` | WireGuard server config — admin access only, not used by Lambda |
| `sqs-agent` | systemd service: polls SQS for jobs, submits to Cape locally, syncs reports to S3 |

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
| Network simulation | FakeNet-NG | Logs C2 callbacks without real outbound traffic |
| Remote state | S3 + DynamoDB | Standard AWS Terraform backend pattern |
| Secrets | AWS Secrets Manager | DSDT values, Cape API key, DB password |
| Sample storage | S3 with object lock | Integrity guarantee, GOVERNANCE mode 90-day retention |
| Lambda→Cape connectivity | SQS async job queue | Bare metal polls SQS; no EC2 WireGuard gateway; bare metal initiates all outbound |
| WireGuard scope | Admin access only | Operator laptop → host management; Lambda has no WireGuard path |
| Bare metal provider | OVHcloud US | Only cost-competitive bare metal provider with US locations |
| Hosting jurisdiction | US only (OVH US + AWS US region) | CFAA compliance, chain of custody, operator is US-based |
