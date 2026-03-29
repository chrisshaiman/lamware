# CLAUDE.md — Malware Analysis Sandbox Infrastructure
# Instructions for Claude Code. Keep this file short — design lives in ARCHITECTURE.md.

## Who owns this
Christopher Shaiman — 15+ years defensive cybersecurity (SOC, IR, malware RE).
Comfortable with Python, PowerShell, learning Rust. Strong Terraform/IaC background.
All new code: Apache 2.0 license, author "Christopher Shaiman", AUTHORS file maintained.

---

## Read first
- **ARCHITECTURE.md** — system diagram, provider rationale, Packer/Ansible/Terraform split, decisions table
- **docs/STATUS.md** — what's built vs stubbed vs future scope
- **docs/DECISIONS.md** — ADR log of resolved decisions and their reasoning
- **docs/SECURITY_CONSTRAINTS.md** — non-negotiable security rules with rationale
- **docs/COST_ESTIMATE.md** — monthly cost breakdown; update when components change

---

## What we're building (summary)
A distributed malware analysis platform: dynamic analysis (CAPEv2 on bare metal KVM),
static analysis (Ghidra headless — not yet built), and memory forensics (Volatility 3 —
not yet built). AWS holds the data plane. Bare metal is the execution plane. See ARCHITECTURE.md.

---

## Build next (in order)
1. **`aws/modules/lambda/variables.tf` + `outputs.tf`** — missing from lambda module;
   update `main.tf` to remove `CAPE_HOST` env var (no longer needed with SQS approach)
2. **`aws/modules/sqs/`** — job queue module (DLQ, visibility timeout, KMS, IAM policy
   for bare metal polling agent)
3. **`aws/bootstrap/`** — one-time Terraform: S3 bucket + DynamoDB table for remote state;
   run manually before any other `terraform init`
4. **`aws/modules/api/`** — HTTP API Gateway in front of `sample_submitter` Lambda
5. **`aws/envs/prod/main.tf`** — composition layer wiring all modules, KMS key,
   Secrets Manager secrets (DSDT, Cape API key, DB password, WireGuard keys)
6. **`Makefile`** — `make image`, `make infra`, `make configure` entry points
7. **`packer/ubuntu-sandbox.pkr.hcl`** — hardened Ubuntu 24.04 base image
   - konstruktoid/hardened-images as foundation
   - Install KVM deps, clone CAPEv2, install Python deps
   - Do NOT run kvm-qemu.sh — hardware-specific, Ansible injects at runtime
8. **`ansible/`** — full role structure
   - `roles/hardening/` — wrap konstruktoid/ansible-role-hardening
   - `roles/kvm/` — install KVM, libvirt, configure hugepages
   - `roles/networking/` — detonation bridge, iptables air-gap rules
   - `roles/cape/` — run kvm-qemu.sh with DSDT vars, run cape2.sh, configure services
   - `roles/wireguard/` — WireGuard server config (admin access only)
   - `roles/sqs-agent/` — systemd service: polls SQS, submits jobs to Cape locally,
     syncs reports to S3
9. **`ovh/`** — OVH Terraform provider module (server, network, firewall, floating IP)

---

## Security constraints (non-negotiable)
Full rationale in **docs/SECURITY_CONSTRAINTS.md**. Never compromise these:

- Detonation VLAN has NO route to management plane or internet
- iptables DROP rules: `virbr-det → eth0` and `virbr-det → wg0`
- S3 buckets: no public access, HTTPS only, KMS encrypted
- RDS: private subnet only, no public endpoint
- Cape web UI/API: bind to `wg0` only, never `eth0`
- OVH robot firewall: whitelist admin CIDRs before OS boots
- Separate AWS account for this project
- All infrastructure in US jurisdiction (OVH US + AWS US region)

---

## Coding conventions
- Terraform: HCL2, modules pattern, no inline everything; tag all resources consistently
- Variables never have sensitive defaults — must be set explicitly in tfvars
- Ansible: roles only, no tasks directly in `site.yml`
- Python (Lambda handlers): type hints, docstrings, structured logging
- Comments explain *why*, not *what*

## When architectural decisions change
When a provider, pattern, or tool is changed or removed:
- Delete the old code/files — don't leave dead stubs or commented-out alternatives
- Grep for references (provider names, tool names, old patterns) across all files
  including comments, variable defaults, and docs
- Update `docs/DECISIONS.md` with a new ADR or amend the relevant existing one
- Update `docs/STATUS.md` to reflect the current state of the repo
- Update `docs/COST_ESTIMATE.md` if the change adds, removes, or resizes a billable component
- The goal: the repo should reflect current decisions only — no archaeological layers

---

## Open questions / decisions deferred
- OVH US location: Vint Hill VA vs Hillsboro OR (operator latency vs AWS region proximity)
- Windows guest Packer image strategy (separate repo or subdirectory)
- Agent orchestration: Lambda Step Functions vs separate service
- Whether Drakvuf is worth adding alongside Cape for agentless analysis
- SQS polling agent: standalone `roles/sqs-agent/` or absorb into `roles/s3-sync/`

See **docs/DECISIONS.md** for all resolved decisions.
