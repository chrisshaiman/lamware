# DECISIONS.md — Architecture Decision Records

ADR log for non-obvious decisions. Format: Status / Context / Decision / Consequences.
Add new ADRs here rather than editing old ones — superseded decisions stay in the log.

---

## ADR-001: Bare metal provider — OVHcloud US

**Status:** Decided

**Context:**
Cape Sandbox requires KVM with ACPI DSDT table patching to defeat sandbox evasion.
This requires physical hardware — virtualised KVM (nested virt) defeats the purpose
because the ACPI tables still reflect the underlying hypervisor. The operator is
US-based and requires US jurisdiction for all infrastructure. Hetzner was evaluated
but has no US bare metal locations (dedicated servers are EU-only, DE/FI).

**Decision:**
Use OVHcloud US (Vint Hill VA or Hillsboro OR) for bare metal.
If OVH proves unworkable (support issues, hardware availability), Vultr Bare Metal
and Latitude.sh are documented alternatives with US locations and Terraform providers.

**Consequences:**
- OVH support is slow — not a concern for a technical operator
- OVH Terraform provider module needs to be built (`ovh/` directory)
- Terraform provider block is the only change if switching to an alternative provider

---

## ADR-002: All infrastructure hosted in the United States

**Status:** Decided

**Context:**
The operator is US-based. The project handles malware samples, which creates potential
legal exposure under the CFAA. EU-hosted infrastructure introduces GDPR considerations
for data processed on that infrastructure, and cross-border law enforcement cooperation
is significantly more complex than within-US.

**Decision:**
All infrastructure — OVH bare metal and AWS — must be in US jurisdiction. AWS region
restricted to `us-east-1`, `us-east-2`, or `us-west-2`. OVH must be a US location.

**Consequences:**
- OVHcloud US selected as bare metal provider (only cost-competitive option with US locations)
- AWS region defaulted to `us-east-1`
- International open-source users can swap providers/regions without code changes —
  document this prominently in README
- Could add AWS Organizations SCP to deny non-US regions as a guardrail

---

## ADR-003: Lambda→Cape connectivity via SQS (not direct WireGuard call)

**Status:** Decided

**Context:**
Lambda functions (`sample_submitter`) need to submit analysis jobs to Cape running on
the bare metal host. The initial design had Lambda calling Cape's REST API directly
using a `CAPE_HOST` environment variable pointing to the Cape server's WireGuard IP.
Problem: Lambda runs in an AWS VPC; Cape's API is bound to the WireGuard interface
only (`wg0`). These can't communicate without an intermediary.

Two options were evaluated:
1. EC2 t3.nano WireGuard gateway in the VPC — Lambda routes Cape API calls through it
2. SQS async job queue — bare metal polls SQS; Lambda never calls Cape directly

**Decision:**
Use SQS async job queue. The bare metal host runs a systemd service (`sqs-agent`)
that polls SQS for analysis jobs and submits them to Cape locally. Cape results are
written to S3 as before. Lambda never initiates connections to the bare metal host.

**Consequences:**
- No EC2 WireGuard gateway needed — reduces cost and management overhead
- Bare metal host initiates all outbound connections (better security posture)
- SQS provides natural buffering if Cape is busy or the host is being rebuilt
- `sample_submitter` Lambda returns a job ID immediately without waiting for Cape
- Requires a new `aws/modules/sqs/` Terraform module
- Requires a new `roles/sqs-agent/` Ansible role (systemd polling service)
- `aws/modules/lambda/main.tf` needs `CAPE_HOST` env var removed
- **Fallback:** EC2 t3.nano WireGuard gateway remains documented as a fallback if
  the SQS approach hits an unexpected blocker

---

## ADR-004: WireGuard scope limited to admin access only

**Status:** Decided

**Context:**
WireGuard was initially scoped as the connectivity layer between AWS Lambda and the
Cape API on the bare metal host, as well as admin access. With ADR-003 (SQS approach),
Lambda no longer needs a path to Cape. WireGuard's role is now narrower.

**Decision:**
WireGuard serves admin access only: operator laptop → bare metal host. This provides
encrypted management access and access to Cape's web UI (bound to `wg0`). Lambda
has no WireGuard path and does not require it.

**Consequences:**
- `roles/wireguard/` Ansible role is simpler — single peer (operator laptop)
- No WireGuard client config needed on Lambda or in the AWS VPC
- Cape web UI remains accessible only over WireGuard, as required by security constraints

---

## ADR-006: No NAT Gateway — VPC endpoints only

**Status:** Decided

**Context:**
The initial VPC design included a NAT Gateway (~$33/month) to give Lambda outbound
internet access for reaching SQS and Secrets Manager. Evaluated whether anything
in the current or planned architecture actually requires internet egress from the VPC.

Current Lambda needs:
- S3: Gateway endpoint (free, already implemented)
- RDS: private subnet routing, no internet path needed
- SQS: Interface endpoint available
- Secrets Manager: Interface endpoint available

Future planned components (Ghidra, Volatility agents) follow the same pattern —
S3 via Gateway endpoint, no internet needed. External enrichment API calls are not
in scope; if ever added, the bare metal host (which already has internet access)
is the better place for that work.

**Decision:**
Remove NAT Gateway, EIP, public subnets, and public route table entirely.
Add Interface Endpoints for SQS and Secrets Manager (~$7/month each).
Move S3 Gateway endpoint from `lambda/main.tf` into `vpc/main.tf` where all
endpoint resources are co-located. Lambda SG egress tightened to VPC CIDR only.

Net saving: ~$19/month ($33 NAT removed, $14 endpoints added).

**Consequences:**
- Lambda has no internet egress path — intentional, reduces blast radius
- If internet access is ever needed, add NAT Gateway back to public subnets
  (public subnets are documented as intentionally omitted, not removed from design)
- `lambda/variables.tf` no longer needs `private_route_table_ids`
- `vpc/outputs.tf` no longer exports `public_subnet_ids`
- AWS monthly cost reduced from ~$62 to ~$43

---

## ADR-005: Packer/Ansible/Terraform toolchain split

**Status:** Decided

**Context:**
The bare metal host requires: a hardened OS baseline, KVM/QEMU installed, Cape
dependencies installed, hardware-specific DSDT patching, and runtime service
configuration. These have different characteristics — some are slow and one-time,
some are hardware-specific, some need to be re-runnable.

**Decision:**
- **Packer**: OS install, package installation, repo clones. Produces a reusable
  snapshot. Run once per OS version or major dependency change.
- **Terraform**: Cloud resource provisioning (server, network, firewall, floating IP).
  Minimal cloud-init — SSH key injection only.
- **Ansible**: All runtime configuration. Idempotent, SSH-only, pulls secrets from
  Secrets Manager at runtime. Handles DSDT patching via `kvm-qemu.sh`.

Hardware-specific steps (DSDT patching) are Ansible-only. Never baked into Packer image.

**Consequences:**
- DSDT values must be in Secrets Manager before `make configure` runs
- Packer image is provider-agnostic (qcow2 output, convertible to OVH snapshot)
- Host rebuilds skip the slow Packer step if the snapshot is current
- `make configure` can be re-run safely after any config change
