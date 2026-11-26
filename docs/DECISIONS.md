# DECISIONS.md — Architecture Decision Records

ADR log for non-obvious decisions. Format: Status / Context / Decision / Consequences.
Add new ADRs here rather than editing old ones — superseded decisions stay in the log.


## Index

Grouped by what the decision governs, because a reader arriving with a question has a
subject in mind rather than a number. **Status is the column that matters:** four of
these describe an AWS data plane that no longer exists.

### Infrastructure and hosting

| ADR | Decision | Status |
|---|---|---|
| [001](#adr-001-bare-metal-provider--ovhcloud-us) | Bare metal provider — OVHcloud US | Live |
| [002](#adr-002-all-infrastructure-hosted-in-the-united-states) | All infrastructure hosted in the United States | Live |
| [005](#adr-005-packeransibleterraform-toolchain-split) | Packer / Ansible / Terraform toolchain split | Live |
| [016](#adr-016-migrate-secrets-to-ansible-vault-remove-aws-data-plane) | Ansible Vault for secrets; AWS data plane removed | Live — supersedes 003, 006, 008 |

### Network and containment

| ADR | Decision | Status |
|---|---|---|
| [004](#adr-004-wireguard-scope-limited-to-admin-access-only) | WireGuard scope limited to admin access | Live (revised 2026-04-18) |
| [011](#adr-011-guest-network-simulation--inetsim-on-host) | Guest network simulation — INetSim on host | Live |
| [012](#adr-012-guest-vm-anti-evasion-hardening) | Guest VM anti-evasion hardening | Live |
| [020](#adr-020-one-firewall-mechanism--iptables-persistent-not-ufw) | One firewall mechanism — iptables-persistent, not UFW | Live (amended 2026-10-05, 2026-10-18) |
| [021](#adr-021-hostile-files-are-interpreted-only-inside-a-sandbox-agent-tools-are-brokered-by-the-orchestrator-and-executed-in-one) | Hostile files are interpreted only in a sandbox; agent tools are brokered and sandboxed | Live |
| [023](#adr-023-image-builds-are-hermetic--an-unprivileged-fetch-user-downloads-every-build-input-pinned-and-checksummed-podman-build-runs-with-no-network) | Image builds are hermetic: an unprivileged fetch user downloads inputs, `podman build` has no network | Accepted |
| [025](#adr-025-code-the-pipeline-runs-is-root-owned-the-pipeline-user-owns-data-only) | Code the pipeline runs is root-owned; the pipeline user owns data only | Accepted |

### Detonation environment

| ADR | Decision | Status |
|---|---|---|
| [009](#adr-009-windows-guest-os--windows-11-enterprise-evaluation-iso) | Windows guest OS — Windows 11 Enterprise eval | Live (revised 2026-04-04) |
| [010](#adr-010-cape-agent-mode--cape-agentpy-with-capemon) | Cape agent mode — `cape-agent.py` with capemon | Live (revised 2026-04-15) |
| [013](#adr-013-guest-snapshot-strategy--clean--office-profiles) | Guest snapshot strategy — clean + office profiles | Live |

### Analysis, data and the LLM

| ADR | Decision | Status |
|---|---|---|
| [015](#adr-015-malwarebazaar-sample-feeder-interactive-cli) | MalwareBazaar sample feeder (interactive CLI) | Live |
| [017](#adr-017-investigation-agent-architecture) | Investigation agent architecture | Live — the capability boundaries |
| [018](#adr-018-adopt-alembic-for-malware_analysis-schema-migrations) | Alembic for schema migrations | Live |
| [019](#adr-019-family-attribution-is-not-a-capability-metric-for-the-re-stage) | Family attribution is not a capability metric | Live — enforced in the scorecard |
| [026](#adr-026-cvp-frontier-models-are-reached-through-claude-platform-on-aws-with-sigv4-from-iam-roles-anywhere-no-static-key) | CVP frontier models through Claude Platform on AWS, SigV4 from IAM Roles Anywhere; no static key | Superseded by ADR-034 (2026-11-20); accepted 2026-11-18 |
| [027](#adr-027-the-cape-account-controls-its-two-guests-through-libvirt-not-libvirt-itself) | The cape account controls its two guests through libvirt, not libvirt itself | Accepted — implemented 2026-11-14 |
| [028](#adr-028-capes-rooter-is-not-run-lamwares-own-firewall-is-the-guests-network-boundary) | CAPE's rooter is not run; lamware's own firewall is the guests' network boundary | Accepted — implemented 2026-11-15 |
| [029](#adr-029-cape-captures-packets-through-a-root-helper-on-the-detonation-bridge-only) | CAPE captures packets through a root helper, on the detonation bridge only | Accepted — implemented 2026-11-15 |
| [030](#adr-030-every-litellm-caller-has-its-own-scoped-key-the-master-key-stays-in-litellms-files) | Every LiteLLM caller has its own scoped key; the master key stays in LiteLLM's files | Accepted — implemented 2026-11-16 |
| [031](#adr-031-the-lamware-group-is-narrowed-in-measured-phases-starting-with-cape) | The `lamware` group is narrowed in measured phases, starting with cape | Accepted — phase 0 in progress |
| [032](#adr-032-root-containers-use-lamware-container-podmans-apparmor-profile-plus-upstreams-stacked-peer-fix) | Root containers use lamware-container: podman's AppArmor profile plus upstream's stacked-peer fix | Accepted — temporary until noble's podman ships container-libs #919 |
| [033](#adr-033-litellm-reaches-the-claude-api-through-workload-identity-federation-no-api-key-on-the-host) | LiteLLM reaches the Claude API through Workload Identity Federation; no API key on the host | Proposed |
| [034](#adr-034-the-old-loopback-forwarder-is-retired-its-eval-arms-use-the-workload-identity-federation-eval-route) | The old loopback forwarder is retired; its eval arms use the Workload Identity Federation eval route | Proposed |
| [035](#adr-035-the-nightly-aide-run-absorbs-only-detonation-reboot-and-container-runtime-differences) | The nightly AIDE run absorbs only detonation, reboot and container-runtime differences | Proposed |
| [036](#adr-036-a-run-chooses-its-llm-backend-by-explicit-profile-automated-runs-stay-local-by-default) | A run chooses its LLM backend by explicit profile; automated runs stay local by default | Proposed |
| [037](#adr-037-litellms-per-call-cost-is-the-price-of-record-the-rate-tables-become-a-fallback) | LiteLLM's per-call cost is the price of record; the rate tables become a fallback | Proposed |
| [038](#adr-038-the-operator-chooses-the-models-the-suite-enables-providers-and-records-where-the-data-went) | The operator chooses the models; the suite enables providers and records where the data went | Proposed |

### Historical — describe infrastructure that is no longer deployed

Kept because the log records what was decided and why, not only what survives. None of
these describe the running system.

| ADR | Decision | Status |
|---|---|---|
| [003](#adr-003-lambdacape-connectivity-via-sqs-not-direct-wireguard-call) | Lambda→Cape connectivity via SQS | **Superseded by 016** — SQS agent removed; ingestion is `sample-feeder` |
| [006](#adr-006-no-nat-gateway--vpc-endpoints-only) | No NAT Gateway — VPC endpoints only | **Superseded by 016** — the AWS VPC is gone |
| [008](#adr-008-two-phase-sample-submission-to-eliminate-sqss3-race) | Two-phase sample submission (SQS/S3 race) | **Superseded by 016** — the race cannot occur without the pipeline |
| [007](#adr-007-s3-object-lock-mode--governance-not-compliance) | S3 Object Lock — GOVERNANCE, not COMPLIANCE | **Deferred, not superseded** — 016 keeps S3 archival as a standalone future option; scaffolding recoverable from `6ce668c` |

There is no ADR-014; the number was never used.

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

**Status:** Superseded by ADR-016 (2026-04-24) — the SQS agent was removed and sample
ingestion moved to the `sample-feeder` CLI. Retained for the record; does not describe
the running system.

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

**Status:** Revised 2026-04-18

**Context:**
WireGuard was initially scoped as the connectivity layer between AWS Lambda and the
Cape API on the bare metal host, as well as admin access. With ADR-003 (SQS approach),
Lambda no longer needs a path to Cape. WireGuard's role is now narrower.

**Decision:**
WireGuard serves admin access only: operator laptop → bare metal host. This provides
encrypted management access and access to Cape's web UI (bound to `wg0`). Lambda
has no WireGuard path and does not require it.

**Revision (2026-04-18) — key management:**
WireGuard keys are no longer stored in AWS Secrets Manager. The server keypair is
generated on the host by the Ansible wireguard role (private key never leaves the server).
The operator's laptop public key is set in `ansible/vars/main.yml` → `wireguard_peer_pubkey`.
After Ansible runs, the host's public key is printed for the operator to configure their
laptop. This eliminates the `wireguard-keys` Secrets Manager secret and the associated
Terraform resources. Rationale: storing VPN private keys in the same AWS account the VPN
protects is a circular trust dependency.

**Consequences:**
- `roles/wireguard/` Ansible role is simpler — single peer (operator laptop)
- No WireGuard client config needed on Lambda or in the AWS VPC
- Cape web UI remains accessible only over WireGuard, as required by security constraints
- Server private key never transits the network or resides in a cloud service
- One fewer Secrets Manager secret ($0.40/month saved)

---

## ADR-006: No NAT Gateway — VPC endpoints only

**Status:** Superseded by ADR-016 (2026-04-24) — the AWS VPC no longer exists, so there
is no NAT/endpoint decision left to make. Retained for the record.

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

## ADR-007: S3 Object Lock mode — GOVERNANCE, not COMPLIANCE

**Status:** Deferred, not superseded — ADR-016 keeps S3 with Object Lock as a standalone
option for evidence archival, deployable with no other AWS infrastructure. Nothing is
deployed today; the Object Lock and lifecycle scaffolding is recoverable from git at
`6ce668c` (`aws/modules/s3/`). The GOVERNANCE-vs-COMPLIANCE reasoning below stands if
it is ever taken up.

**Context:**
S3 Object Lock has two modes. GOVERNANCE prevents deletion by normal IAM principals
but allows override by anyone with `s3:BypassGovernanceRetention`. COMPLIANCE is
absolute — no principal (including root and AWS support) can delete an object before
the retention period expires, and the mode itself cannot be downgraded once set.

The samples bucket uses Object Lock to guarantee sample integrity and reproducibility —
ensuring the exact binary that was detonated can be retrieved for re-analysis.

**Decision:**
Use GOVERNANCE mode. The primary threat model is accidental deletion and unprivileged
tampering, not a determined insider or court order. COMPLIANCE introduces an escape
hatch problem in the other direction: if a sample needs to be purged (legal takedown
request, inadvertent ingestion of CSAM-adjacent content, operator policy change),
COMPLIANCE mode makes that impossible without deleting the AWS account.

This tool does not currently operate under a regulatory chain-of-custody requirement.
If that changes — e.g., formal DFIR engagements where evidence admissibility matters —
revisit COMPLIANCE mode for a dedicated evidence bucket at that time.

**To change:**
In `aws/modules/s3/main.tf`, change `mode = "GOVERNANCE"` to `mode = "COMPLIANCE"` in
`aws_s3_bucket_object_lock_configuration.samples`. This is irreversible per object —
existing locked objects cannot be downgraded. Create a new bucket if you need both modes.

**Consequences:**
- Operator retains the ability to purge samples if legally required
- Root account / break-glass role can bypass object lock with `s3:BypassGovernanceRetention`
- Does not meet evidentiary standards for court admissibility or strict compliance frameworks
- Upgrade path is simple (one line change) if requirements change

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
- **Ansible**: All runtime configuration. Idempotent, SSH-only, secrets from Ansible
  Vault. Handles DSDT patching via `kvm-qemu.sh`.

Hardware-specific steps (DSDT patching) are Ansible-only. Never baked into Packer image.

**Consequences:**
- DSDT values are captured from host firmware at configure time
- Packer image is provider-agnostic (qcow2 output, convertible to OVH snapshot)
- Host rebuilds skip the slow Packer step if the snapshot is current
- `make configure` can be re-run safely after any config change

---

## ADR-008: Two-phase sample submission to eliminate SQS/S3 race

**Status:** Superseded by ADR-016 (2026-04-24) — the SQS/S3 submission pipeline this
race applied to was decommissioned. Retained for the record.

**Context:**
The original `sample_submitter` Lambda (Phase 1 only) issued a pre-signed S3 PUT URL
and immediately enqueued an SQS job. The bare metal sqs-agent could dequeue and attempt
to process the job before the client finished uploading the sample, resulting in a
"object not found" error and unnecessary retry churn.

**Decision:**
Split submission into two phases, both handled by the same Lambda function:

- **Phase 1 (API Gateway POST /submit):** Validate request, generate `task_id`, issue
  pre-signed S3 PUT URL with job metadata (`task_id`, `sha256`, `tags`) embedded in the
  AWS signature via S3 object metadata. The client MUST include `x-amz-meta-*` headers
  matching the signature or S3 rejects the PUT with 403. Return `{task_id, upload_url}`
  immediately. No SQS message is sent here.

- **Phase 2 (S3 ObjectCreated on `samples/` prefix):** Triggered only after S3 confirms
  the object exists. Reads job metadata from the object via `head_object`, then enqueues
  the SQS job. The sqs-agent cannot receive a job for a sample that has not been fully
  uploaded.

Metadata is embedded in the presigned URL signature rather than written to a separate
storage location (e.g. DynamoDB, or a temp object in S3) to avoid cleanup complexity.
The samples bucket has GOVERNANCE Object Lock (90-day) on all objects, so any temp file
written there cannot be deleted by Lambda without a bypass permission — ruling out the
temp-file pattern.

**Consequences:**
- Race condition between upload and job dispatch is eliminated by design
- No new Lambda functions or storage resources required — same zip artifact
- Client API contract is unchanged (`POST /submit` → presigned URL → poll)
- Client must send the `x-amz-meta-*` headers specified in the presigned URL or the
  PUT will be rejected with 403 — this is a documented API requirement
- Lambda must be granted `s3:InvokeFunction` permission from the samples bucket

---

## ADR-009: Windows guest OS — Windows 11 Enterprise evaluation ISO

**Status:** Revised 2026-04-04 (supersedes original Windows 10 decision)

**Context:**
Cape requires a Windows guest VM for dynamic malware analysis. Choices are Windows 10,
Windows 11, or both. Licensing options are Microsoft evaluation ISOs (90-day, free) or
a paid MSDN/Visual Studio subscription.

**Decision:**
Use Windows 11 Enterprise evaluation ISO. Windows 10 was the original choice but
Microsoft reached end-of-life on October 14, 2025 and removed evaluation ISOs from
the eval center — they are no longer available.

Rationale for Windows 11: the only viable evaluation ISO available from Microsoft;
malware authors are increasingly targeting Win11-era environments; Windows 10 EOL means
it is no longer representative of production endpoints. The added complexity of TPM
emulation (swtpm) is worth accepting to stay current.

Rationale for evaluation ISO: Microsoft distributes these specifically for lab use;
the 90-day rebuild cycle is manageable with an automated Packer pipeline; activation
state is not a significant variable for the malware classes this lab targets.
Enterprise SKU (not Home or Pro) is required — Group Policy hooks used by some Cape
analysis modules are Enterprise-only.

**Consequences:**
- New Packer templates needed for Windows 11 (autounattend.xml, pkr.hcl, swtpm for TPM 2.0)
- Existing Win10 templates are complete and retained — on hold pending ISO sourcing via
  MSDN/VS subscription or community contacts; will run both profiles once Win10 ISO available
- Guest image must be rebuilt from a fresh evaluation ISO every 90 days
- Packer guest image pipeline handles rebuilds; rotation process should be documented
  in the runbook before the first guest is deployed

---

## ADR-010: Cape agent mode — cape-agent.py with capemon

**Status:** Revised 2026-04-15 (supersedes original cape-agent-only decision)

**Context:**
Cape supports two complementary in-guest components: `cape-agent.py` (a Python HTTP
server that receives commands from the Cape host — upload sample, execute, collect
results) and capemon (DLLs injected into analyzed processes at runtime for deep API
call hooking, memory dumping, and crypto key extraction). The original decision deferred
capemon until evasion was observed in practice.

During local testing of the Win11 guest image, two issues were discovered:
1. Python 3.14 (x64) was installed, but cape-agent.py requires Python x86 (32-bit)
   because capemon injects 32-bit DLLs into target processes
2. The `cgi` stdlib module (imported by agent.py) was removed in Python 3.13

Both issues are resolved by installing Python 3.12.x x86 — which also enables capemon
with no additional guest-side work. The capemon DLLs are part of the Cape host
installation and are pushed to the guest at analysis time by the Cape machinery.

**Decision:**
Use `cape-agent.py` with capemon enabled. Install Python 3.12.x x86 (32-bit) in the
guest image. Pin to 3.12.x to retain the `cgi` stdlib module required by agent.py
(removed in 3.13). The host-side Cape installation (via `cape2.sh`) already includes
the capemon DLLs and analyzer package — no host changes required.

**Consequences:**
- Python 3.12.x x86 installed in guest image (`install-python.ps1` uses x86 installer)
- Python version must stay on 3.12.x until upstream agent.py removes the `cgi` dependency
- capemon provides full Windows API call tracing, memory dump triggers, crypto key
  extraction, and anti-evasion counterfeit returns — significantly richer analysis output
- Agent process is still visible in the guest process list (inherent to cape-agent.py)
- Firewall rule for port 8000 is created by `install-cape-agent.ps1` provisioner
  (autounattend.xml rule was found missing after Windows setup — belt-and-suspenders)

---

## ADR-011: Guest network simulation — INetSim on host

**Status:** Decided

**Context:**
Cape guest VMs need a network environment for analysis. Options are full internet access,
simulated internet (INetSim/FakeNet-NG), or fully isolated. Full internet access exposes
the host IP to live C2 infrastructure, risks abuse complaints, and may trigger destructive
second-stage payloads. Fully isolated misses all network-based behavior.

**Decision:**
Run INetSim on the bare metal host, bound to the virbr-det bridge gateway IP. Cape's
`routing.conf` is configured with `internet_access = no` and `inetsim = yes`. All guest
DNS queries resolve to the INetSim host; all TCP connections are answered by INetSim
service simulators (HTTP, HTTPS, SMTP, FTP, DNS).

FakeNet-NG was considered but runs inside the guest (Windows-only), which is
architecturally less clean — it cannot be managed by Ansible alongside the host
network configuration.

**Consequences:**
- Guest traffic never reaches the real internet — no abuse risk, no C2 contact
- Malware that performs a live connectivity check before detonating may go dormant;
  `report_processor.py` will detect this pattern and alert the operator (see planned
  features in ROADMAP.md)
- INetSim serves generic responses — second-stage payload downloads receive dummy content;
  operator can choose selective passthrough for re-analysis if warranted
- Requires new `ansible/roles/inetsim/` role and updates to `roles/networking/` and
  `roles/cape/` — tracked in ROADMAP.md next build section

---

## ADR-012: Guest VM anti-evasion hardening

**Status:** Decided

**Context:**
Malware commonly checks for sandbox artifacts before executing its payload. Without
anti-evasion measures, detection-aware samples will go dormant and produce empty reports.
The ACPI/DSDT table patching (already implemented in `roles/cape/`) is the highest-value
single control. Additional measures vary in effort and payoff.

**Decision:**
Implement the following in the Windows 10 guest Packer image and libvirt XML template:

*Packer image (guest build-time):*
- Screen resolution: 1920x1080 (800x600 is a classic sandbox tell)
- CPU cores: 2 (single-core = sandbox signal)
- RAM: 4096 MB
- Disk: 60 GB presented to guest
- Hostname: randomized realistic pattern (`DESKTOP-XXXXXXX` style)
- Username: common first-name pattern, not `analyst`, `sandbox`, `malware`, etc.
- Decoy files: plausible Documents/Downloads/Desktop content (fake PDFs, Word doc,
  browser history) to avoid an obviously empty user profile

*libvirt XML template (roles/cape/):*
- Mask hypervisor CPUID bit: `<feature policy='disable' name='hypervisor'/>` with
  `host-passthrough` CPU mode — prevents `CPUID EAX=1 ECX bit31` detection

*Deferred:*
- User activity simulation (mouse movement, file opens) — high effort, marginal payoff
  for most samples; tracked in ROADMAP.md future scope
- Network adapter MAC/OUI randomization — QEMU default OUI `52:54:00` is known; low
  priority, revisit if OUI-based detection is observed in practice
- RDTSC timing attack mitigation — hard to fully defeat without hardware tricks; DSDT
  work provides partial coverage

**Consequences:**
- Hostname and username must be parameterized in the Packer template (variables, not
  hardcoded) so they can be varied across image rebuilds
- CPUID mask requires `host-passthrough` CPU mode in libvirt — already used for ACPI
  compatibility, no new constraint
- Decoy file content should be benign and non-identifying (no real personal data)

---

## ADR-013: Guest snapshot strategy — clean + office profiles

**Status:** Decided

**Context:**
Cape reverts the guest VM to a clean snapshot before each analysis run. A single clean
snapshot covers most malware but document-based samples (macro Word/Excel, PDF exploits)
won't detonate without the target application installed, producing empty reports for a
large and common sample class.

**Decision:**
Maintain two guest snapshots: `clean` (bare OS + cape-agent) and `office` (clean +
LibreOffice). Cape routes samples to the `office` profile based on file extension tags
(`.doc`, `.docm`, `.xls`, `.xlsm`, `.odt`, etc.) via the existing tag field in the SQS
job schema and `kvm.conf` machine profile mapping.

Use LibreOffice rather than Microsoft Office: free, no account or license required, good
enough for most macro samples. If VBA compatibility issues are observed in practice,
switching to Microsoft Office evaluation is an option — that decision is deferred until
there is evidence LibreOffice is the limiting factor.

**Consequences:**
- Two snapshots to maintain and rotate on the 90-day evaluation ISO rebuild cycle
- `packer/windows10-guest.pkr.hcl` builds the base image; LibreOffice installation is
  a second provisioner pass or a separate Packer build that extends the base
- `roles/cape/` `kvm.conf` template needs machine stanzas for both `clean` and `office`
  profiles with the correct snapshot names
- Tag-based routing is already supported by the SQS job schema — no infrastructure changes
- Additional profiles (browser, PDF reader) deferred until sample volume justifies them

---

## ADR-015: MalwareBazaar sample feeder (interactive CLI)

**Status:** Accepted 2026-04-17

**Context:** The sandbox needs real malware samples for testing, demonstration,
and ongoing analysis. MalwareBazaar (abuse.ch) provides a free, public API with
community-tagged samples — no membership or vetting required.

**Decision:** Deploy an interactive CLI tool on the bare metal host that queries
MalwareBazaar and submits samples to Cape's local API. The operator reviews
matches and explicitly confirms before any sample is downloaded or submitted.
Human in the loop for initial deployment. The tool is designed to support a
non-interactive mode (via `--yes` flag) for future scheduled ingestion once
the operator is comfortable with the pipeline.

**Rationale:**
- Human review in interactive mode prevents blindly ingesting samples that could
  crash Cape, exhaust analysis slots, or behave unexpectedly during initial use
- Running on the sandbox host avoids downloading malware to developer machines
- Direct Cape API submission is simpler than routing through the AWS pipeline
- State file tracks submitted hashes to surface duplicates in the preview
- CLI with --dry-run allows safe exploration of available samples
- MalwareBazaar is free, open, community-curated — ideal for research use
- Automation mode (future) can be wired to a systemd timer using the same tool
  and config — no separate daemon or pipeline needed

**Deferred:** Automated scheduled ingestion via systemd timer. The tool supports
`--auto` and `--no-confirm` flags for this use case but the timer unit is not
deployed until the operator has validated the interactive workflow end-to-end.

**Consequences:**
- Operator must SSH into the host (via WireGuard) to run the tool in interactive mode
- Cape API key stored in config file (mode 0600, deployed by Ansible)
- Samples exist on disk momentarily in /tmp — cleaned up after submission
- Automation path is available by adding a systemd timer unit pointing to the same
  script with `--auto --tag <filter>` args — no code changes required

---

## ADR-016: Migrate secrets to Ansible Vault, remove AWS data plane

**Status:** Accepted 2026-04-24

**Context:**
The original architecture used AWS as a full data plane: Secrets Manager for secrets,
SQS for job queuing, Lambda + API Gateway for sample submission, RDS for IOC storage,
S3 for samples and reports. In practice, the only AWS service actively used was Secrets
Manager — and it caused repeated deployment failures due to SSO session expiry during
long Ansible runs. The SQS agent never worked (Cape API unreachable without WireGuard),
Lambda/API Gateway were never used (sample ingestion goes through the sample-feeder CLI),
and RDS was never populated.

Monthly AWS cost was ~$43 for infrastructure that provided no active value. The
MalwareBazaar sample-feeder CLI (ADR-015) replaced the Lambda/SQS submission pipeline,
and Cape stores analysis results locally.

**Decision:**
- Replace AWS Secrets Manager with **Ansible Vault** (`ansible/vars/secrets.yml`,
  gitignored, encrypted with `ansible-vault encrypt`)
- Remove the `sqs-agent` role from `site.yml` (dead without SQS)
- AWS Terraform code (`aws/`) is retained in the repo for reference but is not
  deployed or maintained. It can be deleted in a future cleanup.
- S3 with Object Lock remains an option for evidence archival if needed later —
  it can be deployed as a standalone bucket with no other AWS infra.

> **Executed 2026-07-27 (#211).** The retained code is now deleted: `aws/`, `src/`,
> their tests, the root `requirements.txt`, the AWS Terraform CI jobs, and the AWS CLI
> install baked into the Packer image. The deployment guide no longer teaches the AWS
> path. Recover any of it from git history at `6ce668c` — in particular
> `aws/modules/s3/`, which holds the Object Lock and lifecycle scaffolding if the
> evidence-archival option above is ever taken up.
>
> **OVH Terraform state is local, and stays local.** `ovh/main.tf` declares
> `backend "local" {}`; the S3 backend was dropped when this ADR was accepted. The
> Makefile was still passing a stale `-backend-config=../shared/backend-aws.hcl` flag
> at a local backend, pointing at a file that no longer exists — removed.
>
> Local is the right choice here: remote state buys locking, team sharing and
> durability, and with a single operator running this a few times a year only
> durability applies. A backup answers that more cheaply than a new SaaS dependency
> or re-creating the S3 bucket we just deleted. If remote state is ever wanted, OVH
> Object Storage is S3-compatible and keeps it with the same provider.
>
> ⚠️ **The state file is a single point of failure, and not a mild one.** It contains
> `ovh_dedicated_server_reinstall_task`. If the state is lost, `terraform apply` sees
> no resources and plans to CREATE them — **reinstalling the OS on the live sandbox**.
> Back it up encrypted (it is gitignored and must stay that way). Removing the
> reinstall task from the config now the host is provisioned would downgrade state
> loss from destructive to merely inconvenient — worth doing.

**Consequences:**
- No AWS credentials required to run Ansible — eliminates SSO session expiry problem
- Secrets are in `vars/secrets.yml` (gitignored), encrypted at rest via `ansible-vault`
- Playbook invocation changes: `ansible-playbook site.yml --ask-vault-pass`
- Monthly cost drops from ~$135 (OVH + AWS) to ~$92 (OVH only)
- No structured IOC database (RDS) — defer until analysis volume justifies it
- No API-driven sample submission — operator uses sample-feeder CLI directly
- S3 evidence archival is a standalone future addition if chain-of-custody is needed

---

## ADR-017: Investigation agent architecture

**Status:** Decided 2026-06-10

**Context:**
The investigation agent is a conversational LLM workbench mounted on the analysis
detail page. It needed decisions on: (a) how to invoke sandbox/Ghidra tools from
the FastAPI process, (b) what to persist and replay for the LLM conversation, and
(c) how to handle ATT&CK technique promotion from pinned findings.

**Decision (a) — Sandbox/Ghidra invocation via scoped sudo to the pipeline user:**
`lamware-api` (running as `lamware-api` user) invokes `run-sandbox` and `run-ghidra`
via `sudo -u pipeline`, delegated through `/etc/sudoers.d/lamware-api-investigate`.
Rootless Podman storage is per-user (`/home/pipeline/.local/share/containers`), so
the pipeline user must run the containers — there is no shared storage path that
would work from a different user.

A separate broker service (e.g., a queue-polling daemon running as pipeline) was
evaluated and rejected as overkill for a single-operator deployment: it would add
a new service, IPC channel, and failure mode with no security benefit beyond what
the scoped sudoers rule already provides.

Systemd hardening tradeoffs: `NoNewPrivileges` cannot be set (sudo requires it
absent to gain credentials); `ProtectHome` must be false (sudo children inherit
the mount namespace, so ProtectHome=true would make `/home/` read-only in-namespace,
breaking pipeline's container storage). Compensating controls: `ProtectSystem=strict`
keeps `/usr`, `/boot`, and `/etc` read-only; the sudoers rule restricts escalation to
exactly two commands with no arguments beyond the task ID; containers run with
`--network=none` and are rootless.

**Decision (b) — tool_call/tool_result rows persisted but NOT replayed to the LLM:**
Each turn's tool calls and results are written to `investigation_messages` for
transcript and audit purposes, but subsequent turns are NOT reconstructed from the
DB into the LLM message list. On each new turn the router sends only the chat
history (user/assistant text rows). Tool exchange rows from prior turns are omitted.

This avoids fragile OpenAI-format reconstruction (tool_calls arrays, matching IDs,
content-null rules) and bounds token costs — prior tool results rarely add value to
later turns. The conversation history provides sufficient context via the assistant's
final text response that summarised each tool invocation.

**Decision (c) — technique pins are not auto-promoted:**
`technique_values.tactics` has a NOT NULL constraint (tactics come from MITRE lookup,
not free text). Pin promotion for technique pins returns `promotion_not_supported`
rather than inserting a row with empty tactics. Auto-promotion would require a live
MITRE ATT&CK lookup at pin-confirm time, which adds latency and an external dependency
to a path that should be lightweight. Analysts who want a technique in the DB can
use the standard pipeline output, which populates techniques with full tactic data.

**Consequences:**
- sudo delegation requires `ProtectHome=false` in the systemd unit and `AF_NETLINK`
  in `RestrictAddressFamilies` (rootless Podman uses netlink during namespace setup)
- tool_call/tool_result rows accumulate per session; the transcript export includes them
- `pin_finding` for technique type always returns `promotion_not_supported` — documented
  in the API and surfaced in the frontend pin bar

## ADR-018: Adopt Alembic for malware_analysis schema migrations

**Status:** Accepted (2026-06-13)

**Context:** The `malware_analysis` schema was managed by a one-shot `schema.sql`
plus hand-numbered, hand-idempotent `migration_00X.sql` files applied by the Ansible
`postgres` role. There was no version tracking, no rollback, and no authoritative
record of a database's schema revision. With more tables coming (campaign graph,
detection-engineering output), the drift risk was compounding.

**Decision:** Adopt Alembic for this database. The Alembic project lives in `api/`
next to the models. The baseline revision `0001` is a raw-SQL snapshot captured from
the live database via `pg_dump --schema-only`, embedded verbatim in the revision.
The production database is adopted non-destructively with `alembic stamp 0001`;
fresh databases are built with `alembic upgrade head`.

At deploy, migrations run from a dedicated postgres-owned runner at
`/opt/lamware-migrations/` (its own venv + a copy of the project), executed as the
`postgres` user via Unix-socket peer auth. This preserves the existing privilege
model — postgres performs DDL, the runtime `pipeline` user stays DML-only — and
avoids the lamware-api venv (mode 0750, unreadable by postgres). A stamp-vs-upgrade
guard in the `postgres` role chooses stamp vs upgrade based on the presence of the
`alembic_version` and `samples` tables.

**Phase A (this change)** runs Alembic alongside the legacy SQL files, which are
retained (with deprecation headers) as a rollback net. Autogenerate is disabled
(`target_metadata = None`) because the ORM models cover only part of the schema.

**Phase B (DONE, 2026-06-14)** retired the legacy `schema.sql` + `migration_00X.sql`
files and their Ansible tasks. All three gates were met: (1) `alembic current` = head
on prod, (2) migration `0002` (normalize the `infrastructure_overlap` view) shipped
end-to-end via a revision, and (3) the fresh-DB `upgrade head` equivalence-diff against
prod is clean. Alembic is now the sole schema-management mechanism.

**Spec 2 (DONE, 2026-06-15):** the ORM models now fully mirror the schema (8 missing
tables added; existing NOT NULL timestamp columns made non-nullable), `env.py`
`target_metadata` is `SQLModel.metadata` (conditionally — the app-less deployed runner
falls back to `None`), and autogenerate is scoped to tables + columns + nullability via
`include_object` (indexes/unique/FK/views remain hand-authored). A drift sentinel
(`api/tests/test_alembic_drift.py`, run on the host via `scripts/check-alembic-drift.sh`)
asserts models and DB stay in sync.

**Consequences:**
- New schema changes are versioned revisions in `api/alembic/versions/`; rollback via
  `alembic downgrade` is available.
- A dedicated `/opt/lamware-migrations/` venv is provisioned on the host.
- Phase A ran Alembic alongside the legacy SQL as a rollback net; Phase B removed the
  legacy mechanism, so a fresh host now builds the schema solely via `alembic upgrade
  head` (0001 → 0002 → …). The schema's single source of truth is `api/alembic/`.

---

## ADR-019: Family attribution is not a capability metric for the RE stage

**Status:** Decided (2026-08-10). Trimmed 2026-10-05: the measurements and literature check
moved to [FAMILY_ATTRIBUTION.md](FAMILY_ATTRIBUTION.md); the decision is unchanged.

**Context:**

The eval harness reports `family_guess` against `mb_family` on every cell, and that column
was read as a quality signal. Measured, it is not one: qwen scored **0/14** against
MalwareBazaar labels, the Claude reference **0/7** on the same samples, and MalwareBazaar's
own labels disagreed with the reference on every sample. Published work puts the labelling
tools behind such labels under 50% accurate (AVClass 46.78% against MOTIF's expert truth).

Scoped correctly, the structural claim is narrow: the signals an LLM reading **decompiled
code** relies on (strings, config markers, crypto constants, import combinations) do not
survive packing, even though the byte-level statistics supervised classifiers use do.
Naming a family from an open set is also inseparable from recall of published analyses
(contamination). The full evidence, including where the naive "packing destroys family
ID" claim is wrong, is in [FAMILY_ATTRIBUTION.md](FAMILY_ATTRIBUTION.md).

**Decision:**

1. **`family_guess` is not a capability metric for THIS stage.** It stays in the
   scorecard, reframed as a **contamination probe**: near-zero is the expected result
   for an LLM reading decompiled packed code over an open family set, and an
   unexpectedly *high* score is more likely memorisation of published analyses than
   analysis of the binary. Note this is a claim about the method, not about family
   classification in general — supervised byte-level classifiers do well on the same
   samples.

2. **The RE stage is measured on grounded capability claims** — `grounded_ratio`,
   fabrication count, and (once #314 lands) recall against detonation-confirmed
   behaviour. Those test whether a claim is supported by the code the model was shown,
   which is the thing static analysis can actually be held to.

3. **Family attribution belongs to detonation and YARA**, not to the RE stage. Where a
   family label is needed for reporting, it comes from CAPE signatures or MalwareBazaar
   metadata, and is presented as provenance rather than as an RE finding.

4. **Ground truth for recall comes from CAPE**, not from threat reports (#314). The
   decisive property is that `run_arm` passes interpret only the Ghidra input production
   would send (since #698, the selected analysed file), so CAPE observations are
   independent of the model's evidence and scoring against them is not circular. It is a
   lower bound — one execution, so evasion or a dead C2 means it
   under-reports — usable for confirming predictions, not for penalising misses.

**Consequences:**

- Any future "the model got the family wrong" observation is expected behaviour, not a
  regression. Do not tune prompts against it.
- Comparisons between local and cloud arms on family ID measure training-data overlap,
  not capability.
- **Label-leak hazard.** `_bazaar_context()` puts the MalwareBazaar family into the prompt
  verbatim (*"Use this as your starting hypothesis"*) whenever the init carries
  `bazaar_family`. Production's .NET, PowerShell and Go paths pass it (`**llm_context` in
  `stages/single_shot_init.py`); the native PE and unpacked-payload paths do not. Since
  #646/#667 the eval's .NET path mirrored production and passed it too; no corpus report
  carried one, so no cell received it (checked 2026-10-05). Since #705 the eval
  **withholds** it and records `bazaar_family_withheld` on the cell; promotion and
  `run_arm` refuse any init that still carries it. Production still passes it.
- If family ID is ever wanted as a product feature, the route is a supervised byte-level
  classifier over a closed family set, not this stage.
- Unpacking was the higher-leverage fix this ADR pointed to, and it has landed: CAPE's
  unpacked payloads reach Ghidra and the agent reads the payload (#646, #651, #666).

---

## ADR-020: One firewall mechanism — iptables-persistent, not UFW

**Status:** Live (2026-09-19; amended 2026-10-05 and 2026-10-18)
**Supersedes:** the implicit arrangement where both were installed
**Closes:** #563 (filed 2026-09-03, which recommended exactly this)

### Decision

This host uses **iptables-persistent only**. `roles/hardening` passes
`manage_ufw: false` to konstruktoid and purges the `ufw` package.

### Why not both

They are mutually exclusive by package metadata — `ufw` declares
`Breaks: iptables-persistent, netfilter-persistent`. Installing either removes
the other. Because `hardening` installs ufw and `networking` installs
iptables-persistent, **every deploy picked a winner by role order**, and that
decided whether the host's controls worked. Nobody chose it and nothing
reported it.

### What ufw broke, measured

All on 2026-09-19, on the live host, with every existing check green:

| control | behaviour with ufw installed |
|---|---|
| pipeline egress | DROP present with **0 packets** while uid 997 reached `1.1.1.1:443`, `1.1.1.1:53`, `127.0.0.1:27017`, `127.0.0.1:4000` |
| host → guest agent | nothing accepted NEW outbound to `virbr-det`; CAPE hit *"guest initialization hit the critical timeout"*, **0 processes, 0 API calls** |
| CAPE web UI | listening on `10.200.0.1:8000` with no inbound rule at all |

The mechanism is ordering. ufw inserts its chains at the top of `INPUT`,
`OUTPUT` and `FORWARD`; `-o lo -j ACCEPT` and `ufw-user-output` (22, 53, 80,
123, 443, 853, 4460 **to any destination**, from konstruktoid's
`ufw_outgoing_traffic` default) both terminate traversal. Anything appended
below is unreachable.

### Why iptables-persistent wins on this host specifically

The air-gap DROPs must be evaluated **before** anything can accept. They sit at
`FORWARD` positions 4–5, above every other chain. ufw's equivalent slot,
`ufw-before-forward`, is position 10 — **below `LIBVIRT_FWO`**, which libvirt
rewrites on every network restart. Choosing ufw means the most critical control
in the project depends on config we do not own.

`rules.v4` also persists `INPUT`, `OUTPUT` **and** `FORWARD` together, which is
what the raw rules need and what before.rules could not give them.

### What this gives up, and does not solve

ufw provided **default-deny inbound**. `/etc/iptables/rules.v4` carries
`:INPUT ACCEPT`, so any service that listens is reachable by whatever can route
to it — which is exactly how the CAPE UI was exposed without a rule. **That
property is currently unpaid for.** It is not addressed by this ADR and must not
be read as handled.

### Why this took sixteen days

#563 was filed 2026-09-03 with the symptom, the cause, the packet counters, and
this recommendation verbatim — *"the only one that removes the class of bug
rather than patching instances"*. It was then rediscovered from first principles
on 2026-09-19 at the cost of a working Saturday, three detonations and two false
urgent pages.

Prose did not prevent it. What prevents it now is executable: the checks in
`tests/test_hardening_ufw_inbound.py` fail if `manage_ufw` is true, if ufw is
not purged, or if persistence is dropped — and `make security-test` now asserts
the host can reach its own guest agent, which is the assertion #563 asked for
and is what turns a four-hour diagnosis into a red check.

**If you are reading this while considering ufw: the tests will stop you, and
they are right to.**

### Amendment (2026-10-05): guest traffic to the host is default-deny on INPUT

The section above leaves default-deny inbound unpaid for. This amendment pays it for
one source, the detonation bridge, and only that one. Everything above stands as
written.

**Amendment status:** implemented on `fix/adr-022-guest-input-default-deny`. It is in
force on the host once `make deploy TAGS=networking` has run from that branch and the
probes under *Verification* pass.

#### Context

The air-gap in `SECURITY_CONSTRAINTS.md` is two `FORWARD` rules. They govern packets
the host *routes* from `virbr-det` to another interface. A packet from a guest
addressed to one of the host's own addresses (the bridge gateway `192.168.100.1`, the
WireGuard address, the public address) is not routed. The kernel delivers it
locally, so it traverses `INPUT`, and the air-gap rules never see it.

`INPUT` on the host, read 2026-10-05: policy `ACCEPT`; fail2ban jumps; nine
`-i virbr-det … -j ACCEPT` rules for INetSim and the resultserver, inserted by
`roles/networking`; a jump to libvirt's `LIBVIRT_INP` (DNS and DHCP on the bridge);
empty chains left behind by ufw. The per-port ACCEPTs were written for the day *"the
hardening role or a future policy tightens the default"* (the role's own comment).
That day never came, so they permitted nothing the policy did not already permit.

Measured 2026-10-05: across 400 CAPE pcaps, guests sent 45,481 SYNs to
`192.168.100.1:5201`. That port is on no allowlist and nothing listens on it, and
every SYN was answered by a RST from the host. The host's TCP stack only answers a
packet that `INPUT` has delivered to it, so if anything had been listening on that
port, the guest would have connected. The same holds for every host listener on an
address the host treats as local. The section above already showed that this
includes the CAPE UI.

#### Decision

Every packet that arrives on `virbr-det` for the host is decided by one chain,
`LAMWARE-GUEST-IN`. The chain ends in a terminal REJECT and is jumped to from `INPUT`
position 1 for `-i virbr-det`. The chain is self-sufficient: it does not rely on
anything else in `INPUT`, before or after it.

IPv4, in order. The ports come from the variables the other roles bind. The INetSim
services are the ones [ADR-011](#adr-011-guest-network-simulation--inetsim-on-host)
put on the gateway.

| # | match | action | why |
|---|---|---|---|
| 1 | `conntrack ESTABLISHED,RELATED` | ACCEPT | replies to host-initiated flows (see below) |
| 2 | udp dport 67 | ACCEPT | DHCP (libvirt's dnsmasq). No destination match, because a DISCOVER goes to the broadcast address |
| 3–4 | `-d detonation_gateway` udp/tcp dport 53 | ACCEPT | DNS, if the PREROUTING redirect is ever absent |
| 5–6 | `-d detonation_gateway` udp/tcp dport `inetsim_dns_port` | ACCEPT | INetSim DNS, after the 53 → 5300 redirect (ADR-011, #456) |
| 7–10 | `-d detonation_gateway` tcp dport 80, 443, 25, 21 | ACCEPT | INetSim HTTP, HTTPS, SMTP, FTP (ADR-011; the bind ports in `inetsim.conf.j2`) |
| 11 | `-d detonation_gateway` tcp dport `cape_resultserver_port` | ACCEPT | CAPE resultserver |
| 12 | `-d detonation_gateway` icmp echo-request | ACCEPT | gateway ping, a common sample connectivity check |
| 13 | tcp | REJECT `tcp-reset` | |
| 14 | everything else | REJECT `icmp-port-unreachable` | |

IPv6 has the same structure: ESTABLISHED,RELATED; neighbour solicitation and
advertisement; echo-request; then the same two REJECTs (`icmp6-port-unreachable`). It
has no service ACCEPTs, because no guest-facing service binds an IPv6 address. IPv6 is
disabled host-wide today. The chain exists so that enabling IPv6 does not open the
guest path; #343 showed what happens when only one family is covered.

**ESTABLISHED,RELATED first.** CAPE drives the guest agent from the host to the guest
(#620). The guest's replies to the host's ephemeral ports arrive on `INPUT` through
`virbr-det`. A deny on that path without an ESTABLISHED accept breaks every
detonation. It fails the way task 1250 failed in #620: *"guest initialization hit the
critical timeout"*.

**REJECT, not DROP.** When nothing listens on a port, the kernel already answers TCP
with a RST and UDP with ICMP port-unreachable. REJECT sends the same answers, so a
closed port looks the same to a guest and replies on the same timing. DROP would turn
every refused probe into a timeout and change the timing of samples that probe the
gateway, such as the 5201 traffic above. Neither the kernel nor REJECT sends an ICMP
error for broadcast or multicast, so that traffic is unchanged too.

**Destination-scoped allows.** A port-only match would accept a guest's packet to the
same port on *any* host address, which is exactly the gap this amendment closes. Only
DHCP is unscoped.

**Position 1, and what the invariant actually is.** The rule is: nothing evaluated
before the jump may accept guest traffic that the chain itself would refuse. fail2ban
re-inserts its jumps at the top of `INPUT` whenever it restarts, so the jump will not
always be literally first. fail2ban's chains only reject banned sources or return.
`LIBVIRT_INP` accepts DNS and DHCP on the bridge, which the chain allows anyway. So
neither one breaks the rule. The role puts the jump back at position 1 on every run.
That way, an interface-agnostic ACCEPT added to `INPUT` later sits below the jump and
never applies to guests.

**Applied atomically and rebuilt every run.** `roles/networking` renders the chain to
a file and loads it with `iptables-restore --noflush`, which replaces the chain's
contents in one transaction. The chain is never half-built, and the order on the host
is the order in the file. The nine per-port `INPUT` ACCEPTs move into the chain and are
removed from `INPUT`. `netfilter-persistent save` persists the result.

#### Consequences

- **Everything a guest can open on the host:** DHCP; DNS and INetSim DNS, HTTP,
  HTTPS, SMTP and FTP on the gateway; the resultserver on the gateway; ping to the
  gateway. Nothing else, on any host address.
- **Changed:** if a host port is *open* and not in that list, guests now get a RST or
  port-unreachable from it. Ping to a host address other than the gateway is refused
  instead of answered. ICMP that is neither echo-request nor part of a tracked flow
  (a timestamp request, for example) is refused.
- **Unchanged:** the `FORWARD` air-gap; host → guest flows, including the CAPE
  agent; the answer to closed ports; DHCP, DNS, INetSim and the resultserver.
- **Still unpaid:** default-deny inbound for traffic arriving on `wg0` or the
  management (public) interface. `INPUT` policy stays `ACCEPT`. This amendment does
  not address that, and must not be read as handling it.
- **Not continuously watched.** `network-monitor` checks `FORWARD` and the pipeline's
  `OUTPUT` allowlist, but not this chain. Probing the chain from the host would need a
  probe interface attached to `virbr-det`, and this amendment does not add one. The
  probes below verify it once, after deploy.

#### Verification

These checks run on the host after `make deploy TAGS=networking`:

- A pcap of the next detonation shows that a guest's SYN to a closed gateway port
  still gets a RST, and that no port outside the list answers a SYN with a SYN-ACK.
- A probe from a clean guest to ports 22, 8000 and 443 on the gateway and on the
  WireGuard address is refused.
- A normal detonation completes: the guest agent is reached and the resultserver
  receives.
- INetSim DNS and HTTP answer.

#### Rollback

Delete the `INPUT` jump and the chain in both families, re-insert the nine per-port
ACCEPTs, and run `netfilter-persistent save`. The exact commands are in the PR that
introduced this amendment. They restore the `INPUT` the host ran until 2026-10-05.
Reverting the code and redeploying does **not** do this: the earlier role never
removes the chain.


### Amendment (2026-10-18): persisted rules exclude chains other agents own

Refs: #580, #576.

ADR-020 made iptables-persistent the single firewall mechanism: the rule set is
written to `/etc/iptables/rules.v4` and `.v6` and restored at boot. Two roles
persisted it with `netfilter-persistent save`, which is `iptables-save` of the
*live* tables. The live tables are not only ours. Podman writes port-publish
chains (`CNI-HOSTPORT-DNAT`, `CNI-DN-*`; `NETAVARK-*` on newer versions) whose
DNAT names the container IP of the moment; libvirt, fail2ban and CAPE's rooter
keep chains of their own too.

Persisting podman's chains looked harmless and was not. Restored at boot, the
saved DNAT sits ahead of the one podman creates for the new container, and the
first match wins: every connection to the published port goes to an address
nothing holds. The container says `Up`, `ss` says `LISTEN`, `systemctl` says
`active`, the pipeline exits 0. That was #580 (six days in September) and again
on 2026-10-18, when a pipeline deploy saved `--to-destination 10.88.0.12` at
18:00, the host rebooted at 18:49, the new container came up at 10.88.0.2, and
the post-reboot detonation's summary stage failed on a 500 from LiteLLM.

**Decision.** The firewall is persisted through one helper, `lamware-persist-firewall`
(roles/networking/files, installed by every role that persists), which saves
the live tables **without** container-managed chains (`CNI-*`, `NETAVARK*`)
and refuses to write a set that `iptables-restore --test` rejects. No role calls
`netfilter-persistent save` directly. Podman recreates its chains when a
container starts; nothing of ours is lost by not restoring them.

Chains owned by libvirt, fail2ban and CAPE are left in the saved set for now:
each of those agents rebuilds its own at start and no harm from restoring them
has been observed. If one is, it joins the filter here, not in a role.

**Consequences.**
- A reboot cannot resurrect a dead container address. The health check in
  `check-podman-ports.sh` stays as the detector for anything else of that shape.
- `rules.v4` no longer mirrors `iptables-save` byte for byte; anyone comparing
  the two must expect the container chains to differ.
- A new agent that writes its own chains needs a conscious decision about
  whether they belong in the persisted set, which is the question this ADR
  exists to ask.

## ADR-021: Hostile files are interpreted only inside a sandbox; agent tools are brokered by the orchestrator and executed in one

**Status:** Live (2026-10-03) — PR #673 deployed and merged (5dda856); on the host each .NET tool call ran in a sandbox container (~0.45 s per call) with memory/pids limits enforced (cgroup controllers delegated to `pipeline`)
**Issue:** #646 (the agentic .NET path is where the question came up; the decision is general)

### Decision

Hostile files are interpreted only inside a sandbox. Orchestrators (the pipeline and
the API) may hash, peek at fixed-offset headers, read bounded byte ranges, and run
fixed-pattern scans over bounded bytes; they never parse file formats and never run
model-supplied logic. Agent tools are brokered by the orchestrator and executed in a
sandbox — never in the orchestrator's own process and never answered by the interpret
container itself.

### Context

Two properties, and both decide where a tool runs.

**Interruptibility.** The interpret container reads stdin only while waiting for a tool
result, so a brokered tool call is the only moment `force_final` and the synthesis
reserve can reach the agent (#240, #663). A tool the interpret container answered for
itself would recreate the run nothing can stop — the .NET single-shot request that ran
5,447 s past a 3,600 s budget (redet644, 2026-09-27) was that shape.

**Isolation.** The orchestrators hold what an attacker wants: the pipeline user has the
database credentials (pipeline.env), CAPE storage, every report and rootless podman;
the API holds the same data behind its users. The first version of #673 served the
.NET tools in the pipeline process — interruptible, but parsing the sample's C# with
those privileges, and running the model's regex in a child that had them too. Review
then found the parser could be crashed by its input (600 nested interpolated strings,
`RecursionError` out of Stage 4.5). A parser of hostile input will have defects; the
question is only what they can reach.

**Survey, 2026-10-03** (the guard test below keeps it true):

- The pipeline and API import no format parser: no pefile, lief, yara, olefile/oletools,
  zipfile/tarfile/py7zr, scapy/dpkt/pyshark, evtx, Registry or volatility.
- Every real parser runs in a container: triage, CAPE, Volatility, Ghidra, ILSpy,
  PyInstaller, Office, PowerShell, PCAP.
- In-process byte handling is limited to sha256, header peeks (stages/ghidra.py,
  dotnet.py, pyinstaller.py, cape.py), script text (script_analysis.py) and
  fixed-pattern dump scans (volatility.py `extract_shellcode_artifacts`).
- The analyst agent's tools: the Ghidra tools and `run_python` already execute in
  sandboxes; `read_payload` is an allowed bounded byte read with no format parsing; the
  rest read stored report and database JSON.

So the rule already held everywhere except the agentic .NET tools.

### Consequences

- Ghidra tools: unchanged — the orchestrator brokers each call, `run-ghidra --tool` runs
  it in a per-call container.
- .NET tools: the pipeline brokers each call (`stages/dotnet_agentic.py`) and
  `run-dotnet-tools` executes it in a per-call `python-sandbox` container (no network,
  read-only root, no host mounts — the source arrives on stdin — memory and pids
  limits, all capabilities dropped, no-new-privileges, `--user 65534`, podman
  `--timeout` plus an outside backstop). The first-message map is built there too, so
  the pipeline never parses the sample's C#. Any sandbox failure is that one call's
  error; the run continues.
- A container per call costs a container start and an index rebuild per call. Accepted:
  it keeps every call a separate, killable, brokered unit, the Ghidra shape.
- `tests/test_orchestrators_parse_no_file_formats.py` fails when an orchestrator imports
  a format parser; an exception needs a written reason in its allowlist.
- New tools — for the pipeline agent or the analyst agent — follow the same rule: if a
  tool interprets sample bytes, it runs in a sandbox, brokered.

---

## ADR-023: Image builds are hermetic — an unprivileged fetch user downloads every build input, pinned and checksummed; `podman build` runs with no network

**Status:** Accepted (2026-10-09; fetch user amended at the owner's direction)
**Refs:** #728 (pdf-generation image stale since 2026-05-17), #725 (triage YARA), #344
**Extends:** the 2026-08-08 rule that third-party *source* is fetched by the role with
`get_url` + checksum and `COPY`ed in (`tests/test_container_build_pinning.py`). That rule
never covered package managers. This decides them.

### Decision

1. **Nothing inside a Containerfile reaches the network.** `podman build` runs with
   `--network=none`. No `pip install` from an index, no `apt-get update/install` from a
   mirror, no `curl`/`wget`/`git clone`, no `dotnet tool install` from NuGet.
2. **A dedicated unprivileged user, `lamware-fetch`, downloads every input before the
   build**, and each one is verified. Not root, and not pipeline: the fetch user is the only
   one with network for builds, it runs nothing but downloads, and owns nothing else. Ansible
   copies the verified files into the build context.
   - **Python:** a wheelhouse from `pip download --require-hashes --only-binary=:all:`
     (target `cp312` / `manylinux`, matching the image) against a hash-locked
     `requirements.lock`. The Containerfile installs `--no-index --find-links` with
     `--require-hashes`.
   - **Debian packages:** resolved and fetched with `apt-get install --download-only` in a
     throwaway **rootless** container of the *same pinned base image*, run by the fetch
     user (container root is that user on the host, so apt's resolver runs without host
     root). Versions recorded in the role. Installed offline in the build
     (`apt-get install ./*.deb`). apt's signed Release chain verifies them at download.
   - **Source archives, tools, NuGet packages:** `get_url` with `checksum: sha256:…`, as
     today.
   - **Base images:** pinned twice — by the registry manifest digest the fetch user pulls,
     and by the image ID (config digest) the build uses — and handed to the pipeline user's
     image store, where the ID is asserted before any build. Moving a base image is a
     deliberate change to both pins, not a side effect of a tag moving or of a cache being
     cleared. See the 2026-10-12 amendment below.
3. **A stale image fails the deploy.** Each image carries a label with a hash of its build
   context. After the build, the deploy compares the label of the image the wrappers will
   run against the context it just shipped, and fails on a mismatch, rather than reporting
   `changed` for a build that kept an old image.

Downloads run code from nobody: `pip download --only-binary` and `apt-get --download-only`
execute no package scripts. Installation, which does, happens in the build, which has no
network. A compromised upstream package therefore runs with nothing to talk to. And the
process that does talk to the network holds no privilege beyond its own download
directory: no root, no access to samples or reports.

### Context: what was observed

- **The pdf-generation image is from 2026-05-17.** Its build is `--no-cache`, so it runs
  `pip install weasyprint` on every deploy, as the pipeline user, which has no DNS since the
  egress lockdown (#343). No build has succeeded since: the deploy on 2026-10-08 failed at
  that step with `Temporary failure in name resolution`. The image's `generate-report.py`
  differs from the repo's, and six later report-generator commits, including the
  header-hash fix (302c05a), never reached a PDF.
- **Triage's YARA step could not succeed** for the same reason: the rules were
  `git clone`d as pipeline, on a host with no git, and were last fetched 2026-05-17. #725
  fixed that one with pinned, checksummed archives, the pattern this ADR generalises.
- **12 of 14 image roles install packages at build time.** Only go-analysis and
  python-sandbox do not. Six roles build `--no-cache`, so their package steps run on every
  deploy; the other eight reuse cached layers for them. Either way, a package step that
  runs depends on network access the build user is not meant to have, and a new host or
  a cleared cache runs all of them.
- **Base images are pulled once and never refreshed.** Tags float upstream; nothing here
  moves them.

The surface looked healthy throughout: a build task reports `changed`, the old image keeps
running, and nothing compares what runs with what the repo says should run.

### Alternatives considered

- **Root does the downloading.** The first draft of this ADR. Rejected by the owner on
  least privilege: downloads need network, not root, and the fetch user gets the first
  without the second.
- **Give the pipeline user network for builds.** Rejected. Pipeline's lack of DNS and
  egress is the containment for everything that touches a sample. Weakening it for build
  convenience trades the property the host exists to have.
- **A dedicated build user with egress, images handed to pipeline with `podman save` /
  `load`.** Simpler: the Containerfiles barely change. Rejected as the default because it
  runs every upstream install script *with* network on the analysis host at deploy time,
  and the inputs stay implicit in the build log instead of visible and checksummed in the
  role. Kept as the fallback for a role whose dependencies cannot be resolved offline,
  recorded per role with the reason.
- **Build images off-host (CI or the controller) and ship them.** Deferred, not rejected.
  It moves the build off the analysis host entirely, but needs a registry or artifact
  transfer and a reproducibility story this repo does not have yet.

### Consequences

- One PR per role group, pdf-generation first: it serves stale code today, and its
  wrapper change from #725 waits on `fix/pdf-generation-offline-build`. Then the other
  `--no-cache` roles, then the cached ones.
- `tests/test_container_build_pinning.py` widens from source fetches to package managers,
  with a `MIGRATION_PENDING` list that must shrink, and a check that every `podman build`
  task passes `--network=none`.
- Builds get slower to change: adding a Python dependency means regenerating a hash-locked
  lockfile. That is the point. The analysis toolchain decides what an analysis sees.
- Not solved here: whether the *running* analysis containers' images are the ones the repo
  describes is what decision 3 makes checkable; it does not by itself rebuild anything.

### Amendment (2026-10-12): a base image is identified by its image ID, not its registry digest

**Observed.** The first base image that pipeline did not already hold (the dotnet SDK)
could not be handed over. `podman save --format oci-archive` rewrites a Docker-format
registry manifest as an OCI manifest, so the saved manifest's digest
(`sha256:f80ec9a7…`) is not the registry digest that was pinned (`sha256:0eeb52c7…`), and
`podman load` refuses to file the image under the pinned reference ("Digest of source
image's manifest would not match destination reference"). Pinning the platform manifest
instead of the multi-arch index did not help: the conversion changes the bytes whatever
is pinned. Every role built so far succeeded only because pipeline already held its base
from before ADR-023; on a fresh host, or at any base bump, all of them would fail this way.

**Decision.** Each base is pinned twice:
- `ref`: the registry manifest digest. The fetch user pulls by it; the registry's
  content addressing is the trust anchor, exactly as before.
- `id`: the image ID, the sha256 of the image config. The manifest the registry verified
  names the config by this hash, so the ID is derived from what was verified, and it is
  the one identity that survives save/load unchanged, provided the hand-off uses a
  docker-archive: an oci-archive rewrites the config as well (measured 4df5db95… → ea074cf5…).

The hand-off tags the image locally in the fetch user's store, saves it as a docker-archive
(saving by the registry digest cannot load: the archive names a digest the save no longer
matches), loads it into pipeline's store under that local tag (so a prune does not treat it
as dangling), and **asserts the loaded image's ID equals the pin**
before any build. Containerfiles build `FROM` the image ID; every built image carries a
`lamware.base` label naming the registry reference, so lineage stays readable.

**Consequences.** Bumping a base changes both pins; a mismatch fails the deploy at the
hand-off rather than building from the wrong base. All image roles change their `FROM`
once; the bases are byte-identical, so the rebuild is expected to reuse cached layers.

**Recorded under the second-fix rule (CLAUDE.md §2):** the first fix (platform digest)
addressed the instance; this addresses the decision the original text got wrong.

---

## ADR-025: Code the pipeline runs is root-owned; the pipeline user owns data only

**Status:** Accepted (2026-10-15)
**Refs:** the 2026-10-07 security review; ADR-021 (sandboxing hostile files), ADR-023 (hermetic builds)

### Context

The `pipeline` user reads hostile files all day, through parsers, decompilers and
model output. The architecture assumes it can be compromised, which is why it has
no network (ADR-020, #777) and why hostile files are opened only in containers
(ADR-021). What it could still do was write: it owned `/opt/pipeline`, the venv it
runs from, and the modules in it. One write as pipeline would then run again in
every later analysis, with no further foothold needed. The same held for any
other user that could write there.

### Decision

1. **Anything the pipeline executes or imports is owned by root and not writable
   by any other user**: the install directory itself, the stage modules, the
   eval and detonation harnesses, the venv and everything installed in it, the
   wrappers, `config.json` and `pipeline.env`. Pipeline reads them through its
   group.
2. **Directories count, not just files.** The owner of a directory can rename or
   replace any file in it, whoever owns the file.
3. **No writable bytecode caches.** A cache directory another user can write in
   a root-owned tree is code that user can plant. Caches are removed on deploy,
   and only root can recreate them.
4. **Root installs only what root controls.** The venv is installed by root,
   offline, from a root-owned wheelhouse and root-owned package source. Moving
   the install to root while the pipeline still owned its inputs would have
   turned a persistence path into a privilege escalation.
5. **The pipeline user owns data only**: reports, eval output, corpus, logs,
   the correlated-report keep-list, the Volatility ramdisk.

### Verification

Security-test check 14 asks the kernel, as the pipeline user and as cape, with
`find -writable` (access(2), nothing modified), whether any code path is
writable: the install directory itself, every code subdirectory, the venv in
full, and the top-level code files. It fails if anything is, and it fails if the
pipeline user cannot write its own reports directory, so a blind probe cannot
pass. It was run against the host before the change and failed, naming both
users.

### Consequences

- A deploy of the pipeline role takes ownership back every time, including
  files no task ships (stale modules) and files pip writes.
- Operators running code from `/opt/pipeline` as root import root-owned files
  only.
- Rollback is not a plain revert: the previous role pip-installs as pipeline,
  which fails on a root-owned venv. Give the venv, `pkg/` and `wheelhouse/` back
  first (`chown -R pipeline:lamware` on each), then redeploy the reverted role,
  which re-owns the rest. No data moves.


### Amendment (2026-11-13, proposed): phase 3, the images the pipeline runs

Phases 1 and 2 made the pipeline's code and the analysis tools' code root-owned
(#787, #838, #839). The containers those tools run in are still the pipeline's:
each wrapper runs `localhost/<tool>:latest` from the pipeline user's rootless
store (`/home/pipeline/.local/share/containers/storage`), which that user can
change. A compromised pipeline can rebuild or retag an image, or edit a layer's
files on disk, and every later analysis runs its version. That is persistence
and a quiet loss of analysis integrity (a tampered analyser can report a sample
as clean). It is not an escalation: the containers already run with the
pipeline's privileges and no network.

**Measured on the host (podman 4.9.3, rootless, native overlay), with the
limits of each result stated:**

- The wrappers name images by mutable tag. The only check is at deploy time
  (the `lamware.build-context` label); nothing checks at run time.
- **Not every caller goes through a wrapper.** `run-dotnet-tools`,
  `run-prompt-ab`, `run-sandbox`, the Volatility cache-build task and
  security-test's network probe also name `localhost/<tool>:latest`. Any fix
  must cover all of them.
- **The build cache is the pipeline's.** `podman build` runs as the pipeline
  user in its own store, without `--no-cache`. A tampered cached layer would be
  baked into a freshly built image that the deploy then trusts.
- **The image store's metadata is the pipeline's too**, not just its layer
  files. An edit there could point an image ID at different layers. That is
  reasoned, not tested; podman is not known to re-verify layers when it runs one.
- **A root-built image used from a read-only additional store — unresolved.**
  - In one run it **started and ran**, both as the image's non-root user and as
    root. In that run, however, the store had been made world-readable
    recursively, which also changed a private file in the image from 0600 to
    0644. Files owned by the image's own user appeared as uid 65534.
  - In a later run it **failed**, with `creating /etc/mtab symlink: permission
    denied`. That run changed three things at once (a new graph root, explicit
    storage flags, and a not-yet-created `XDG_CONFIG_HOME`), so the cause was
    not isolated. It is **not** established that root ownership of the layers
    caused the failure.
- **Configuration precedence — unresolved.** With only `CONTAINERS_STORAGE_CONF`
  set, podman kept the pipeline user's usual graph root, but did honour the
  additional store from that file. Which file wins for which setting was not
  isolated. Passing `--root`, `--runroot` and `--storage-driver` on the command
  line did take effect.

**Options:**

1. *Root-built images in a read-only additional store.* Would make the images
   root's. Whether they run rootless on podman 4.9, and with what file-ownership
   cost inside the container, is open (above).
2. *A dedicated non-root build user's store, shared read-only.* Reasoned, not
   tried: likely the same cross-user ownership question as option 1.
3. *Pin and watch.* Run by image ID from a root-owned manifest, ignore the
   user's container configuration, and have AIDE watch layer contents. Weaker
   than it first looked:
   - an ID does not protect against a metadata edit (above), and the metadata
     changes on every run, so AIDE cannot watch it;
   - every deploy rebaselines AIDE (#822), so a layer edited before a deploy is
     absorbed into the new baseline, not alerted on;
   - it does not cover the build cache.
4. *Keep the pipeline-built store, but read-only to everyone outside a build.*
   Root bind-mounts the store read-only; each run uses a fresh empty writable
   graph root with the read-only store as an additional store. A deploy
   remounts it writable only for its own build step. Ownership stays mapped as
   today, so containers should run as now, and the kernel refuses writes to
   layers and metadata alike, whoever owns them. Untested.

Whichever option is chosen, the build cache needs its own answer: build with
`--no-cache`, or build in a separate store.

**Controlled spike (2026-11-13), throwaway stores only, every podman call with
explicit `--root`/`--runroot`:**

- **Option 1 does not run on podman 4.9, and the cause is isolated.** The same
  image fails from a root-built read-only store (`creating /etc/mtab symlink:
  permission denied`), with or without the `XDG_CONFIG_HOME` override. It runs
  from a pipeline-built store mounted the same way. The only difference is who
  owns the layers. The earlier "success" was produced by re-moding the layer
  files.
- **Option 4 runs, and ownership is preserved:** the image's own user read its
  0600 file, as in the control.
- **Option 4, as built in the spike, is not tamper-proof.** Writing through the
  read-only bind mount was refused for a direct write, but **succeeded through
  `podman unshare`**: the layer file's hash and mode changed, and a container
  then read the tampered content. Likely causes (reasoned, not isolated):
  - the pipeline user's long-lived podman namespace predated the read-only
    remount and kept a writable view of the mount;
  - the store's real directory was owned by the pipeline and reachable through
    a world-traversable path, so it could be written without going through the
    mount at all.
- **Lesson for any check of this property:** it must be probed from *inside* the
  pipeline user's podman namespace (`podman unshare`), not only as the user.
  The direct-write probe alone passed while the store was writable.

**Second controlled spike (2026-11-13): option 4 holds with two conditions.**
The pipeline built an image into a throwaway store. Root then placed the store's
real directory under a root-only (0700) parent and bind-mounted it read-only
elsewhere. Every write was probed as the pipeline user, directly and through
`podman unshare`:

| | pipeline's podman namespace started **before** the read-only mount | restarted (`podman system migrate`) **after** it |
|---|---|---|
| write via the read-only path | refused | refused |
| write / chmod via `podman unshare` | **succeeded** (file changed) | refused |
| write to the hidden real path (also via unshare) | refused | refused |
| container from the read-only store | n/a | runs; the image's user reads its own 0600 file |

The leak was namespace ordering: a podman namespace that predates the
read-only remount keeps a writable view of the mount. The pause process's PID
was not captured (the probe pattern was wrong), so the restart is evidenced by
the change in behaviour.

**Proposed decision: option 4.**

- **The store:** the pipeline's image store lives under a root-only directory
  and is reachable only through a read-only bind mount, set up at boot before
  the pipeline user first runs podman.
- **Each run:** uses a fresh empty graph root, with the read-only store as an
  additional image store and explicit storage flags.
- **Each deploy's build step:** opens the root-only parent (the read-only view
  stays mounted), builds into the real path as the pipeline user, then closes
  the parent, waits (bounded) for running containers, restarts the pipeline's
  podman namespace, and probes; the deploy fails if the probe can write or is
  blind. As built: `image-store` role, `lamware-image-store open|close`, and
  `lamware-podman` for every run.
- **What this closes:** layer files, image metadata and the build cache are all
  read-only outside a deploy's build step, so it covers the gaps that ruled out
  option 3.
- **Every caller** that names an image moves to the per-run form: the wrappers
  and the five other callers listed above.
- **security-test check 18** must probe through `podman unshare`. The spike shows
  that probe tells the broken and fixed states apart; a plain write test does not.

**Not yet tested:** the deploy-time open/build/close cycle on the real 14
images; a reboot (does the mount come up before the pipeline's first podman
use?); and running containers across a namespace restart. Before migration the
store should be pruned: 143 of its 166 images are dangling.

**Rollback:** wrappers go back to tags; remove any manifest, per-run
configuration, mounts or AIDE rules. No data moves.

---

## ADR-026: CVP frontier models are reached through Claude Platform on AWS, with SigV4 from IAM Roles Anywhere; no static key

**Status:** Superseded by ADR-034 (2026-11-20): retired, its arms moved to ADR-033's eval route. Accepted 2026-11-18 (owner); proposed 2026-11-09.
**Supersedes:** the proposals ADR-022 (#724, Anthropic-direct WIF from Keycloak) and
ADR-024 (#784, Amazon Bedrock with IAM Roles Anywhere). Neither merged; their numbers
stay retired.
**Refs:** ADR-016 (secrets), ADR-021 (brokered model access), CLAUDE.md §10 (usage tracking)

### Context

The owner's Cyber Verification Program (CVP) access is what makes Claude Mythos 5.1
callable. The program forbids static or long-lived keys, requires credentials that
expire within 12 hours, and requires federation for workload access.

Both earlier proposals assumed the wrong place for that access. Measured on
2026-11-09, read-only except one call:

- **Not the Anthropic API organization.** lamware's existing keys belong to a separate
  API organization. #724 built Keycloak federation into that organization.
- **Not Amazon Bedrock.** The AWS account with Bedrock lists Opus 5.5, Fable 5.1 and the
  5.5 family in every region, but no Mythos model or inference profile, and rejects the
  Mythos model id. #784 planned Bedrock.
- **Claude Platform on AWS.** The Anthropic-operated service reached through AWS, in the
  owner's other AWS account, has a workspace bound to us-west-2 whose `GET /v1/models`
  lists `claude-mythos-5-1` alongside Fable 5.1 and Opus/Sonnet/Haiku 5.5.
- **One test call** to `claude-mythos-5-1` through that endpoint, SigV4-signed with the
  owner's temporary SSO credentials, returned `end_turn` with a complete `usage` block
  (18 input and 4 output tokens). No static key was involved anywhere.

The service authenticates with AWS IAM. Requests are SigV4-signed for the service
`aws-external-anthropic` at `https://aws-external-anthropic.{region}.api.aws`, carry an
`anthropic-workspace-id` header, and use bare first-party model ids, with API parity
with first-party. It bills through AWS Marketplace in Claude Consumption Units, shown in
Cost Explorer as the service `Claude Platform`.

### Decision

1. **Route.** Frontier eval arms that need CVP access (Mythos 5.1; Fable 5.1 and Opus 5.5
   where the standard safeguards refuse the workload) call Claude Platform on AWS in the
   workspace's region. Production keeps its current route. Eval-only, guarded like every
   frontier arm: no interpret, pipeline or vars setting may name these aliases or models.
2. **Credentials: IAM Roles Anywhere, own CA.**
   - The trust anchor is a small private CA kept off the host, uploaded as a
     certificate bundle. AWS Private CA is not used; it costs about $400 a month for
     nothing this needs.
   - The host holds a short-lived end-entity certificate (days), renewed by a timer. Its
     private key is generated on the host, root-owned, mode 0400, and reaches the signing
     service only through systemd `LoadCredential`. This is the same exception to
     ADR-016 that #724 proposed.
   - `aws_signing_helper` exchanges the certificate for temporary credentials of about
     1 hour, well inside the 12-hour limit.
3. **Least-privilege role.**
   - Its trust policy names only that trust anchor and the certificate's subject.
   - Its permissions:
     - `aws-external-anthropic:CreateInference` and `CountTokens` on the one workspace
       ARN;
     - the two STS actions the gateway needs: `sts:TagGetWebIdentityToken`, and
       `sts:GetWebIdentityToken` conditioned on Anthropic's audiences and
       `aws:CalledViaLast = aws-external-anthropic.amazonaws.com`.
   - No `CallWithBearerToken`: short-term bearer keys are not minted at all.
4. **Signing on loopback, not in LiteLLM.** A forwarder on 127.0.0.1 signs each request
   with SigV4 and forwards it unchanged. It reuses #724's forwarder:
   - the model allowlist, enforced before anything is signed;
   - the check on which local uid is calling;
   - the header allowlist;
   - unbuffered streaming, so `usage` still reaches LiteLLM.

   Only the credential step changes, from a Keycloak token exchange to SigV4. LiteLLM
   points an `eval-*` alias at it with a placeholder key, so nothing in `litellm.env`
   changes.
5. **Spend.** Bounded outside lamware by the workspace spend limit (a hard stop;
   requests fail until the 1st of the next month) and an AWS Budget on the
   `Claude Platform` service that alerts the owner. A budget action can attach a deny
   policy to the role. Inside lamware, the per-run cost caps apply as for every arm.
   The amounts are the owner's to set and are not recorded here. Spend limits lag by
   about 2 hours, and the overshoot is billed.

### Alternatives considered

- **#724, Anthropic-direct WIF from Keycloak:** the organization it federates into has
  no CVP access.
- **#784, Amazon Bedrock:** Mythos is not offered there.
- **Short-term API keys** (minted from IAM credentials, at most 12 hours): compliant,
  but a bearer token on disk is replayable until it expires. SigV4 signs each request.
  Kept as the fallback if the forwarder cannot stream through.
- **Static IAM access keys or long-lived keys:** forbidden by CVP and ADR-016.

### Consequences

- One federation path to maintain: the CA, and certificate renewal on the host. The
  Keycloak client, audience mapper and JWKS upload from #724 are not needed.
- lamware gains a dependency on the owner's AWS Organization for frontier evals only.
  Production analysis does not use this path.
- **Rollback:** disable the role's trust (or the trust anchor) in AWS, stop the
  forwarder and the renewal timer, and remove the aliases. Nothing falls back to a key.
  No data moves.

### Not verified

- **Roles Anywhere end to end** (CA, certificate, signing helper, assumed role): not yet
  built. The test call used the owner's SSO session.
- **Streaming through the forwarder:** SigV4 signs the request, not the response, but
  not yet exercised.
- **Refusal behaviour under CVP** on this route: the test prompt was benign.
- **Pricing:** whether Mythos 5.1 is metered at the first-party list rate ($10 / $50 per
  million tokens) in Claude Consumption Units is not yet confirmed.


---

## ADR-027: The cape account controls its two guests through libvirt, not libvirt itself

**Status:** Accepted, option 2 as amended below (2026-11-14, owner). Implemented 2026-11-14.
**Refs:** ADR-025 (code the pipeline runs is root-owned), #801 (vhost modules), #835 (CAPE rooter)

### Context

CAPE drives its guests through libvirt's system daemon (`qemu:///system`). To let it,
the kvm and qemu-patched roles both put the `cape` user in the `libvirt` and `kvm`
groups. Measured on the host, 2026-11-14:

- **Full control is all-or-nothing.** `libvirtd.conf` sets `unix_sock_group = "libvirt"`,
  `unix_sock_rw_perms = "0770"` and `auth_unix_rw = "none"`. The packaged polkit rule
  `60-libvirt.rules` grants `org.libvirt.unix.manage` to the whole group, and no
  `access_drivers` are configured. So any process running as cape gets the full
  read-write API from a root daemon. That includes defining a domain with a host disk
  or filesystem passed through, network and storage definitions, and raw QEMU monitor
  commands. That is root-equivalent: the standard libvirt-group escalation.
- **CAPE uses a small part of the API.** Its `LibVirtMachinery` (`abstracts.py`,
  `modules/machinery/kvm.py`) calls `open`, `lookupByName`/`lookupByID`, the domain
  listings, `info`/`state`/`isActive`, `XMLDesc`, the snapshot lookups and listings,
  `revertToSnapshot`, `destroy`, `screenshot`, and `coreDump`. It never defines,
  undefines or migrates a domain, and never touches networks, storage or node devices.
- **`coreDump(path)` is a root file write to a caller-chosen path.** libvirtd, running
  as root, creates the dump file at whatever path the client names. Per-task memory
  dumps call it with `storage/analyses/<id>/memory.dmp`. An allow-list of operations
  cannot fix this, because libvirt's access-control checks do not see the path.
- **`kvm` gives direct `/dev/kvm` access**, and with it a host-kernel attack surface (the
  #801 class). CAPE does not need it: under `qemu:///system`, libvirt starts QEMU as
  `libvirt-qemu`, and no CAPE code opens `/dev/kvm`.
- **cape can write the office guest's disk.** `windows11-office.qcow2` is
  `libvirt-qemu:kvm 0775`, and cape is in `kvm`, so cape can plant something in the
  image every later office detonation boots from. The clean guest's disk is `0600`.
- **libvirt's access checks default to "yes".** Every `org.libvirt.api.*` polkit action
  ships with `implicit any: yes`. With access control on, any user no rule matches is
  allowed, so the rules must end by refusing everyone not listed.
- **CAPE calls libvirt from more than the machinery.** Startup checks (`startup.py`:
  domain and snapshot lookups), the QEMU screenshot auxiliary (enabled: `screenshot`)
  and the web console (`web/guac`, `central_guac.py`: `state`, `XMLDesc`; console
  disabled here) all run as cape.
- **The read-only socket is world-accessible.** `libvirtd-ro.socket` sets
  `SocketMode=0666`, overriding `unix_sock_ro_perms = "0770"`. Any local user, the
  pipeline included, can read domain definitions. Low severity on its own.

### Options

1. **Accept.** cape stays root-equivalent, and every cape-reachable bug is a root bug.
2. **libvirt access control (`access_drivers = ["polkit"]`) plus a memory-dump helper.**
   Polkit rules allow cape only the domain permissions CAPE needs (getattr, read,
   snapshot, start, stop, screenshot), only on the named guests, plus the connect-level
   reads. root keeps everything; everyone else gets nothing. `core-dump` is denied, so
   `dump_memory` moves to a root-owned helper. The helper takes only a guest label from
   the allow-list and a numeric task id. It dumps into a root-owned staging directory,
   then copies the file into the task directory **as cape**, so root never writes
   through a path cape controls. This needs one more local CAPE patch, to
   `dump_memory`. cape leaves the `kvm` group.
3. **Rootless libvirt (`qemu:///session` as cape).** No root daemon in cape's path at
   all, and dumps are written as cape. Rejected because it weakens guest containment,
   the primary threat for a malware sandbox. Today `qemu.conf` sets
   `security_driver = "apparmor"`, so each guest's QEMU runs as `libvirt-qemu` under a
   per-VM AppArmor profile, and a guest escape lands confined. A session daemon cannot
   load AppArmor profiles, so QEMU would run unconfined as cape, and an escape would
   reach every analysis and CAPE's credentials. It also keeps `/dev/kvm`, and needs
   `qemu-bridge-helper` made privileged (it is not setuid here) to attach to
   `virbr-det`. Both guest disks, one with an external snapshot chain, would have to
   move into cape's ownership. Otherwise: But the detonation network, the rooter, the AppArmor/sVirt confinement and the
   bridge are built around the system daemon. Session networking needs the setuid
   `qemu-bridge-helper`, and cape would keep `/dev/kvm`. This is the largest change, and
   it keeps the kernel surface.
4. **A root VM-control daemon with a narrow API**, with CAPE patched to call it for every
   operation. The same boundary as option 2, with more code we own and a larger CAPE
   patch.

### Decision (proposed)

**Option 2**, done in this order, each step measured:

0. **Audit first.** Enable the ACL with a rule that only logs each action cape (and any
   other non-root user) triggers, with domain names, and decides nothing, so the
   defaults still allow. Then CAPE's real call sequence, including one operator-run
   detonation, yields the exact permission set. The enforcing rule is written from
   that log, not from documentation.
1. **Spike on the host, with nothing detonated.** Enable the ACL with rules for cape.
   Run CAPE's exact call sequence against the `clean` guest:
   lookup, snapshot listing, revert, screenshot, destroy. Those must succeed. Each of
   these must be refused: `defineXML`, `qemuMonitorCommand`, `coreDump`, network and
   storage writes, any other domain name, and a read-only-socket call by the pipeline
   user. The operator starts and stops the guest, because a running guest is the
   operator's call. Not yet measured: which permissions `revertToSnapshot` needs (it
   may need `write` as well as `snapshot`). The spike decides that.
2. **Memory-dump helper and CAPE patch.** Proven by one operator-run detonation with
   `memory=1`: the dump arrives, is owned by cape, and Volatility reads it.
3. **Remove cape from `kvm`** in both the kvm and qemu-patched roles. cape **stays in
   `libvirt`**: with `auth_unix_rw = "none"` the group is now only what lets cape reach
   the read-write socket, and the ACL decides what it may do there. Set the office
   disk to `0600`, like the clean one. Then check that cape's group list is exactly
   what CAPE needs.
4. **A security-test check.** As cape, a call that must be refused is refused and a call
   that must succeed succeeds (the control). As cape, `/dev/kvm` cannot be opened.

### Spike results (2026-11-14)

- **Audit mode must allow explicitly.** 75 of the `org.libvirt.api.*` actions default
  to `no` (snapshot, start, stop, screenshot, write, core-dump, ...). With
  `access_drivers` on, those defaults apply to every caller, root included. The first
  audit rule decided nothing, so CAPE's revert was refused: task 1312 failed on both
  guests, and CAPE then dropped both machines from its table until restarted. The
  working audit rule allows root and cape explicitly and logs through `logger`. Ubuntu
  runs polkitd with `--no-debug`, which drops `polkit.log()`.
- **CAPE's complete permission set**, from startup, the read-only calls and one
  detonation (task 1313, normal result): `connect.getattr`, `connect.search-domains`,
  and `domain.getattr`, `read`, `screenshot` (about one a second), `snapshot` (revert to
  a running snapshot; no `start`) and `stop`. No `write`, `start` or `core-dump`. No other
  user touched libvirt during the run. The pipeline user reads domains over the
  read-only socket.
- **`domain.snapshot` is a root file write.** Revert and create share this one
  permission. On a throwaway VM, cape asked for an external memory snapshot whose file
  was an existing root-owned 0600 file in a root-only directory. libvirtd (root)
  overwrote it with about 39 MB of saved VM state before the snapshot failed on its disk
  overlay. AppArmor did not block it. New memory files were created and then removed on
  failure. Disk overlays failed, because QEMU runs as `libvirt-qemu`, confined. libvirt
  refused an existing file as an overlay.

**Amended decision.** polkit gives cape only `connect.getattr`,
`connect.search-domains` and `domain.getattr`/`read`/`screenshot`/`stop` on the named
guests. None of these takes a path. Snapshot revert goes through a root-owned helper
(`lamware-vm revert <guest>`) that accepts only an allow-listed guest and a snapshot
that already exists, and can neither create a snapshot nor name a file. CAPE's revert
call is patched to use it through sudo. That makes one local CAPE patch, not the
memory-dump one. `core-dump` is refused: full-VM memory dumps are not supported, and the
dump helper is the documented route back if they are ever needed (issue to be filed
after deploy). Once the change is enforced, the new security-test check also confirms
CAPE still has both machines loaded, because a missing permission makes CAPE drop them.

### As built (2026-11-14)

- **kvm role:** installs `/etc/polkit-1/rules.d/49-lamware-libvirt.rules` (root: all;
  cape: the measured set on the guests named in `cape_guests`; everyone else: no),
  then sets `access_drivers`. It restarts libvirtd only when no guest is running, then
  proves an allowed and a refused call as cape. It takes cape out of `kvm` and
  restarts CAPE's services **and cape's systemd user manager**. cape lingers, so the
  manager runs from boot and passes the group to everything it starts. The first
  deploy missed it, and check 19 caught it.
- **cape role:** root-owned `/usr/local/sbin/lamware-vm revert <guest> <snapshot>`,
  which accepts only each configured guest's configured snapshot. A sudo rule for that
  command only. Local patch 0004 makes `LibVirtMachinery.start` call it.
- **cape-guests and qemu-patched:** the image directory is `root:root 0711`; the
  cape-guests role had it as `cape:cape 0755`, and the two roles flipped it
  0755/0711 on every deploy. Base images are `0600`.
- **security-test check 19:** probes as cape. One allowed call is the control; network
  listing must be refused by the rule; `/dev/kvm` must not open; no cape process may
  hold `kvm`; the pipeline user may not read libvirt; CAPE must have every guest
  loaded; nothing in the image directory may be group- or world-writable. It failed
  before the role changes and passed after.
- **Proof:** a detonation under the enforced rule (task 1316) completed in the
  sample's best observed tier, with no refusal and one helper revert.
- **Not part of this ADR:** CAPE logs at every start that it cannot reach the rooter
  socket. That predates this work (seen at the first boot of the day) and is tracked
  separately.

### Correction (2026-11-15): cape was still root at reboot

"cape loses root-equivalence through libvirt" held for libvirt, but cape was still
root-equivalent another way. CAPE's installer leaves `@reboot cd /opt/CAPEv2/utils/ &&
./smtp_sinkhole.sh` in root's crontab, and cape owns that tree. Found by an
adversarial review; fixed by removing that line and two other dead cape2.sh lines. A
new security-test check (root's cron jobs run and name only root-owned,
root-only-writable paths) guards the class.

### Correction (2026-11-15): memory dumps were in use

The amended decision above says full-VM memory dumps were not used. That was wrong.
The pipeline's code default is `cape_memory_dump: False`, but the deployed pipeline
config sets it to `True`. So production `run-pipeline` submissions request `memory=1`,
and the Volatility stage reads the dump. The claim came from the code default and from
`make detonate`, which refuses `memory`, instead of from the deployed config. After
#844, CAPE's `coreDump` was refused, and CAPE logs that and carries on, so Volatility
would have silently had no input. No pipeline run happened in that window.

**Fix (#845):** `lamware-vm dump <guest> <task-id>`, now a Python helper (stdlib only,
`python3 -I`). It accepts a configured guest and a numeric task id, and no path.
libvirtd writes into a root-only staging directory on the same filesystem. The helper
gives the file to cape: owner, mode 0640, and the task folder's default ACL, which a
renamed file would not inherit and which is how the pipeline reads it. It then renames
the file into `<analyses>/<id>/memory.dmp` through directory handles opened without
following links, after checking the folder is cape's. Local CAPE patch 0005 makes
`dump_memory` call it. The cape-role cron that deletes dumps after 60 minutes runs as
cape, so it still reclaims them.

**Proven:** a pipeline run with `memory=1` (task 1317). The dump arrived through the
helper as an 8,606,523,139-byte ELF image, `cape:cape 0640` with `group:lamware:r--`,
and Volatility read it. Staging was empty afterwards, with no refusals.

### Consequences

- cape loses root-equivalence through libvirt. A compromise of CAPE's web, processing
  or machinery code then reaches only the two guests.
- **One more local CAPE patch** (the third). It must be re-applied on CAPE upgrades and
  checked by the role, like the existing two.
- **Other users are refused explicitly.** That includes the pipeline on the read-only
  socket, which closes the world-readable domain definitions too.
- **The ACL governs root too.** The polkit rule must allow uid 0 everything, or Ansible
  and the operator lock themselves out of libvirt. Restarting libvirtd with the ACL
  enabled is the risky moment, so it happens with no guest running.
- The kvm role is console-gated (CLAUDE.md §7a), so the operator deploys steps 1 and 3.

### Rollback

Remove `access_drivers` from `libvirtd.conf` and restart libvirtd with no guest running.
That restores the group-based model at once. Put the group memberships back if they
were removed. Revert the CAPE patch. No data moves.

### Not yet known

- The exact permission set CAPE's sequence needs (step 1 measures it).
- Whether the guacamole/VNC console path in CAPE's web UI uses libvirt. It is not in
  the machinery's call list; the spike checks it.

---

## ADR-028: CAPE's rooter is not run; lamware's own firewall is the guests' network boundary

**Status:** Accepted (2026-11-15, owner). Implemented 2026-11-15.
**Refs:** ADR-020 (one firewall mechanism), ADR-027, #459 (INetSim DNS), #708 (guest-input chain), #835 (rooter root-owned copy)

### Context

CAPE's rooter (`utils/rooter.py`, unit `cape-rooter`) is a root daemon. CAPE's scheduler sends it commands over a Unix socket, and it applies per-VM iptables and routing for each analysis. Measured on 2026-11-15:

- **CAPE could not reach it.**
  - The socket is `root:cape 0620`; the rooter is started with `-g cape`, by upstream's unit and by #835's.
  - CAPE's services run with `Group=lamware` (`cape.service.d/lamware-group.conf`, dated 2026-05-15). systemd then derives their supplementary groups from `/etc/group`, which does not list cape's own primary group `cape`. The scheduler's groups were `pcap lamware systemd-journal libvirt`.
  - So every rooter call since about 2026-05-15 failed with `Permission denied`. CAPE logged it as `CRITICAL` and carried on.
- **What the rooter would do here.** With `route = none` (set since 2026-04-01), CAPE asks it for `drop_enable`, which drops every packet the host sends to the guest except the CAPE agent (port 8000) and result-server replies. That includes INetSim's replies.
- **The guests depend on INetSim.** INetSim's DNS only started working with #459 (2026-08-25). In task 1316, the sample's DNS lookup was answered by INetSim, and 99 TCP flows went to it. Every detonation since August, including every evaluation baseline, used a network where the guests reach INetSim *because* the rooter was unreachable. Repairing the socket alone would reintroduce the #459 failure.
- **Containment does not come from the rooter.** It is lamware's own firewall: the guest-input chain (#708) and the detonation air gap, both probe-tested by the security test.
- **CAPE does not need it to start.** `init_rooter` returns early when `route = none` and VPN, Tor, INetSim and socks5 routing are all disabled, which they are.

### Options

1. **Don't run it.** Make the measured state official: stop and mask the rooter, remove #835's copy, and accept CAPE's per-task "rooter unreachable" log line as expected. This removes one root daemon that takes cape's commands, and changes no detonation.
2. **Fix the socket group and switch to CAPE's `inetsim` route.** CAPE would then redirect **all** guest traffic to INetSim, including connections to arbitrary IPs, which the firewall now drops. That might be a more realistic simulated network, but it changes results, so under consistency-first it needs a measured before/after on the eval corpus first.
3. **Fix only the socket group.** Breaks INetSim (the #459 failure). Rejected.

### Decision

**Option 1.** The cape role stops, disables and **masks** `cape-rooter`, so a CAPE upgrade that re-enables it fails instead of quietly bringing it back. It removes `/opt/cape-rooter`, the staging directory, the unit's drop-ins and the stale socket. The network-monitor allowlist no longer accepts a rooter process. Security-test check 15 requires the unit to be masked and inactive, no rooter process, and no socket, with a control that a known unit loads. Option 2 is filed as an investigation, not a change.

### Consequences

- One fewer root daemon accepting input from cape; #835's concern (root running cape-controlled code) goes away entirely.
- CAPE logs that it cannot reach the rooter at each task. That is expected and documented, not silenced: silencing it would take another local CAPE patch.
- The `Group=lamware` drop-in stays: the pipeline reads CAPE's output through that group's ACLs.
- Detonation behaviour is unchanged. The proof is a detonation whose network picture matches task 1316: DNS answered by INetSim, flows to 192.168.100.1.

### Rollback

`systemctl unmask cape-rooter` and redeploy the cape role from before this change. For the rooter to actually work, the socket group would also have to change. As shown above, that changes every detonation's network, so it is option 2, not a rollback.

---

## ADR-029: CAPE captures packets through a root helper, on the detonation bridge only

**Status:** Accepted (2026-11-15, owner). Implemented 2026-11-15.
**Refs:** ADR-027 (the same pattern for libvirt), #711 (capture without sudo)

### Context

CAPE's sniffer runs tcpdump for each analysis. #711 replaced cape2.sh's `sudo tcpdump` rule (root with any arguments) with file capabilities on `/usr/bin/tcpdump` for a group only cape was in. Capabilities apply to every invocation, so cape could capture on any interface, not just the detonation bridge. Loopback carries nginx's traffic to its upstreams and every call to the LLM router, in clear text.

Measured on the host (2026-11-15):

- CAPE's sniffer (`modules/auxiliary/sniffer.py`) uses sudo whenever `sudo --list <tcpdump>` succeeds. It passes a fixed argument shape with `-Z <its user>`, and stops the capture by signalling sudo's child process. The tcpdump path comes from `auxiliary.conf`.
- tcpdump opens its `-w` file as root, before it drops to the `-Z` user. A test capture into a root-only directory succeeded. The task directory is cape's.
- With `Defaults use_pty` (Ubuntu's default), sudo's child is a root monitor process, which CAPE cannot signal.
- `/proc` is mounted `hidepid=invisible`. CAPE finds the process to stop with `ps --ppid <sudo>`, run as cape. A process that changed uid, or holds a capability cape lacks, is invisible to cape. The first version of the helper ran tcpdump as root with `-Z cape`. In detonation 1319, CAPE logged `Failed to get child pid of sudo process to stop the sniffer`, and the capture kept running after the analysis.

### Decision

The same shape as ADR-027's `lamware-vm`:

- **The helper.** `/usr/local/sbin/lamware-capture` is root-owned and runs Python with `-I`. It accepts only the sniffer's argument shape, the detonation bridge, `-Z cape`, and `<analyses>/<task>/dump.pcap`. Every filter element must be words, addresses, ports, parentheses and spaces.
- **How it runs tcpdump.** The helper opens the pcap itself with cape's permissions, without following links, and passes it to tcpdump as stdout (`-w -`). It puts the filter after `--`.
- **The process shape follows from how CAPE stops it.**
  - tcpdump runs as cape holding only `net_raw` and `net_admin` (`setpriv`, ambient), as a child of the helper.
  - The helper then drops to cape for good, with no capabilities and with the **gid sudo was called with**, and marks itself dumpable, so CAPE can see it. hidepid compares gid as well as uid. CAPE's units run as cape with `Group=lamware`, so a helper with cape's primary gid was still invisible to CAPE. Detonation 1320 showed this, after probes run as `sudo -u cape` had passed. The gid is used only if it is one of cape's groups.
  - It forwards CAPE's signal to tcpdump. Signalling depends only on uid, so the signal reaches tcpdump even though cape cannot see it.
- **sudo.** cape may run the helper and nothing else new; `!use_pty` is set for this one command, so CAPE can still stop the capture. `auxiliary.conf`'s `[sniffer] tcpdump` points at the helper.
- **What is removed.** tcpdump loses its capabilities, its statoverride and the apt hook that re-applied them. The `pcap` group is removed.
- **Security-test check 23** probes it:
  - each service user tries to capture on `lo`, and must fail;
  - root doing the same is the control that the probe can see a capture;
  - the helper must refuse `lo`, must capture on the bridge, and must be stoppable the way CAPE stops it: as cape with CAPE's unit group, through `ps --ppid`.

### Consequences

- Packet capture is root's alone. cape can capture the detonation bridge only, into a task's own `dump.pcap`.
- A CAPE upgrade that changes the sniffer's argument shape makes the helper refuse it. The result is an empty pcap and a refusal in CAPE's log; the role's deploy-time probe catches it at the next deploy.
- No local CAPE patch is needed.

### Rollback

Revert and redeploy the cape role. The old capture-privileges tasks re-create the `pcap` group, the statoverride and the capabilities, and the sniffer goes back to `/usr/bin/tcpdump`.

---

## ADR-030: Every LiteLLM caller has its own scoped key; the master key stays in LiteLLM's files

**Status:** Accepted (2026-11-16, owner). Implemented 2026-11-16.
**Refs:** #238 (no default key), #854 (scoped keys), CLAUDE.md §10 (usage tracking)

### Context

LiteLLM's master key administers the proxy: it creates keys, reads every caller's spend, and changes the proxy's configuration. It was rendered into the interpret wrappers (readable by four service accounts), the digest and the API's environment. #854 replaced it with scoped keys at the call sites it found.

It missed one: the API sends `settings.litellm_key` from two places, the spend router and the investigation agent. #854 made that setting a read-only spend key, which LiteLLM refuses for every model call, so the agent lost access to its models. The enumeration was a grep whose output was cut at 60 lines.

### Decision

- The master key is rendered only by the litellm role. Security-test check 24 searches the host by content and fails on any copy outside LiteLLM's install directory.
- Every caller gets its own key, created by the litellm role (`litellm_scoped_keys`, managed by `lamware-litellm-keys`), scoped to what that caller does:
  - `interpret`: every model;
  - `digest`: the summary model;
  - `investigate`: the agent's `MODEL_COSTS`;
  - `api-spend`: a read-only admin viewer that can call no model.
- **One setting per key, never one setting shared by two callers.** A test enumerates every `Bearer {settings.litellm_*}` the API sends and requires each one to be written from a scoped key. A test also keeps the investigate key's models equal to `MODEL_COSTS`.

### Consequences

- A new caller needs a new key spec and its own setting. Reusing an existing one fails a test.
- LiteLLM attributes usage to each key's alias, alongside the per-call usage lamware already records (§10).
- Rotating the master key no longer touches any caller.

### Rollback

Revert and redeploy `litellm` and `api`. Keys left in LiteLLM's database stay valid until deleted by alias.

---

## ADR-031: The `lamware` group is narrowed in measured phases, starting with cape

**Status:** Accepted (2026-11-17, owner). Phase 0 done (2026-11-20); phase 1 deployed 2026-11-22.
**Refs:** ADR-025 (root-owned code), ADR-030 (one key per caller), #850, #854 (both exposures through this group)

### Context

`lamware` has four members: `pipeline`, `lamware-api`, `cape` and `auto-feeder`. The roles grant it access about 150 times across 20 roles: read access to the analysis tools' code, the pipeline's results, CAPE's output (through a default ACL), the MOTIF corpus and the notifier, and **write** access to four rendezvous places (the spool, the control directory, the auto-feeder's state and the sample-feeder's seen-hash file).

Because one group carries every flow, each member gets the union of all of them:

- **Reading:** #854 (a LiteLLM key in a file shared for one reader) and #850 (the ntfy topic) were both this.
- **Writing:** the open feeder- and spool-state findings are this.
- **cape is the account that handles guest-controlled data, and it's in all of it,** although it needs only to write its own results.

A one-shot regrouping would change every one of those grants at once. When a read breaks here, nothing crashes: the report just comes out thinner. That is the failure mode this project keeps meeting, and a big change would invite it.

### Decision

**The rule:**

- A group grants one data flow, and its members are that flow's writer and readers.
- cape is a member of no group it doesn't write for.
- A file holding a secret is never readable by a group whose members don't use that secret.
- Readers open shared rendezvous files with `O_NOFOLLOW` and a regular-file check.

**The method:** phases, each one PR, each done and verified in one sitting, with the host left stable between them.

- **Phase 0, measure (no permission change):**
  - Record which account actually opens what under the group's trees, over several days of normal use: `scripts/flow-measure/` (fatrace, installed for the measurement and removed after).
  - Build a use-case check that compares the *shape* of real outputs (a detonation's report, the API's paths, the CAPE UI) against a recorded baseline.
- **Phase 1:** cape leaves `lamware`. Access it still needs is granted explicitly first; its membership is removed second.
- **Phase 2:** the spool and the feeder state get two-member groups, and their readers get `O_NOFOLLOW` (the open feeder- and spool-state findings).
- **Phase 3, a decision rather than a commitment:** whether narrowing read access to code and retiring `lamware` is still worth it. After #850 and #854 the code holds no secrets.

**Each phase:**

- adds access before it removes any;
- passes only if the use-case check matches its baseline;
- has a one-line rollback (re-add a membership or a grant).

### Consequences

- The measured access map (phase 0) replaces the grant inventory as the source of truth. It's attached to this ADR when the measurement ends.
- Slower than one migration, by design. Earlier changes of this size took days of fixes after they merged.

### Phase 0 result (2026-11-17 to 11-20)

fatrace ran for 3.8 days (95 hourly snapshots), recording every non-root open, read and write under the group's trees. In that window:

- **cape:** its own processes (CAPE's Python, tcpdump, its CLI) touched only cape's trees: `/opt/CAPEv2/storage` (all of its writes) and `/home/cape/.cache`. Every cape access that needed `lamware` was `find`, which is the security test's probe that cape cannot write code.
- **pipeline:** writes its reports and harvest files. Reads CAPE's analyses (through the storage ACL), the tools' rules and symbols, and its own code and venv. Its containers (a subordinate uid) read the same.
- **lamware-api:** read the auto-feeder's state. **lamware-notify:** read its own code.
- **Limits:**
  - 37% of kept events came from processes that exited before they could be attributed;
  - the window held one detonation, and no feeder or intake runs.
  - The use-case check and a detonation after each phase cover what the measurement could not see.

### Phase 1 (2026-11-22): cape leaves `lamware`

- **Nothing had to be granted first:** the measurement found no access cape needed through the group.
- **The membership is removed by the cape role, before CAPE restarts.** systemd gives a service its user's groups when it starts, so a removal in a later role would leave CAPE running with them.
- **CAPE's two units now run `Group=cape`.** They ran `Group=lamware`, which kept the group whatever the membership said.
- **The pipeline's read path is unchanged:**
  - the storage ACL (`group:lamware:r-x`, inherited by new analyses);
  - the setgid `lamware` group on the analysis directories, which a file's creator gets whether or not it is a member.
- **Security-test check 27:**
  - cape isn't a member;
  - no running cape process carries the group, primary or supplementary;
  - the pipeline can still read the newest analysis (the control);
  - at least one cape process exists (otherwise the probe is blind).

### Rollback

Each phase reverts by redeploying the previous commit. No phase removes the `lamware` group itself.

---

## ADR-032: Root containers use lamware-container: podman's AppArmor profile plus upstream's stacked-peer fix

**Status:** Accepted (2026-11-16, owner). Temporary, until noble's podman ships the fix.
**Refs:** #842 (LiteLLM never starts on kernel 7.0.0-43), container-libs PR #919 (merged 2026-11-06), containerd #14485, moby #54099

### Context

On kernel 7.0.0-43, LiteLLM never starts serving. The host has been pinned to -38 since 2026-11-14, so newer kernels, security updates included, install but don't boot. Measured over three test boots of -43 on 2026-11-16:

- **Prisma's migration step finishes,** printing "No pending migrations to apply.", then sends SIGTERM to its schema engine. **The kernel refuses the signal** (`kill … = -1 EACCES`) and logs nothing, so the engine waits on stdin forever, the CLI waits for it, and LiteLLM waits for the CLI.
- **Inside any root container that uses podman's default profile, a process cannot signal its own child on -43;** on -38 it can. Userspace is identical on both boots (podman 4.9.3, AppArmor parser 4.0.1, the same profile). The one difference is the label: `containers-default-0.57.4-apparmor1` on -38, `containers-default-0.57.4-apparmor1//&unconfined` on -43.
  - Ubuntu's `kernel.apparmor_restrict_unprivileged_unconfined=1` (set by Ubuntu, on both kernels) now makes the kernel stack the container profile with `unconfined`.
  - podman 0.57.4's template allows signals only to `peer=<its own name>`, which the stacked label doesn't match.
- **Not the cause:** the BPF LSM (-43 hangs with it removed from `lsm=`), and kernel futex or epoll wakeups (every waiting thread is consistent).
- **The same failure is reported for containerd, Docker, k3s, Incus and CRI-O.** Upstream podman fixed it in container-libs PR #919 by adding `peer=<name>//&*` signal and ptrace rules. Noble's podman 4.9.3 won't have that fix unless Ubuntu backports it.
- **The pipeline's rootless containers are unaffected:** rootless podman applies no AppArmor here, and their labels read `unconfined`.

### Options

1. **Stay pinned to -38 until Ubuntu backports #919.** No customization, but no kernel security updates for an unknown time.
2. **Run root containers with `apparmor=unconfined`.** This removes confinement and conflicts with SECURITY_CONSTRAINTS. Rejected.
3. **Turn off `apparmor_restrict_unprivileged_unconfined`.** This disables an Ubuntu hardening restriction. Rejected.
4. **Carry podman's own profile with upstream's fix applied, until Ubuntu ships it.**

### Decision

**Option 4.**

- **The profile:** `lamware-container` (`ansible/roles/podman/files/`) is containers/common v0.57.4's template, rendered with that name, plus exactly the four lines of #919 (two rules and their comments). A test renders the vendored template and requires the profile to match line by line.
- **How it's applied:** a `containers.conf.d` drop-in makes it root podman's default. Every root container (LiteLLM, llama-cpp, Keycloak) gets it without a flag, and rootless podman skips it.
- **Security-test check 26:**
  - the profile is loaded;
  - every running root container is under it;
  - a fresh root container can signal its own child;
  - podman is still 4.9.3.
  - It also reports whether podman's built-in profile delivers signals on the running kernel.

Measured on -43 with the profile loaded: a container's process signals its child, LiteLLM serves within about 20 seconds, and the confinement probes (sysrq write, mount) are denied as under the built-in profile. Measured on -38: no difference from the built-in profile.

### Consequences

- **The kernel pin can be removed as a separate step:** one more -43 boot with this deployed, LiteLLM serving within a minute, then the pin is deleted.
- **One file we carry.** Any podman upgrade fails check 26: remove the copy if the new podman has #919, re-derive it if not.
- **The rules match `//&*`, as upstream's do,** rather than only `//&unconfined`. That is slightly broader, but it's the rule upstream reviewed, and the one we'd be running after a backport.

### Exit

Delete the profile, the drop-in and check 26's version clause once noble's podman ships #919's rules. Check 26 reporting "podman's own profile also delivers signals" on a stacking kernel is the sign.

### Rollback

Revert and redeploy `podman`. The drop-in disappears, and the root containers go back to podman's built-in profile at their next start. On a -43 kernel that brings back the LiteLLM hang, so roll back only while pinned to -38.

## ADR-033: LiteLLM reaches the Claude API through Workload Identity Federation; no API key on the host

**Status:** Proposed (2026-11-19).
**Refs:** ADR-030 (scoped LiteLLM keys), ADR-025 (root-owned code), Claude API docs: Workload Identity Federation

### Context

LiteLLM's Anthropic entries authenticate with two long-lived workspace API keys from the vault: production (`ANTHROPIC_API_KEY`) and the spend-capped eval workspace (`ANTHROPIC_RESEARCH_API_KEY`). The keys sit in LiteLLM's env file and never expire, so a copy taken from the host works until someone notices and revokes it.

An expiring key only moves the problem. A workspace key can be given an expiry, but a short one means rotating it by hand on a schedule, and a missed rotation stops every cloud call at once.

The Claude API supports Workload Identity Federation: a workload presents a JWT from an identity provider the organization trusts and receives an access token that lasts minutes. The issuer can be registered with **inline** public keys. Anthropic then never contacts the issuer and compares its URL with the JWT's `iss` as a string, so the issuer can be the host itself.

### Decision

**The host is its own identity provider, and a loopback forwarder does the exchange.**

- **The key:** an EC P-256 signing key generated on the host once, root `0600` in `/etc/anthropic-wif`. Its public half (`jwks-public.json`, derived on every deploy) is registered as a federation issuer with inline JWKS. The private key never leaves the host.
- **The forwarder** (`ansible/roles/anthropic-wif`, its own system user, the same hardened unit and proxy core as the existing loopback forwarder):
  - mints a fresh ES256 JWT for each exchange: unique `jti` (the issuer enforces single use), a 15-minute `exp`, a fixed `sub` and `aud` that the federation rule matches exactly;
  - exchanges it at `POST /v1/oauth/token` for a token scoped to one workspace, caches that in memory only, refreshes 120 s before expiry, and keeps serving the cached token if a refresh fails until 30 s before expiry;
  - forwards only `POST /v1/messages` and `/v1/messages/count_tokens` from allowlisted local uids, drops the caller's `x-api-key` and `authorization`, adds `Authorization: Bearer`, and streams responses unchanged, so the `usage` block still reaches LiteLLM (CLAUDE.md section 10).
- **Production and eval stay separate.** Each workspace is its own *route*: its own loopback port, model allowlist and token. A model may be on only one route, and the forwarder refuses to start otherwise. A request for an eval model on the production port is refused before any exchange, so production traffic cannot bill the eval workspace, as the separate keys guaranteed before.
- **LiteLLM switches per route** with `litellm_anthropic_wif_routes`. A listed route's entries (production: the analyst models and haiku-fallback; eval: the eval-\* arms) point at the forwarder with a placeholder key, and that route's key is left out of the env file. A route becomes active in the forwarder when its workspace id is set, so the two workspaces can move separately. With the list empty, the rendered config is unchanged from before this ADR (tested).
- **The forwarder-only eval arms** (`eval-mythos`, `eval-mythos52`, `eval-fable52`) moved from ADR-026's forwarder to the eval route (2026-11-19). They are not switched by `litellm_anthropic_wif_routes`: they always point at the eval route, so they never fall back to a key in any configuration.
- **The federation rule** has scope `workspace:developer`, the same access a workspace key has; the Console offers no narrower scope for a rule. Token lifetime is 600 seconds, and the rule is enabled only for the workspaces its routes use, each of which has the service account as a member.
- **The ids** (organization, rule, service account, workspaces) are identifiers, not secrets, but they are the owner's. They live in the gitignored `ansible/vars/main.yml`.
- **Health:** a daily check (and one at every deploy) does, per route, a token exchange and a free `count_tokens`, and alerts through ntfy on failure.

### Consequences

- **No long-lived Anthropic credential is on the host.** A stolen access token works for at most 10 minutes, in one workspace. The signing key is now the long-lived secret, but it is generated on and never leaves the host, and it's useless without the rule and organization id, which also have to match.
- **The key is the issuer.** If the host is rebuilt or the key is lost, generate a new one and register its JWKS. Exchanges fail until then, and the daily check says so.
- **Rotation is manual (inline mode).** Add the new key to the issuer's JWKS, deploy with the new `anthropic_wif_key_id`, then remove the old key. Nothing expires, so there's no schedule to miss.
- **A new failure mode:** if the exchange endpoint is unreachable, cloud calls fail once the cached token expires (at most 10 minutes). Automated runs are local by policy, so this affects analyst and eval calls, not the pipeline.

### Rollback

While the workspace keys still exist: empty `litellm_anthropic_wif_routes` and deploy `litellm`. LiteLLM is back on the keys, and the forwarder can stay up unused. After the keys are deleted, rollback means creating new workspace keys first. Turning off `anthropic_wif_enabled` alone stops cloud calls.

## ADR-034: The old loopback forwarder is retired; its eval arms use the Workload Identity Federation eval route

**Status:** Proposed (2026-11-20).
**Refs:** ADR-026 (superseded), ADR-033, #864, #865

### Context

ADR-026's loopback forwarder gave three eval arms a route to the eval workspace with no static key, using short-lived cloud credentials from a certificate issued by a CA on the controller. ADR-033 then gave the eval workspace a federated route with no key at all, and #865 moved those three arms to it, after confirming the workspace lists their models and that a call on each returns 200.

Since #865 nothing points at the old forwarder: no LiteLLM entry, and no forwarded call in the 24 hours before this change. Its host certificate was four days from expiry, and keeping it would mean renewing a certificate and a second credential path to the same workspace, with no caller.

### Decision

**Retire it.** The `claude-platform-aws` role becomes teardown-only, as the Ollama role did (#818):

- stop and disable the service and its daily check, clear their failed state, and remove the four unit files;
- remove `/opt/claude-platform-aws` (the forwarder and its credential helper) and `/etc/claude-platform-aws` (config, host key and certificate);
- remove the `claude-aws` user and group;
- assert that nothing listens on port 4010 afterwards.

A test pins the role to removal only: no task may start, enable or install anything, and it has no handlers, templates or files.

### Consequences

- **One credential path to the eval workspace,** ADR-033's, which every eval arm now uses.
- **The cloud-side resources and the controller's CA are the owner's to delete.** Nothing on the host references them after the teardown.
- **Security-test check 17** now watches the `anthropic-wif` service user in place of the removed one.

### Rollback

Revert this change and #865, restore the cloud-side resources and the CA, and redeploy `claude-platform-aws` and `litellm`. Once the owner deletes the cloud-side resources, rollback means recreating them.

## ADR-035: The nightly AIDE run absorbs only detonation, reboot and container-runtime differences

**Status:** Proposed (2026-11-20). The owner chose re-baselining after detonations, run nightly, with `/etc` content changes from libvirt accepted.
**Refs:** #867 (the `/dev/null` finding), `ansible/roles/hardening/files/lamware-aide.py`, `expected-differences.conf`

### Context

A deploy and an apt run each renew the AIDE baseline, so a nightly difference is meant to be a change neither of them made. In practice every detonation night and every reboot also produced differences: CAPE's logs, the guest's libvirt and swtpm state, the per-VM AppArmor profile, and everything under `/run`. So the high-priority alert fired almost every night.

From 11-16 to 11-19 it reported `/dev/null` changing owner (#867, a real finding) among dozens of expected entries, and nobody acted on it.

Two fixes were considered:

- **Excluding those paths from AIDE.** This hides two `/etc` entries and every attribute of the excluded paths, owner and mode included.
- **Re-baselining after each detonation.** This absorbs *everything* that changed during the detonation, which is exactly when malware escaping the guest would change the host. There is also no single hook: detonations start from three front doors and CAPE's API, and the root VM helper sees each task's revert, not its end.

### Decision

**The nightly run absorbs differences only when every one of them is expected, judged per path and per attribute.**

- **One scan.** `lamware-aide check` runs `aide --update`, which reports the differences and writes a new database from the same scan. A check followed by a separate rebaseline would absorb, unseen, anything changed between the two scans (a scan takes about 7 minutes).
- **Classification.** Each Added, Removed or Changed entry is checked against `/etc/lamware-aide/expected-differences.conf`. Rules are `allow|deny SECTIONS LETTERS REGEX`, and the first match wins. For an allowed Changed entry, only the listed attributes of AIDE's summary string may change.
  - No rule allows the type, mode, owner, ACL, xattr, SELinux, ext2-attribute or capability bits to change.
  - The one exception is the group of CAPE's two live logs: each day's file is created by whichever CAPE process rotates it first, and they run with different groups.
- **The rules come from evidence:** the 30 reports kept on the host (11-04 to 11-20). Each rule names what was seen.
  - A detonation: CAPE's logs, the staged sample, the guest's overlay images, snapshot, nvram and swtpm state.
  - Libvirt's rewrite of `/etc/libvirt/qemu/clean.xml` and of the per-VM AppArmor profile: contents and times only. The owner accepted this as the one weakening.
  - A reboot: `/run`, postfix's chroot copies (never their contents), udev's disk links, cloud-init's state (never its user data or scripts), the NVMe nodes that swap names between boots, and rotated `dmesg` logs.
  - A **new** file where systemd reads runtime units is never absorbed, except podman's per-container scopes.
- **Outcomes:**
  - **All expected:** the new database becomes the baseline, with a low-priority line.
  - **Anything unexpected:** a high-priority alert lists only the unexpected entries, the new database is discarded, and the old baseline stays, so the alert repeats every night until a person rebaselines.
  - **Fail closed:** a report whose parsed entries don't add up to AIDE's own counts, or a missing or malformed rules file, is treated as unexpected. The deploy runs `lamware-aide rules` and fails on a malformed file.

Replayed over the kept reports, the nightly checks behave as intended:

- **11-19:** its 30 detonation entries are absorbed, and the alert names `/dev/null`.
- **11-16:** the 888 boot-noise entries are absorbed, and it still alerts on 87 real changes made that day.
- **11-18 and 11-20:** they alert only on ADR-031's temporary measurement in `/root/flow-measure` (and a digest file this change also excludes).

### Consequences

- **A night with a detonation or a reboot and nothing else is quiet.** One new kind of difference wakes the alert, and keeps it awake until a person looks.
- **The rules file is now security-relevant.** It lives under `/etc`, so AIDE watches it. A deploy changes it, and the deploy rebaselines.
- **A change libvirt could make to the domain XML's contents is absorbed.** Its owner and mode are not.
- **New noise must be explained before it is allowed.** It is an alert until a rule names it.

### Rollback

Revert and redeploy `hardening`: `check` goes back to `aide --check`, alerting on every difference.

## ADR-036: A run chooses its LLM backend by explicit profile; automated runs stay local by default

**Status:** Proposed (2026-11-23). Extended by ADR-038 (proposed): `local` stays the default, and the operator may also change the automated default, not only choose a cloud model per run.
**Refs:** `tests/test_automated_runs_stay_local.py`, ADR-033 (the eval route), ADR-031 (permission phases), `scripts/usecase-check/coverage-corpus.json`

### Context

The pipeline's LLM stages use the models set at deploy time: the agentic RE stage, its escalation model, and the executive and plain-English summaries. All are local by policy, because the pipeline runs unattended on decompiled malware and nothing automated may send that to a cloud model on its own.

Some runs don't need that model, or need a different one:

- **Permission phases** (ADR-031) and the coverage corpus need every stage to *run*, not to analyse well. The local model's agent loop is most of a run's time on this host, and it produces nothing they use.
- **Comparing models,** or exercising the real tool-calling loop quickly, needs a fast cloud model now and then.
- **Other people running this suite** have different models: no cloud at all, an API key, or other access.

Changing the deployed defaults for one run would change them for every automated run too.

### Decision

**A run chooses its models by naming a profile. Without one it is `local`, exactly as deployed.**

- **A profile** is a named set of the four model choices and the two transports, defined in `pipeline_llm_profiles` and rendered into the pipeline's config. Nothing else changes with a profile: limits, timeouts and modes stay as deployed.
- **`local`** is the `interpret` block itself. It cannot be redefined, and it is the default for every front door. API submissions and the feeder pass no profile.
- **Choosing one:** `run-pipeline --llm-profile NAME`, and `make intake ... LLM_PROFILE=NAME`, which records the profile in the batch directory. An unknown name stops the run; it never falls back.
- **Cloud is declared, and checked.**
  - Each profile says `cloud: true|false`.
  - A profile with `cloud: false` may name only local aliases (`LOCAL_ALIAS_RE`), and the pipeline refuses to start otherwise.
  - A test holds every alias matching that pattern to the llama.cpp server's own address in the rendered LiteLLM config. Loopback alone isn't enough, because the federated eval route is loopback too.
- **Recorded.**
  - Every report carries `llm_profile`: its name, whether it is cloud, and the models.
  - A replay records `replay_llm_profile`.
  - A cloud profile logs a warning naming the models it sends to.
- **The defaults define one profile, `stub`,** and never a cloud one.
  - **`stub`:** the `llm-stub` role, a loopback server that answers every LLM stage with valid, fixed replies, priced at zero. It's free and deterministic, for permission phases and coverage runs, and it changes nothing about what leaves the host.
  - **Cloud profiles are the operator's own addition,** in their vars. A commented `haiku` example on an eval-only alias is in the pipeline role's defaults.

### Consequences

- **`test_automated_runs_stay_local.py` still holds:** no deployed default names a cloud model. What changes is that a person can choose one for a run, and the report says so.
- **A cloud profile sends decompiled code, strings and behaviour to that provider.** That's the operator's decision for that run, and it is visible in the run's log and report.
- **A stub run proves the plumbing,** that every stage ran and parsed its reply, **not that a real model can still drive the tools.** After a permission phase, one run on a real model (a cloud profile, or `local`) covers that.

### Rollback

Revert. Runs then use the deployed models only. Reports written with `llm_profile` keep the field; nothing reads it.

## ADR-037: LiteLLM's per-call cost is the price of record; the rate tables become a fallback

**Status:** Proposed (2026-11-24).
**Refs:** CLAUDE.md section 10, ADR-030 (scoped LiteLLM keys), ADR-036 (LLM profiles), #449, #718, #803

### Context

Two hand-kept rate tables price model calls:

- **`db_ingest._LLM_PRICING`,** for `analyses.llm_cost_usd`;
- **`lamware_eval.runner._RATES`,** for the eval scorecards.

Both have drifted before:

- free local inference priced at Sonnet rates (#449);
- cache tokens billed at nothing (#718).

Neither knows every alias a run can use now. An unpriced alias is billed at the default (Sonnet) rate with a warning. The `stub` profile had exactly that until it got its own row, and the eval-only aliases an LLM profile can name (ADR-036) still do in `db_ingest`.

LiteLLM already prices every call it routes, and records the result in its spend log. **Measured 2026-11-24** from that log:

- **one Haiku 5.5 call** (13 in, 4 out) cost $0.0000033;
- **three other eval-route calls** (13 in, 5 out each) cost $0.000988 together;
- **both match the published rates exactly,** and local and stub calls are $0.

**What it exposes:**

- every response carries `x-litellm-call-id` when its headers arrive, streamed or not;
- non-streamed responses also carry `x-litellm-response-cost-*` headers;
- streamed responses carry those headers too, but they read 0, because the cost is only known after the stream ends;
- `GET /spend/logs?request_id=<call-id>` returns the call's row (`spend`, `prompt_tokens`, `completion_tokens`, `model_group`) for streamed and non-streamed calls alike.

### Decision

**The price of a run is the sum of LiteLLM's recorded cost for every call the run made.**

- **The interpret container records every call ID.**
  - An `httpx` response hook on every client it builds (the two Anthropic SDK clients and the synthesis client) collects `x-litellm-call-id` from each response. That covers all twelve call sites, streamed or not, without editing each one.
  - Each container process serves one stage, so the IDs it collected are that stage's.
  - They travel with the stage's result.
- **The orchestrator resolves them after the last LLM stage.**
  - It looks up each call in LiteLLM's spend log, retrying for a short while, because LiteLLM writes the log in batches.
  - It writes `report["llm_cost"]`: `source: litellm`, the dollar total, the number of calls, and any IDs it could not resolve.
  - The lookup uses a new scoped key with read-only spend access (ADR-030's one key per caller).
  - It goes over LiteLLM's Unix socket (`/run/litellm/litellm.sock`, the one the interpret container already uses), not TCP. The pipeline user's egress rules drop TCP to LiteLLM's port by design; measured on the host, TCP timed out and the socket answered. So this adds no firewall opening.
- **`db_ingest` uses `llm_cost` when every call resolved.** Otherwise, and for every report written before this ADR, it uses the rate table as today, with a warning.
- **The rate tables stay, as the fallback,** and are no longer extended for new aliases. A price for a new alias goes in LiteLLM's model list, where LiteLLM's spend tracking reads it too.
- **The eval harness moves to the same source** in a follow-up.

### Consequences

- **One price source** for the pipeline, the eval harness and LiteLLM's own spend view; cache reads and writes are priced the way LiteLLM prices them.
- **A run's cost depends on LiteLLM's spend log being written and kept.** A call the log doesn't have is listed in the report, and that run falls back to the table.
- **Reports carry LiteLLM call IDs.** They're opaque identifiers, not secrets.

### Rollback

Revert. `db_ingest` prices from the table again; reports that already carry `llm_cost` keep it, and nothing reads it.


---

## ADR-038: The operator chooses the models; the suite enables providers and records where the data went

**Status:** Proposed (2026-11-25). Extends ADR-036; it reverses nothing. Local stays the default, and profiles, the `cloud` declaration and the report record stand. ADR-036 let a person choose a cloud model only for one run. This adds a changeable automated default, and the design ADR-036 left open: providers, the web UI's models, escalation, model terms and the digest's routing.
**Refs:** ADR-030 (scoped LiteLLM keys), ADR-033 (Workload Identity Federation), ADR-036 (LLM profiles), ADR-037 (LiteLLM prices every call), `tests/test_automated_runs_stay_local.py`, `tests/test_frontier_arms_are_eval_only.py`

### Context

**Three mechanisms choose a model today, and they overlap:**

- **The deployed defaults** (`interpret_model`, `interpret_summary_model`, the pipeline's summary models), used by every automated run. Policy and a test hold them to the local model.
- **The analyst-facing models** (`interpret_analyst_model` and the other Claude entries in LiteLLM's model list), chosen in the web UI, on the production credentials.
- **The `eval-*` aliases** on the eval credentials, used by the eval harness and, since ADR-036, by per-run profiles.

**"Local only" holds two different rules,** and only one of them is a judgement about models:

1. **Which model analyses a sample.** Local is a good default, and the suite should keep it. But today the automated runs can *only* be local: an operator can choose a cloud model for one run, never as the default. That suits this deployment; for many people running the suite it won't. The likeliest backend for most is a cloud provider (the Anthropic API, Amazon Bedrock, Microsoft Foundry, Google Vertex), and some will need a specific model for reasons the suite can't see. The local work stays valuable. On a powerful enough host a local model may be the best option, and for some operators the only acceptable one. But it is one option among several.
2. **Where the sample's data goes, and who decided that.** Decompiled code, strings and behaviour leaving the host must always be a deliberate, recorded operator choice, never an accident. `test_automated_runs_stay_local.py` exists because of a real trap of that kind: a template once named a cloud entry after the local alias, so samples would have gone to the cloud while every config file said "local". This rule is about consent and visibility, not about which model is better.

**The split already costs us.** The daily digest reuses `interpret_summary_model` but sends through LiteLLM's `/anthropic` passthrough, which forwards straight to Anthropic without LiteLLM's routing. When that variable became `local-qwen-llamacpp`, Anthropic answered "model not found" every morning (measured in LiteLLM's spend log: failures since at least 2026-11-16), and nothing said the digest had lost its summary.

### Decision

**The suite enables models; the operator chooses them. The suite holds minimal opinions about models. It makes the operator's choice explicit, true and recorded.**

1. **The default is a setting, not a policy.** One variable (working name `pipeline_default_llm_profile`) names the profile every automated run uses.
   - **It ships as `local`,** so a fresh install keeps today's behaviour.
   - **The operator can change it at any time,** to any defined profile, local or cloud, by setting the variable and redeploying the `pipeline` role. Nothing in the suite stops a cloud default, and nothing switches it silently.
   - **A deploy that names an undefined profile stops** before changing anything, and lists the defined ones.
2. **Providers are the operator's to define.** They are LiteLLM model-list entries for whatever LiteLLM supports: the Anthropic API (key or Workload Identity Federation), Bedrock, Foundry, Vertex, llama.cpp or other local servers. The repo ships examples, not opinions. Each provider's credentials stay in the operator's vars or vault, as now.
3. **One concept: the profile** (ADR-036's shape).
   - The automated default is the operator's chosen profile, which may be local or cloud.
   - `--llm-profile` and `LLM_PROFILE=` still choose another for one run.
   - The web UI's model choices come from the same profiles, replacing the separate `interpret_analyst_model` path.
4. **What stays strict.** These rules are about data handling, not about models:
   - **A profile declares `cloud: true|false`, and the declaration is checked against where its aliases actually route.** `cloud: false` requires every alias to resolve to a host-local server in the rendered LiteLLM config (ADR-036's test, kept).
   - **Every report records the profile and models** (ADR-036, kept).
   - **A cloud default is announced:** at deploy, in each automated run's log, and in the report.
   - **No crossing mid-run.** Escalation and every stage stay within the run's profile. An unattended run never reaches a provider the operator didn't choose for it.
   - **Every path captures usage** (CLAUDE.md section 10). LiteLLM prices every call (ADR-037), whatever the provider.
   - **No caller bypasses LiteLLM's routing.** The digest moves from the `/anthropic` passthrough to the router, so a profile alias means the same thing to every caller.
5. **The one opinion: a model's terms must allow the work.** This pipeline reverse-engineers malware for security research. Some model licences or usage policies forbid reverse engineering or security research, and some of those offer no exception path. The docs tell operators to check a model's terms before choosing it, and point them at models whose terms (or an exception or approval process the provider offers) permit this use. This is guidance, not a gate: the suite doesn't read licences or refuse a model, and the operator is responsible for the terms they accept. It doesn't rank models by quality either. Where the eval harness has measured a model, the docs can publish the results.
6. **One model per run for the agent; no escalation.** The agentic stage uses the profile's one `model` from first turn to last. `escalation_model` and `escalation_threshold` are removed.
   - **What escalation did:** it switched models after a fixed number of tool calls (5), unconditionally, so on any real analysis the first model did only the first five calls. On the automated path it was a no-op, since the escalation model was the same local model. Only the analyst path (Sonnet, then Opus) used it. 5 of 76 reports on the host ever escalated, and nothing measured whether escalating improved an analysis.
   - **What a switch costs on current models:** the prompt cache is per model, so the new model reads the whole transcript again at full input price. The first model's thinking is dropped, because current models carry thinking over only to certain other models. And one run mixes two models, which makes runs harder to compare.
   - **Instead:** an operator who wants a stronger model for hard samples picks a profile with that model for the run.
   - **Reports keep `model_initial` and `model_final`;** they now always match.
7. **Short single-shot prompts take their own, cheaper model.** The executive and plain-English summaries are separate calls on short prompts, not a switch mid-conversation, so a profile keeps `summary_model` and `plain_english_model` apart from `model`. The examples pair a strong agent model with a cheap summary model, such as Haiku or the local model. That's a suggestion: the operator can set all three to the same model.
8. **`eval-*` stays, as a credentials and billing namespace,** not a verdict on models. Those aliases run on the eval credentials and budget. They may appear in per-run profiles, but not in the automated default, the analyst settings or any other deployed default. `test_frontier_arms_are_eval_only.py` keeps checking that, and exempts only the `cloud: true` per-run profiles, which ADR-036 requires to name `eval-*`.

### Consequences

- **`test_automated_runs_stay_local.py` changes its claim.** It moves from "no deployed default names a cloud model" to "the deployed default is the profile the operator named, and its `cloud` declaration is true". It keeps the shadowing check that motivated it.
- **A fresh install runs on `local`,** as today. Choosing a cloud default is one variable and a redeploy, and the deploy, every run's log and every report say so. `docs/LLM_PROFILES.md` becomes the guide to the choice, including the terms check above.
- **The web UI changes** to list profiles. Its current production-key models become a profile.
- **Providers other than Anthropic and llama.cpp are unverified here.** Bedrock, Foundry and Vertex examples are marked unverified until someone runs one, including whether LiteLLM's price map covers their models.
- **Escalation goes,** on the basis of cost, simplicity and comparability, not quality data. Whether Sonnet-then-Opus produced better analyses than either model alone was never measured. If that matters, the eval harness can run the same sample both ways (paid, and only with the operator's approval).
- **Measured guidance, not gates.** Nothing refuses a model for being weaker, or for its terms; the docs inform the choice.

### Not decided here

- **Variable names, and how the web UI presents profiles** (all of them, or a marked subset).
- **Whether a cloud default needs a second confirmation at deploy** beyond the announcement, for example an explicit `pipeline_default_llm_profile_is_cloud: true` that must match the profile.
- **Whether changing the default needs its own command** (for example `make llm-default PROFILE=…`, which deploys only the `pipeline` role), or the variable and a redeploy are enough.

### Implementation, if accepted (one PR each, each deployed and checked on the host)

1. **Profiles merge with the role's built-ins,** and the eval-only guard exempts `cloud: true` per-run profiles (the parked `fix/llm-profiles-merge` branch).
2. **Remove escalation.** Delete `escalation_model` and `escalation_threshold` from the interpret config, from `LlmProfile`, from the `interpret_*` and `interpret_analyst_*` defaults and from the agent loop, and check the reports' `model_initial` and `model_final` stay equal. Enumerate every reader first (eval harness, `db_ingest` pricing, the API, the web UI).
3. **The default profile setting,** shipped as `local`. Automated runs use it, a deploy naming an undefined profile stops, and the stay-local test changes as above.
4. **The digest uses the router,** not the passthrough.
5. **The web UI lists profiles.**
6. **Docs:** provider examples (Anthropic key and WIF, Bedrock, Foundry, Vertex, llama.cpp), each marked verified or not, and the terms check.

### Rollback

Revert. Deployments go back to the `interpret_*` defaults and ADR-036's local-by-default rule. A deployment that changed its default profile keeps a variable nothing reads, and returns to `local`.
