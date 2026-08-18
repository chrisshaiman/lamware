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

## ADR-007: S3 Object Lock mode — GOVERNANCE, not COMPLIANCE

**Status:** Decided (known limitation documented)

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

**Status:** Decided

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

**Status:** Decided (2026-08-10)

**Context:**

The eval harness reports `family_guess` against `mb_family` on every cell, and that
column has been read as a quality signal. Measured against real corpora it is not one.

Three independent measurements, all on the deployed pipeline:

- **qwen scores 0/14** on family identification against MalwareBazaar labels
  (post-#321 sweep, both depths, all 7 samples).
- **The Claude reference scores 0/7** on the same samples. When a frontier model and a
  35B local model both score zero, the metric is the suspect, not the models.
- **MalwareBazaar's own labels disagree with the reference on every sample** —
  raccoonstealer/njrat, icedid/bumblebee, emotet/smokeloader, warmcookie/orcus. There is
  no agreement anywhere to anchor on.

**Checked against the published literature** (2026-08-10 — the argument above is reasoning
from our own data and deserved an outside check). It both supports and *narrows* the
conclusion:

- The MOTIF paper measures **AVClass at 46.78%** accuracy and **AV majority voting at
  62.10%** against its expert ground truth ([arXiv:2111.15031](https://arxiv.org/abs/2111.15031)).
  The tooling whose output becomes MalwareBazaar-style labels is under 50% accurate. Our
  0/14 is therefore as much a statement about the labels as about the models — and this
  is the **strongest support for this ADR**, stronger than the packing argument.
- Packing does degrade static classification: one AV vendor loses 19% accuracy on packed
  files, and static approaches are broadly sensitive to packing and obfuscation.

But the naive packing claim is **too strong and must not be repeated**:

- Supervised classifiers *do* achieve high accuracy on packed samples — MaliCage reports
  **91.66%** on real packed malware (97.8% with GAN augmentation).
- One study found near-zero correlation (0.015 binary, 0.0001 family) between packing
  prevalence and classification accuracy. "Packing destroys family ID" is not a law.

The distinction that matters is **what is classified, and how**. Those results come from
supervised models over **byte-level and structural features** — entropy, byte histograms,
section characteristics, import tables — against a **closed set** of known families. That
is a different task from an LLM reading **decompiled code** and naming a family from an
**open set of 454+**, which is what this stage does. A packer stub is generic *as source
code* while remaining statistically distinctive *as bytes*: a DNN can exploit the latter,
a decompiler-reading model cannot.

So the structural claim, correctly scoped: **the signals available to an LLM reading
decompiled code — distinctive string constants, config markers, custom crypto constants,
characteristic import combinations — do not survive packing**, even though byte-level
statistical signals do. Confirmed on the MOTIF corpus (#368): of 29 samples, 14 yield no
strings matching the interest filter, and the most opaque export 2 imports across 4
functions.

A corollary worth keeping: if family ID is ever wanted as a *product* feature rather than
a metric, the viable route is a supervised byte-level classifier over a closed family
set — not this stage.

The same structure explains why published threat-report IOCs cannot ground this stage
either (#314): **0 of 9** icedid samples and **0 of 2** azorult samples contained any
literal from their own linked reports — C2 domains, drop paths, `regsvr32`, `certutil`.
The reports describe runtime behaviour; static analysis sees the packer.

Real-world family attribution uses YARA over unpacked or memory-dumped samples,
behavioural signatures from detonation, config extraction after unpacking, and network
IOCs. None of those are decompilation of a packer.

There is also a contamination problem that cannot be engineered away. MOTIF has been
public since 2021, its md5→family mappings are in `motif_dataset.jsonl`, and the
underlying vendor reports are indexed web content. Any model trained on public data has
plausibly seen them. The exploitable vector is not hashes — the model never sees one —
but **memorised code patterns from published analyses**, which is indistinguishable from
genuine recognition. That is equally true of a human analyst who has read the same
writeups. "Name the family" therefore conflates analysis with recall and cannot separate
them.

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
   decisive property is that `run_arm` passes only `report["ghidra"]` to interpret, so
   CAPE observations are independent of the model's evidence and scoring against them is
   not circular. It is a lower bound — one execution, so evasion or a dead C2 means it
   under-reports — usable for confirming predictions, not for penalising misses.

**Consequences:**

- Any future "the model got the family wrong" observation is expected behaviour, not a
  regression. Do not tune prompts against it.
- Comparisons between local and cloud arms on family ID measure training-data overlap,
  not capability. Both scoring zero is the signal that the task is ill-posed here.
- **Label-leak hazard, recorded because it is one refactor away.** `_bazaar_context()`
  injects the family verbatim into the prompt — *"MalwareBazaar identifies this sample as
  'X'. Use this as your starting hypothesis"* — whenever `bazaar_family` is present in
  the payload. It does not fire in eval runs only because `run_arm` passes
  `report["ghidra"]` while `bazaar_family` sits at report top level. Passing the whole
  report would silently turn the benchmark into an answer key. Verified 2026-08-10 by
  rendering the prompt with a marker in every field: `filename`, `program_name` and
  `project_dir` do **not** reach the model; `bazaar_family` does.
- The production .NET, PowerShell **and Go** paths *do* receive that hint — all three
  spread `**llm_context` into their init payload (`build_dotnet_init` / `build_ps_init` /
  `build_go_init` in `stages/single_shot_init.py`), and `run-pipeline.py` puts
  `bazaar_family` in `_llm_context` whenever the report carries it. The PE path does not.
  That asymmetry is intentional-by-accident and worth revisiting if those paths are ever
  benchmarked. Corrected 2026-08-18: this entry previously listed only .NET and
  PowerShell, which undercounted the exposed paths.
- Unpacking is the higher-leverage fix. CAPE already dumps unpacked payloads to
  `/opt/CAPEv2/storage/analyses/<task>/dropped`, and the investigate tools already read
  them. Running Ghidra over those rather than the packed original attacks the root cause
  of both this ADR and #314.
