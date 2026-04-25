# SECURITY_CONSTRAINTS.md — Non-Negotiable Security Rules

These constraints are not optional and must not be compromised for convenience.
Each has a rationale — understanding the *why* prevents accidental violations.

---

## Detonation network is fully air-gapped

**Rule:** `virbr-det` (the KVM bridge serving detonation VMs) has no route to
`eth0` (public internet) or `wg0` (management VPN). iptables DROP rules enforce this
at the hypervisor level, not just at the guest level.

**Why:** Malware that successfully escapes its guest VM should land on the bare metal
host with no further outbound reach. The detonation VLAN must be a dead end.
If malware can reach `eth0`, it can beacon out. If it can reach `wg0`, it can attempt
to pivot to the management plane or enumerate the WireGuard network.

**Implementation:** Two explicit iptables DROP rules in `roles/networking/`:
```
iptables -I FORWARD -i virbr-det -o eth0 -j DROP
iptables -I FORWARD -i virbr-det -o wg0  -j DROP
```
These are set before any ACCEPT rules and must be verified after every host rebuild.

---

## Cape web UI and API bind to WireGuard only

**Rule:** Cape's web interface and REST API must bind to `wg0` (WireGuard interface)
only. Never bind to `eth0` or `0.0.0.0`.

**Why:** Cape's API accepts sample submissions and controls the analysis pipeline.
Exposing it on the public interface means anyone who can reach the host IP can submit
malware for analysis, enumerate running tasks, or attempt to exploit Cape itself.
WireGuard-only binding means you must be an authenticated VPN peer to reach it.

**Implementation:** Two separate bindings, each restricted to the correct interface:

- **Resultserver** (`cape.conf [resultserver] ip`): bound to `detonation_gateway`
  (192.168.100.1 — the virbr-det bridge IP) so guest VMs can deliver analysis data
  to the host. Guests have no route to eth0 or wg0, so this is the only IP they can reach.

- **Cape web UI / API** (`cape-web.service ExecStart`): bound to the WireGuard interface
  IP only (`wg0`). Never bound to eth0 or 0.0.0.0. Enforced by a `lineinfile` task in
  `ansible/roles/cape/tasks/main.yml` that rewrites the `runserver_plus` bind address
  after `cape2.sh` installs the unit file.

---

## S3 buckets: no public access, HTTPS only, KMS encrypted (if deployed)

> **Note:** AWS infrastructure is not currently deployed (see ADR-016). These rules
> apply if S3 evidence archival is added in the future.

**Rule:** S3 buckets holding malware samples or reports must have:
- Block Public Access enabled at the bucket level
- Bucket policy enforcing `aws:SecureTransport` (HTTPS only)
- SSE-KMS encryption with a project-specific KMS key
- No public ACLs or bucket policies granting `*` principal access

**Why:** S3 buckets holding malware samples must not be publicly accessible under
any circumstances. Defense in depth: block at multiple layers.

---

## Secrets in Ansible Vault, never in plaintext committed files

**Rule:** All sensitive values (API keys, auth tokens) must be stored in
`ansible/vars/secrets.yml` (gitignored) and encrypted at rest with `ansible-vault`.
Never commit plaintext secrets to git. Never store secrets in `vars/main.yml`.

**Why:** Secrets committed to git history are effectively permanent — even if removed
in a later commit, they remain in the history. Ansible Vault provides AES-256
encryption at rest with a password only the operator knows. The gitignore pattern
prevents accidental commits of the unencrypted file.

---

## OVH robot firewall: whitelist before OS boots

**Rule:** OVH's hardware firewall (robot firewall) must be configured with admin
CIDR allowlists before the server is provisioned. The firewall must drop all traffic
except: SSH (22) from admin CIDRs, WireGuard UDP port from admin CIDRs, and any
explicitly required management ports.

**Why:** The window between OS boot and the host firewall (iptables/ufw) becoming
active is a brief exposure. OVH's robot firewall operates at the network edge before
packets reach the server — it closes this window. A freshly booted Ubuntu server with
no iptables rules is briefly reachable from the internet; the robot firewall prevents
that from being exploitable.

---

## Separate AWS account for this project (if AWS is used)

> **Note:** AWS infrastructure is not currently deployed (see ADR-016). This rule
> applies if S3 evidence archival is added in the future.

**Rule:** All AWS resources for this project must live in a dedicated AWS account,
not shared with other personal or work infrastructure.

**Why:** This project handles malware samples. If any S3 bucket or IAM role is
misconfigured, blast radius must be limited to this project's account only.

---

## All infrastructure in US jurisdiction

**Rule:** All infrastructure — bare metal and AWS — must be hosted in the United States.
AWS region must be `us-east-1`, `us-east-2`, or `us-west-2`. Bare metal must be
OVHcloud US (Vint Hill VA or Hillsboro OR) or equivalent US-based provider.

**Why:** The operator is US-based. Malware analysis work creates potential legal exposure
(CFAA, chain of custody for samples, possible law enforcement interaction). Keeping all
infrastructure under US jurisdiction simplifies that exposure significantly. EU-hosted
infrastructure introduces GDPR considerations for any data processed, and cross-border
law enforcement cooperation is significantly more complex.

**For open-source users in other jurisdictions:** This constraint applies to the operator's
deployment only. The architecture is fully portable — swap AWS region and bare metal
provider. No code changes required.
