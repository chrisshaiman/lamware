# SECURITY_CONSTRAINTS.md — Non-Negotiable Security Rules

These constraints are not optional and must not be compromised for convenience.
Each has a rationale — understanding the *why* prevents accidental violations.

> **On interface names:** where this document says `eth0` it means *the management
> interface*, which is a variable (`management_interface` in `ansible/vars/main.yml`)
> and is `enp3s0f0` on the live host. The distinction is not pedantry: a hardcoded
> `eth0` in the air-gap monitor meant its iptables match never matched a real rule,
> so the egress alarm was unreachable and the check reported healthy while measuring
> nothing (GHSA-f5q8-v78c-mr55, fixed in #336).

---

## Detonation network is fully air-gapped

**Rule:** `virbr-det` (the KVM bridge serving detonation VMs) has no route to
the management interface (public internet) or `wg0` (management VPN). iptables DROP rules enforce this
at the hypervisor level, not just at the guest level.

**Why:** Malware that successfully escapes its guest VM should land on the bare metal
host with no further outbound reach. The detonation VLAN must be a dead end.
If malware can reach the management interface, it can beacon out. If it can reach `wg0`, it can attempt
to pivot to the management plane or enumerate the WireGuard network.

**Implementation:** Two explicit iptables DROP rules in `roles/networking/`:
```
iptables -I FORWARD -i virbr-det -o "$MGMT_IFACE" -j DROP   # NOT a literal eth0
iptables -I FORWARD -i virbr-det -o wg0  -j DROP
```
These are set before any ACCEPT rules and must be verified after every host rebuild.

---

## Cape web UI and API bind to WireGuard only

**Rule:** Cape's web interface and REST API must bind to `wg0` (WireGuard interface)
only. Never bind to the management interface or `0.0.0.0`.

**Why:** Cape's API accepts sample submissions and controls the analysis pipeline.
Exposing it on the public interface means anyone who can reach the host IP can submit
malware for analysis, enumerate running tasks, or attempt to exploit Cape itself.
WireGuard-only binding means you must be an authenticated VPN peer to reach it.

**Implementation:** Two separate bindings, each restricted to the correct interface:

- **Resultserver** (`cuckoo.conf [resultserver] ip` — CAPE reads it from there,
  not from `cape.conf`; the role writes both): bound to `detonation_gateway`
  (192.168.100.1 — the virbr-det bridge IP) so guest VMs can deliver analysis data
  to the host. Guests have no route to the management interface (`management_interface`, `enp3s0f0` on the current host — **not** literally `eth0`) or `wg0`, so this is the only IP they can reach.

- **Cape web UI / API** (`cape-web.service ExecStart`): bound to the WireGuard interface
  IP only (`wg0`). Never bound to the management interface or 0.0.0.0. Enforced by a `lineinfile` task in
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

## Analysis service users read CAPE storage; they never write it

**Rule:** `pipeline` and `lamware-api` reach CAPE's detonation output through
the `lamware` group, granted **`rx` only** on `/opt/CAPEv2/storage`. Never
`rwx`, never by adding those users to the `cape` group, and never by
loosening `other`. `cape` remains the sole writer of its own tree.

**Why:** The analysis stages and the investigation agent have to read extracted
payloads — that is the point of #377 and the ground truth #314 needs. Write
access buys nothing and costs the property that makes detonation output
trustworthy as evidence: if a compromised pipeline process could write into
CAPE storage, it could plant a payload and every downstream conclusion drawn
from "CAPE extracted this" would be forgeable. Read-only keeps the output a
record of what the sample did, not of what a later process claimed.

Adding the users to group `cape` would also hand them everything else `cape`
owns, well beyond the analysis tree.

**Implementation:** `roles/cape/tasks/main.yml`, tagged `cape-storage-perms`:

```yaml
- name: Grant the lamware group traversal of CAPE storage
  ansible.posix.acl:
    path: "{{ cape_install_dir }}/storage"
    entity: lamware
    etype: group
    permissions: rx
    state: present
```

An ACL rather than the group ownership alone, because the ownership does not
stay put: the role sets `storage/` to `cape:lamware` and the host was found at
`cape:cape` with the role's own mode, and the hourly maintenance cron repairs
only `analyses/`. When that reverted, **no service user could traverse
`storage/` at all**, so the correctly-granted permissions on every directory
beneath it were unreachable and two features returned "nothing found" for
every analysis ever run (#385).

That is the trap worth remembering: a grant on a child is worthless if the
parent cannot be traversed, and every check of the child still passes. Verify
by reading a payload directory **as a member of the group**, which the role's
verify step does — not by re-reading the mode you just set.

---

## OVH robot firewall: whitelist before OS boots

**Rule:** OVH's hardware firewall (robot firewall) must be configured with admin
CIDR allowlists before the server is provisioned. The firewall must drop all traffic
except: SSH (22) from admin CIDRs, WireGuard UDP port from anywhere, HTTP/HTTPS
(80/443) from anywhere, and any explicitly required management ports.

WireGuard and 80/443 are **deliberately public** (`ovh/main.tf`). WireGuard is
cryptographically authenticated — unauthenticated packets are dropped by the
protocol before anything listens — and admin access is needed from mobile networks
whose source IPs are unpredictable behind carrier NAT. An admin-CIDR allowlist
would make the VPN unusable for the case it exists to serve. SSH keeps its
allowlist because it has no equivalent pre-auth packet filter.

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
