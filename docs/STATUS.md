# STATUS.md — Build Status (Living Document)

Update this file as components are built, stubbed, or descoped.
For the ordered build queue see CLAUDE.md. For design rationale see ARCHITECTURE.md.

---

## Repo structure

```
malware-sandbox-infra/
├── CLAUDE.md                      ✓ instructions + build queue
├── ARCHITECTURE.md                ✓ system design reference
├── README.md                      ✓ public-facing overview
├── AUTHORS                        ✓
├── Makefile                       ✓ complete
│
├── docs/
│   ├── DECISIONS.md               ✓ ADR log
│   ├── SECURITY_CONSTRAINTS.md    ✓ non-negotiables with rationale
│   └── STATUS.md                  ✓ this file
│
├── packer/
│   ├── ubuntu-sandbox.pkr.hcl     ✓ complete
│   ├── windows10-guest.pkr.hcl    ✓ complete (Win10 22H2 eval, Python, cape-agent, anti-evasion)
│   ├── windows10-office.pkr.hcl   ✓ complete (boots from base, adds LibreOffice, macro security LOW)
│   ├── answer-files/
│   │   └── autounattend.xml       ✓ complete (unattended Win10 install, WinRM, eval ISO)
│   ├── scripts/windows/           ✓ complete (8 PowerShell provisioner scripts)
│   ├── ansible/
│   │   └── hardening.yml          ✓ complete (konstruktoid.hardening playbook)
│   └── http/
│       ├── meta-data              ✓ complete
│       └── user-data              ✓ complete (placeholder hash — run make packer-setup)
│
├── ansible/
│   ├── site.yml                   ✓ complete
│   ├── requirements.yml           ✓ complete (konstruktoid.hardening, community.general)
│   ├── inventory/
│   │   └── hosts.example          ✓ exists
│   ├── vars/
│   │   └── main.yml               ✓ complete (fill in ARNs + bucket names post-deploy)
│   └── roles/
│       ├── hardening/             ✓ complete (wraps konstruktoid.hardening, production settings)
│       ├── kvm/                   ✓ complete (libvirt, hugepages, groups, disable default net)
│       ├── networking/            ✓ complete (virbr-det libvirt network, iptables air-gap + INetSim INPUT rules)
│       ├── inetsim/               ✓ complete (install, bind to virbr-det, DNS/HTTP/HTTPS/SMTP/FTP, systemd ordering)
│       ├── cape/                  ✓ complete (DSDT patch, kvm-qemu.sh, cape2.sh, config, services,
│       │                                      routing.conf, guest-domain.xml, kvm.conf stanzas)
│       ├── wireguard/             ✓ complete (server config from Secrets Manager, wg-quick)
│       └── sqs-agent/             ✓ complete (systemd service: SQS poll → Cape → S3 report upload)
│
├── ovh/
│   ├── main.tf                    ✓ complete (firewall, SSH key, OS install)
│   ├── variables.tf               ✓ complete
│   ├── outputs.tf                 ✓ complete
│   └── terraform.tfvars.example   ✓ complete
│
├── aws/
│   ├── bootstrap/
│   │   ├── main.tf                ✓ complete
│   │   ├── variables.tf           ✓ complete
│   │   └── outputs.tf             ✓ complete
│   ├── modules/
│   │   ├── vpc/                   ✓ complete (subnets, NAT, flow logs)
│   │   ├── s3/                    ✓ complete (buckets, object lock, KMS, lifecycle)
│   │   ├── rds/                   ✓ complete (PostgreSQL, private subnet, encrypted)
│   │   ├── lambda/
│   │   │   ├── main.tf            ✓ complete
│   │   │   ├── variables.tf       ✓ complete
│   │   │   └── outputs.tf         ✓ complete
│   │   ├── sqs/
│   │   │   ├── main.tf            ✓ complete
│   │   │   ├── variables.tf       ✓ complete
│   │   │   └── outputs.tf         ✓ complete
│   │   └── api/
│   │       ├── main.tf            ✓ complete
│   │       ├── variables.tf       ✓ complete
│   │       └── outputs.tf         ✓ complete
│   └── envs/
│       └── prod/
│           ├── main.tf            ✓ complete
│           ├── variables.tf       ✓ complete
│           ├── outputs.tf         ✓ complete
│           └── terraform.tfvars.example ✓ complete
│
├── shared/
│   └── backend-aws.hcl            ~ placeholder values, needs real bucket name
│
└── src/
    ├── report_processor.py        ~ stub (deployable, no real logic yet — needs real Cape report JSON)
    └── sample_submitter.py        ✓ complete
    # run `make lambda` to build src/*.zip before terraform apply
```

**Legend:** ✓ complete · ~ stub/partial · ✗ not built · ! needs fix

---

## Deployment status (2026-04-03)

Code is complete. Nothing has been deployed yet. Work through these in order.

### Pre-deployment checklist

- [ ] **`shared/backend-aws.hcl`** — fill in real S3 state bucket name.
      Run `terraform -chdir=aws/bootstrap apply` first (local state), then copy the
      `state_bucket_name` output into `shared/backend-aws.hcl`.
      *File:* `shared/backend-aws.hcl`

- [ ] **AWS bootstrap** — create Terraform state bucket + DynamoDB lock table.
      ```
      cd aws/bootstrap && terraform init && terraform apply
      ```
      One-time. Uses local state (no remote backend needed for bootstrap itself).

- [ ] **AWS prod Terraform plan + apply** — provision VPC, S3, RDS, Lambda, SQS, API Gateway,
      KMS, Secrets Manager, CloudTrail.
      ```
      cd aws/envs/prod && terraform init -backend-config=../../shared/backend-aws.hcl
      terraform plan -out=tfplan
      terraform apply tfplan
      ```
      Outputs needed for the next steps:
      - `samples_bucket_name`, `reports_bucket_name` → `ansible/vars/main.yml`
      - `baremetal_agent_secret_arn` → `ansible/vars/main.yml`
      - API Gateway invoke URL → note for client use

- [ ] **WireGuard keys** — generate server + client keypair, create AWS secret.
      ```
      wg genkey | tee server.key | wg pubkey > server.pub
      wg genkey | tee client.key | wg pubkey > client.pub
      ```
      Store `{ "private_key": "<server.key>", "peer_pubkey": "<client.pub>" }` in a new
      Secrets Manager secret; record the ARN in `ansible/vars/main.yml` → `secret_arn_wireguard`.
      Generate client WireGuard config from `client.key` + `server.pub` + server WireGuard IP.

- [ ] **Cape API key** — generate a random key, create AWS secret.
      ```
      python3 -c "import secrets; print(secrets.token_hex(32))"
      ```
      Store `{ "dsdt_string": "<hex>", "api_key": "<key>" }` in a new Secrets Manager secret;
      record the ARN in `ansible/vars/main.yml` → `secret_arn_cape`.
      DSDT string: run `acpidump -b && iasl -d dsdt.dat` on the bare metal host after OS install.

- [ ] **`ansible/vars/main.yml`** — fill in all ARNs and bucket names from Terraform outputs.
      Fields: `s3_bucket_samples`, `s3_bucket_reports`, `secret_arn_baremetal`,
      `secret_arn_wireguard`, `secret_arn_cape`.

- [ ] **OVH bare metal provisioning** — provision server, apply firewall, install Ubuntu 24.04.
      ```
      cd ovh && terraform init && terraform apply
      ```
      Then update `ansible/inventory/hosts` with the server IP.

- [ ] **Ansible** — configure bare metal host (KVM, Cape, INetSim, WireGuard, sqs-agent).
      ```
      ansible-galaxy install -r ansible/requirements.yml
      ansible-playbook -i ansible/inventory/hosts ansible/site.yml
      ```

- [ ] **Packer guest builds** — build Windows guest images.
      Populate `packer/packer.auto.pkrvars.hcl` first (see checklist below).
      ```
      make image
      ```
      Then `scp` the two qcow2 files to `/var/lib/libvirt/images/` on the bare metal host.

- [ ] **Libvirt snapshots** — take clean + office snapshots (manual, after Ansible defines domains).
      See snapshot workflow in the "Next build" section below.

- [ ] **`src/report_processor.py`** — implement report ingestion logic once Cape is running
      and real analysis JSON is available. Currently a deployable stub.

---

## Documentation (2026-04-03)

**`docs/DEPLOYMENT.md`** — written. Single document covering all 10 deployment phases.
The README should link to it.

### `docs/DEPLOYMENT.md` — phase checklist

- [x] **Phase 0 — Prerequisites**
      Everything that must be in place before any `terraform` or `ansible` command runs.
      - Accounts: OVHcloud US account, AWS account (dedicated — not shared with other infra)
      - Tools and minimum versions: Terraform ≥ 1.6, Ansible ≥ 2.14, Packer ≥ 1.10,
        AWS CLI v2, WireGuard tools (`wg`, `wg-quick`), Python 3.11+ (local, for Lambda build),
        `make`, `acpica-tools` (for DSDT capture on the bare metal host after OS install)
      - AWS credentials configured (`aws configure` or profile) with AdministratorAccess
        on the sandbox account
      - OVHcloud API credentials: `OVH_ENDPOINT`, `OVH_APPLICATION_KEY`,
        `OVH_APPLICATION_SECRET`, `OVH_CONSUMER_KEY`
      - Windows 10 22H2 Enterprise evaluation ISO downloaded locally
        (link to official Microsoft evaluation download page)

- [x] **Phase 1 — AWS bootstrap**
      One-time: creates the S3 state bucket and DynamoDB lock table with local state.
      - Copy `aws/bootstrap/terraform.tfvars.example` → `terraform.tfvars`, fill in
        `name_prefix` and `aws_region`
      - `terraform init && terraform apply`
      - Record `state_bucket_name` output → fill into `shared/backend-aws.hcl`

- [x] **Phase 2 — AWS infrastructure**
      Provisions VPC, S3, RDS, SQS, Lambda, API Gateway, KMS, Secrets Manager, CloudTrail.
      - `make lambda` — build Lambda ZIPs before plan (plan will error without them)
      - Copy `aws/envs/prod/terraform.tfvars.example` → `terraform.tfvars`; fill in
        `samples_bucket_name`, `reports_bucket_name` (globally unique — include account ID),
        `budget_alert_emails`
      - `terraform init -backend-config=../../shared/backend-aws.hcl`
      - `terraform plan -out=tfplan && terraform apply tfplan`
      - Record outputs: `samples_bucket_name`, `reports_bucket_name`,
        `baremetal_agent_secret_arn`, `api_invoke_url` → fill into `ansible/vars/main.yml`

- [x] **Phase 3 — Secrets setup**
      Two secrets must be created manually (outside Terraform) because they contain
      information only available after provisioning or key generation.
      - **WireGuard**: generate server + client keypair; create Secrets Manager secret;
        record ARN → `ansible/vars/main.yml` → `secret_arn_wireguard`
      - **Cape API key + DSDT**: generate API key now (random hex); DSDT captured later
        in Phase 5 after bare metal OS install; create the secret once both values exist;
        record ARN → `ansible/vars/main.yml` → `secret_arn_cape`
      - Exact commands for key generation, secret creation via AWS CLI

- [ ] **Phase 4 — OVH bare metal provisioning**
      Provisions the server, applies OVH robot firewall (SSH + WireGuard allowlist),
      registers SSH key, installs Ubuntu 24.04.
      - Copy `ovh/terraform.tfvars.example` → `terraform.tfvars`; fill in OVH credentials,
        admin CIDR (your IP), SSH public key
      - `terraform init && terraform apply`
      - Wait for OS install to complete (~15 min); record server IP
      - Update `ansible/inventory/hosts` with the server IP
      - Verify SSH access: `ssh root@<server-ip>`

- [ ] **Phase 5 — DSDT capture (bare metal, post-OS-install)**
      Must be done on the physical host before running Ansible — value is hardware-specific.
      ```
      apt install -y acpica-tools
      acpidump -b && iasl -d dsdt.dat
      ```
      Extract the DSDT hex string; update the Cape Secrets Manager secret with it.

- [ ] **Phase 6 — Ansible configuration**
      Configures KVM, CAPEv2, INetSim, WireGuard, and the SQS polling agent on the host.
      - Install Galaxy requirements: `ansible-galaxy install -r ansible/requirements.yml`
      - `ansible-playbook -i ansible/inventory/hosts ansible/site.yml`
      - Note: `kvm-qemu.sh` (DSDT-patched QEMU build) takes 30–60 min — expected
      - Verify services: `systemctl status cape cape-web cape-processor inetsim wg-quick@wg0`

- [ ] **Phase 7 — Packer guest image builds**
      Builds the Windows 10 base image and the LibreOffice office image.
      Prerequisite: `packer/packer.auto.pkrvars.hcl` populated (see "required variables"
      checklist in the Packer section of this file).
      - `make image` — builds both images sequentially (~2–3 hours total)
      - SCP both qcow2 files to the bare metal host:
        ```
        scp packer/output/windows10-guest.qcow2  root@<host>:/var/lib/libvirt/images/
        scp packer/output/windows10-office.qcow2 root@<host>:/var/lib/libvirt/images/
        ```
      - Re-run Ansible to define libvirt domains: `ansible-playbook ... ansible/site.yml`

- [ ] **Phase 8 — Libvirt snapshots**
      Manual steps on the bare metal host after images are in place and domains are defined.
      See "Snapshot workflow" section in this file.

- [ ] **Phase 9 — Smoke test**
      Verify the full pipeline end to end before treating the system as operational.
      - Submit a known-benign sample via the API (e.g., `calc.exe` or a simple `hello.exe`)
      - Verify it appears in the SQS queue, is picked up by sqs-agent, detonated by Cape,
        and the report lands in S3
      - Check Cape web UI (via WireGuard) for the analysis report
      - Suggested test sample: EICAR test file (detected but harmless)

---

## Review findings (2026-04-02) — Packer/Ansible security & functional review

Issues identified during deep review of Packer guest builds, Ansible roles, and Terraform.

### Critical — supply chain / integrity

- [x] **No hash verification on cape-agent.py download.**
      Fixed 2026-04-02. Added required `cape_agent_commit` and `cape_agent_sha256` Packer
      variables (no defaults — must be set together). Script pins the download URL to the
      commit SHA and verifies `Get-FileHash` after download; aborts with error on mismatch.
      Instructions for deriving both values added to the variable descriptions.
      *Files:* `packer/windows10-guest.pkr.hcl`, `packer/scripts/windows/install-cape-agent.ps1`

- [x] **No hash verification on Python installer.**
      Fixed 2026-04-02. Removed `python_version` default (no default — must be set alongside
      `python_checksum`). Added required `python_checksum` variable. Script validates both are
      set, verifies `Get-FileHash` after download, aborts on mismatch.
      *Files:* `packer/windows10-guest.pkr.hcl`, `packer/scripts/windows/install-python.ps1`

- [x] **No hash verification on LibreOffice MSI.**
      Fixed 2026-04-02. Removed `libreoffice_version` default. Added required
      `libreoffice_checksum` variable. Script validates both are set, verifies `Get-FileHash`
      after download, aborts on mismatch.
      *Files:* `packer/windows10-office.pkr.hcl`, `packer/scripts/windows/install-libreoffice.ps1`

### High — functional correctness

- [x] **Office guest IP not reserved in DHCP — will get wrong address.**
      Fixed 2026-04-02. Added `{% for guest in cape_guests %}<host>{% endfor %}` loop inside
      the `<dhcp>` block of `detonation-network.xml.j2`. Static reservations are now derived
      directly from the `cape_guests` list so MAC/IP pairs stay in sync with kvm.conf.
      *Files:* `ansible/roles/networking/templates/detonation-network.xml.j2`

- [x] **LibreOffice file associations won't work — UserChoice hash protection.**
      Fixed 2026-04-02. Replaced `HKCU:\...\UserChoice` writes (silently ignored on
      Windows 10 1803+) with `HKLM:\SOFTWARE\Classes\.<ext>` system-level defaults.
      HKLM\SOFTWARE\Classes has no hash protection and applies to all users.
      *Files:* `packer/scripts/windows/install-libreoffice.ps1`

- [x] **SECURITY_CONSTRAINTS.md incorrectly describes resultserver binding.**
      Fixed 2026-04-02. Corrected: resultserver binds to `detonation_gateway` (virbr-det,
      192.168.100.1) for guest access; cape-web binds to WireGuard IP only. Both bindings
      now documented accurately with implementation details.
      *Files:* `docs/SECURITY_CONSTRAINTS.md`

- [x] **WinRM left enabled in final guest image.**
      Fixed 2026-04-02. Added step 8 to `cleanup.ps1`: stops WinRM service, sets startup
      type to Disabled, and removes the `WinRM-HTTP` firewall rule added by autounattend.xml.
      *Files:* `packer/scripts/windows/cleanup.ps1`

### Medium — operational / hardening

- [x] **`cape-web.service` lineinfile with `backrefs: false` can append duplicate ExecStart.**
      Fixed 2026-04-02. Switched to `backrefs: true` with a capture-group regex so the task
      only substitutes the bind address when the ExecStart line matches. No-match now silently
      skips rather than appending a second ExecStart that would break systemd.
      *Files:* `ansible/roles/cape/tasks/main.yml`

- [x] **No IPv6 iptables rules — air-gap only covers IPv4.**
      Fixed 2026-04-02. Added matching `ip6tables` DROP rules for `virbr-det → eth0` and
      `virbr-det → wg0` using the same check-then-insert idempotency pattern. Also added
      `net.ipv6.conf.all.forwarding = 0` sysctl to `/etc/sysctl.d/90-ipforward.conf`.
      *Files:* `ansible/roles/networking/tasks/main.yml`

- [x] **SQS DLQ retention too short — defaults to 4 days.**
      Fixed 2026-04-02. Set `message_retention_seconds = 1209600` (14 days, SQS maximum)
      on the DLQ so failed jobs survive extended downtime or bare metal rebuilds.
      *Files:* `aws/modules/sqs/main.tf`

- [x] **`virsh define` `changed_when` always true — misleading idempotency.**
      Fixed 2026-04-02. Changed to `changed_when: false` — virsh define outputs "Domain X
      defined" on both new and re-define, so tracking changes via stdout is meaningless.
      Removed now-unused `register` variable.
      *Files:* `ansible/roles/cape/tasks/main.yml`

### Low — cleanup / cosmetic

- [x] **`vars/main.yml` comment references "FakeNet-NG" — stale after ADR-011.**
      Fixed 2026-04-02. Updated comment to reference INetSim.
      *Files:* `ansible/vars/main.yml`

- [x] **`install-python.ps1` dead comment about `requests` package.**
      Fixed 2026-04-02. Removed stale comment — only Pillow is installed, not requests.
      *Files:* `packer/scripts/windows/install-python.ps1`

---

## Done (fully implemented)

- `aws/modules/vpc/` — VPC, subnets, NAT gateway, flow logs
- `aws/modules/s3/` — samples + reports buckets, object lock, KMS, lifecycle, S3 event notification
- `aws/modules/rds/` — PostgreSQL, private subnet, Performance Insights, encrypted
- `aws/modules/lambda/` — report_processor + sample_submitter functions, IAM, SQS permissions, VPC endpoint, variables, outputs
- `aws/modules/sqs/` — job queue, DLQ, bare metal IAM user + policy, credentials in Secrets Manager
- `aws/bootstrap/` — S3 state bucket + DynamoDB lock table; runs once with local state
- `aws/modules/api/` — HTTP API Gateway v2, POST /submit route, IAM auth, throttling, access logs
- `aws/envs/prod/` — composition layer wiring all modules; KMS key, Secrets Manager secrets, cross-module rules
- `Makefile` — `make image`, `make infra`, `make configure` entry points
- `ovh/` — OVH bare metal module: robot firewall (SSH + WireGuard allowlist), SSH key registration, Ubuntu 24.04 OS install
- `packer/ubuntu-sandbox.pkr.hcl` — hardened Ubuntu 24.04 image: KVM packages, CAPEv2 clone + deps, AWS CLI, konstruktoid hardening, qcow2 output
- `src/sample_submitter.py` — Lambda handler: validates submission, issues pre-signed S3 URL, enqueues SQS job
- `ansible/roles/hardening/` — wraps konstruktoid.hardening with production settings (key-only SSH)
- `ansible/roles/kvm/` — libvirt enabled, hugepages configured, cape user groups, default network disabled
- `ansible/roles/networking/` — virbr-det libvirt isolated network, iptables air-gap DROP rules, netfilter-persistent
- `ansible/roles/wireguard/` — wg0 server config from Secrets Manager, wg-quick@wg0 service
- `ansible/roles/cape/` — DSDT patch via kvm-qemu.sh, cape2.sh, cape.conf/api.conf/kvm.conf, systemd services
- `ansible/roles/sqs-agent/` — systemd service polling SQS, submitting to Cape, uploading reports to S3

---

## Next build — guest VM and network simulation

Design decisions resolved (see docs/DECISIONS.md ADR-009, ADR-010, ADR-011, ADR-012, ADR-013):
- Windows 10 22H2 Enterprise evaluation ISO
- cape-agent.py (Python in-guest)
- INetSim on host for network simulation
- Anti-evasion: resolution, CPU, RAM, disk, hostname/username, decoy files, CPUID mask
- Two guest snapshots: `clean` and `office` (LibreOffice); tag-based routing via kvm.conf

### Ansible roles to build

- [x] **`ansible/roles/inetsim/`** — Install and configure INetSim on the bare metal host
      - Installs `inetsim` package (Ubuntu universe)
      - Templates `/etc/inetsim/inetsim.conf`: binds to `{{ detonation_gateway }}` only
        (not 0.0.0.0), enables DNS/HTTP/HTTPS/SMTP/FTP, sets `report_dir`
      - Systemd drop-in `/etc/systemd/system/inetsim.service.d/after-libvirtd.conf`:
        `Requires=libvirtd.service` / `After=libvirtd.service` so virbr-det bridge IP
        exists before INetSim tries to bind (prevents boot-time bind failure)
      - Enables and starts `inetsim` systemd service
      - *Files:* `ansible/roles/inetsim/tasks/main.yml`, `templates/inetsim.conf.j2`,
                 `defaults/main.yml`, `handlers/main.yml`

- [x] **`ansible/roles/networking/` — add INetSim INPUT rules**
      - ACCEPT on INPUT chain for virbr-det → host: DNS UDP/TCP (53), HTTP (80),
        HTTPS (443), SMTP (25), FTP (21), Cape resultserver (2042)
      - All 7 rules use `-C` check before insert (idempotent)
      - Persisted by `netfilter-persistent save` at end of networking tasks
      - *Files:* `ansible/roles/networking/tasks/main.yml`

- [x] **`ansible/roles/cape/` — add `routing.conf` template**
      - `internet_access = no`, `inetsim = yes`, `inetsim_server = <virbr-det gateway IP>`
      - Cape uses this to configure per-analysis guest DNS and route guest traffic to INetSim
      - *Files:* `ansible/roles/cape/templates/routing.conf.j2`, tasks appended to `main.yml`

### Packer image to build

- [!] **`packer/windows10-guest.pkr.hcl`** — **On hold pending ISO sourcing** (see ADR-009)
      - Windows 10 eval ISO removed by Microsoft (EOL Oct 2025); need to source ISO via other means
      - Templates are complete and will be used once a Win10 ISO is available — do not delete
      - Do not build until ISO is sourced and path/checksum set in packer.auto.pkrvars.hcl
      - Installs Python 3.11 and cape-agent.py; Scheduled Task starts agent at boot (port 8000)
      - Output: qcow2 base image for libvirt snapshot
      Anti-evasion measures baked into image (ADR-012):
      - Screen resolution: 1920x1080 (registry + live ChangeDisplaySettings)
      - CPU cores: 2, RAM: 4096 MB, disk: 60 GB
      - Hostname: DESKTOP-XXXXXXX pattern (`guest_hostname` Packer variable)
      - Username: realistic first-name (`guest_username` Packer variable, default `jsmith`)
      - Decoy files: Documents/Downloads/Desktop populated with realistic work files
      - Windows Defender fully suppressed (Tamper Protection + GP keys + scheduled tasks)
      - *Files:* `packer/windows10-guest.pkr.hcl`, `packer/answer-files/autounattend.xml`,
                 `packer/scripts/windows/*.ps1` (8 provisioner scripts)

- [x] **`ansible/roles/cape/` — CPUID hypervisor bit mask in libvirt XML template** (ADR-012)
      - `<feature policy='disable' name='hypervisor'/>` in `host-passthrough` CPU block
      - TSC in native mode (reduces rdtsc timing delta detection)
      - `on_reboot=destroy` so sample reboots end the analysis cleanly
      - *Files:* `ansible/roles/cape/templates/guest-domain.xml.j2`

- [!] **`packer/windows10-office.pkr.hcl`** — **On hold pending Win10 ISO sourcing**
      - Boots from `windows10-guest.qcow2`, installs LibreOffice, outputs `windows10-office.qcow2`
      - WinRM as guest user (`jsmith`) — Administrator is disabled by base cleanup.ps1
      - Macro security set to LOW in LibreOffice user profile (required for VBA detonation)
      - File associations registered for .doc/.docm/.xls/.xlsm/.odt/.ppt and Open Document variants
      - *Files:* `packer/windows10-office.pkr.hcl`, `packer/scripts/windows/install-libreoffice.ps1`

- [x] **`ansible/roles/cape/` — `kvm.conf` machine profile stanzas** (see ADR-013)
      - `[clean]` and `[office]` machine stanzas via `cape_guests` list in `ansible/vars/main.yml`
      - Tag `office` routes Office document samples to the LibreOffice guest
      - All other samples → `clean` profile (no tag)
      - *Files:* `ansible/roles/cape/tasks/main.yml`, `ansible/vars/main.yml`,
                 `ansible/roles/cape/defaults/main.yml`

### Snapshot workflow (manual — after Ansible runs)

Once Ansible has defined the libvirt domains and the qcow2 images are on the host:

```
# Start the VM, verify cape-agent.py is listening, then shut it down cleanly
virsh start clean && sleep 60 && virsh shutdown clean

# Take the snapshot (disk-only = fast, no memory state needed)
virsh snapshot-create-as clean  clean  --disk-only --atomic
virsh snapshot-create-as office office --disk-only --atomic
```

Cape restores from these snapshots at the start of each analysis run.

### Packer build — required variables before first build

The supply chain fixes (2026-04-02) removed all version defaults. Before running either
Packer build, populate `packer/packer.auto.pkrvars.hcl` with the following:

```hcl
# Windows 10 guest (windows10-guest.pkr.hcl)
iso_path       = "/path/to/Win10_22H2_EnterpriseEval.iso"
iso_checksum   = "sha256:<checksum>"   # sha256sum <iso>

python_version  = "3.x.x"             # https://www.python.org/downloads/windows/
python_checksum = "<sha256>"           # listed on the Python release page beside "Windows installer (64-bit)"

cape_agent_commit = "<commit-sha>"     # https://github.com/kevoreilly/CAPEv2/commits/master/agent/agent.py
cape_agent_sha256 = "<sha256>"         # curl -sL https://raw.githubusercontent.com/kevoreilly/CAPEv2/<commit>/agent/agent.py | sha256sum

# Windows 10 office (windows10-office.pkr.hcl) — also needs the above guest vars
libreoffice_version  = "x.x.x"        # https://www.libreoffice.org/download/download-libreoffice/
libreoffice_checksum = "<sha256>"      # listed on the LibreOffice download page (Checksum column)
```

---

## Review findings (2026-03-30) — Automated security scan

Issues identified by automated security review tool. Work through each: fix, defer, or accept.

### Critical

- [x] **DSDT sed injection risk.**
      Fixed 2026-03-30. Switched sed delimiter from `/` to `|`. DSDT values are pure hex
      (`[0-9a-f]`) so `|` can never appear in the value, eliminating the injection surface
      without requiring escaping.
      *Files:* `ansible/roles/cape/tasks/main.yml`

- [x] **Cape API key written to plaintext env file on disk.**
      Fixed 2026-03-30. Replaced `CAPE_API_KEY=<value>` in the env file with
      `CAPE_API_SECRET_ARN=<arn>`. The agent now fetches the key at startup from Secrets
      Manager using its assumed-role credentials — the key is held in process memory only,
      never written to disk. Removed the Cape secret Ansible-time fetch from the sqs-agent
      role (key is no longer needed at deploy time).
      *Files:* `ansible/roles/sqs-agent/templates/sqs-agent.env.j2`,
               `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`,
               `ansible/roles/sqs-agent/tasks/main.yml`

### High

- [x] **RDS CloudWatch log groups not KMS-encrypted with project key.**
      Fixed 2026-03-30. Added explicit `aws_cloudwatch_log_group` resources for
      `postgresql` and `upgrade` log streams with `kms_key_id` set to the project KMS key
      and `retention_in_days = 90`. Added `depends_on` to the RDS instance so groups exist
      before RDS starts writing. Without this, AWS auto-creates groups using the default
      managed key.
      *Files:* `aws/modules/rds/main.tf`

- [x] **Lambda permission source ARN uses HTTP method wildcard.**
      Fixed 2026-03-30. Changed `source_arn` from `/*/*/submit` to
      `/$default/POST/submit` — now matches only the `$default` stage and `POST` method,
      consistent with the IAM submitter policy in the same file.
      *Files:* `aws/modules/api/main.tf`

### Medium

- [x] **No S3 object size check before sample download in sqs-agent.**
      Fixed 2026-03-30. Added `head_object` call in `download_sample()` before any data
      is transferred. Raises `ValueError` if `ContentLength` exceeds `MAX_SAMPLE_BYTES`
      (default 256 MB, configurable via `sqs_agent_max_sample_bytes`). `process_message()`
      catches `ValueError` and returns `True` (delete message) — oversized samples are
      unrecoverable and should not be retried.
      *Files:* `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`,
               `ansible/roles/sqs-agent/templates/sqs-agent.env.j2`,
               `ansible/roles/sqs-agent/defaults/main.yml`

- [x] **STS AssumeRole failure not explicitly caught in sqs-agent `_refresh()`.**
      Fixed 2026-03-30. Wrapped `assume_role()` in a `try/except ClientError` that logs
      the role ARN and error before re-raising. Differentiates "STS broken" from transient
      SQS errors in `journalctl` output.
      *Files:* `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`

- [x] **No Cape API health check on sqs-agent startup.**
      Fixed 2026-03-30. Added a `GET /apiv2/cuckoo/status/` check in `main()` after the
      API key is loaded, before entering the poll loop. On failure the agent calls
      `sys.exit(1)` with a clear error naming the URL and exception — systemd will report
      the service as failed immediately rather than appearing healthy for 5 minutes.
      *Files:* `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`

### Low

- [x] **No CloudTrail Terraform resource.**
      Fixed 2026-04-01. Added `aws_cloudtrail` with a dedicated S3 bucket encrypted
      with the project KMS key. Added `aws_kms_key_policy` to grant CloudTrail
      `kms:GenerateDataKey*` and `kms:DescribeKey` while preserving root admin access.
      Captures management events (free), S3 data events for samples and reports buckets,
      and Lambda invocation events. Log file validation enabled. 365-day retention.
      *Files:* `aws/envs/prod/main.tf`

- [~] **Cape API key and WireGuard keys have no rotation procedure.** *(deferred — revisit when feature-complete)*
      Both use `lifecycle { ignore_changes }` — static until manually rotated. No documented
      cadence or runbook. Rotation requires: generate new key, update Secrets Manager,
      re-run Ansible configure, restart services.
      *Files:* `aws/envs/prod/main.tf`

---

## Review findings (2026-03-30) — Full system cross-component review

Issues identified during full-system assessment, focusing on toxic pairs and unexpected
interactions between components. Work through each: fix, defer, or accept.

### High — toxic pairs / unexpected interactions

- [x] **Pre-signed URL race: SQS message enqueued before sample is uploaded.**
      Fixed 2026-03-30. Split `sample_submitter.py` into two phases. Phase 1 (API GW):
      embeds job metadata (task_id, sha256, tags) in the pre-signed URL signature via
      S3 object metadata — client MUST send x-amz-meta-* headers or PUT fails with 403.
      Phase 2 (S3 ObjectCreated on samples/): reads metadata via head_object, enqueues SQS.
      Job is now only enqueued after S3 confirms the object exists. Added S3 event
      notification on samples bucket → sample_submitter, and Lambda permission for
      samples bucket to invoke the function.
      *Files:* `src/sample_submitter.py`, `aws/modules/lambda/main.tf`,
               `aws/envs/prod/main.tf`

- [x] **Cape API binding may not respect `api.conf [api] url`.**
      Fixed 2026-03-30. Confirmed via CAPEv2 source that `api.conf [api] url` is the
      display/callback URL only — it does not control the bind address. The real bind
      address is the `runserver_plus 0.0.0.0:8000` argument in
      `/lib/systemd/system/cape-web.service`. Added a `lineinfile` task that rewrites that
      argument to the WireGuard IP after `cape2.sh` installs the unit file. Updated the
      `url` task comment to clarify it is for display purposes only.
      *Files:* `ansible/roles/cape/tasks/main.yml`

- [x] **Lambda Secrets Manager policy is over-scoped.**
      Fixed 2026-03-30. Replaced `secrets_arn_prefix/*` wildcard with the two exact ARNs
      Lambda needs: `var.db_secret_arn` and `var.cape_api_secret_arn`. Removed the
      `secrets_arn_prefix` variable from the lambda module interface and the composition
      layer entirely — it only existed to enable the wildcard.
      *Files:* `aws/modules/lambda/main.tf`, `aws/modules/lambda/variables.tf`,
               `aws/envs/prod/main.tf`

### Medium — operational risks

- [~] **iptables rule ordering not guaranteed after libvirtd restart.** *(deferred)*
      libvirtd re-inserts its own FORWARD rules on restart, potentially ahead of the DROP
      rules. The detonation network uses an isolated libvirt network (no `<forward>` element)
      so libvirt adds no external ACCEPT rules today — risk is low. Robust fix would use a
      libvirt hook script (`/etc/libvirt/hooks/network`) to re-insert DROP rules whenever
      the detonation network starts. Deferred: requires live testing on bare metal; current
      risk is mitigated by the isolated network type.
      *Files:* `ansible/roles/networking/tasks/main.yml`

- [~] **Duplicate IOC records possible in RDS on Lambda retry.** *(deferred — revisit when report_processor is implemented)*
      S3 event delivery retries up to 3× on Lambda failure. If `report_processor` is retried
      after a partial write, the same report gets processed twice. Fix: use
      `INSERT ... ON CONFLICT DO NOTHING` keyed on `(task_id, ioc_value)` in the RDS schema.
      *Files:* `src/report_processor.py` (stub — not yet implemented)

### Documentation — stale after Ansible implementation

- [x] **CLAUDE.md "Build next" still lists Ansible roles as unbuilt.**
      Fixed 2026-03-30. Removed the six-role list; section now points to STATUS.md and
      lists only `report_processor.py` as remaining.
      *Files:* `CLAUDE.md`

- [x] **ARCHITECTURE.md says "All roles are currently stubs".**
      Fixed 2026-03-30. Updated to "All roles are complete."
      *Files:* `ARCHITECTURE.md`

---

## Review findings (2026-03-30) — Ansible roles post-implementation review

Issues identified after Ansible role implementation. Work through each: fix, defer, or accept.

### Critical — security/functionality blockers

- [x] **Cape API key not enforced at startup.**
      Fixed 2026-03-30. Changed `os.environ.get("CAPE_API_KEY", "")` to
      `os.environ["CAPE_API_KEY"]` — raises `KeyError` at startup if missing.
      Removed silent empty-headers fallback in `_cape_headers()`.
      *Files:* `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`

- [x] **Cape race condition — services may auto-start during cape2.sh.**
      Fixed 2026-03-30. Added explicit stop of cape/cape-web/cape-processor before
      the ini_file config block, guarded by `when: cape_service_file.stat.exists`
      so it's a no-op on first install. `failed_when: false` handles the case where
      cape2.sh hasn't created units yet.
      *Files:* `ansible/roles/cape/tasks/main.yml`

- [x] **Empty S3 bucket names / missing ARN validation in vars.**
      Fixed 2026-03-30. Added `pre_tasks` assert block in `site.yml` that validates all
      five required vars (both S3 buckets + three secret ARNs) before any role runs.
      Fail message includes the exact `terraform output` commands to populate each value.
      *Files:* `ansible/site.yml`

### High — operational correctness

- [x] **Secrets Manager fetch has no explicit failure check.**
      Fixed 2026-03-30. Added `failed_when: rc != 0 or stdout | length == 0` to all four
      AWS CLI fetches (cape, wireguard, baremetal, cape-in-sqs-agent). Wrong ARN or missing
      credentials now fails with a clear Ansible task error rather than an obscure JSON parse
      error in the following task.
      *Files:* `ansible/roles/cape/tasks/main.yml`, `ansible/roles/wireguard/tasks/main.yml`,
               `ansible/roles/sqs-agent/tasks/main.yml`

- [x] **iptables rule duplication on re-run.**
      Fixed 2026-03-30. Replaced bare `insert` tasks with check-then-insert pattern:
      `iptables -C` checks for the rule first (rc=0 if exists, rc=1 if absent);
      the insert task only runs when rc != 0. Rules still inserted at positions 1 and 2
      to stay ahead of libvirt's ACCEPT rules.
      *Files:* `ansible/roles/networking/tasks/main.yml`

- [x] **Hugepages count hardcoded in GRUB line.**
      Fixed 2026-03-30. Created `roles/kvm/defaults/main.yml` with `kvm_hugepages_2mb: 4096`.
      Both the GRUB lineinfile and sysctl tasks now reference the variable. Override in
      `ansible/vars/main.yml` to tune for larger hosts (RISE-1: 16384 = 32 GB).
      *Files:* `ansible/roles/kvm/tasks/main.yml`, `ansible/roles/kvm/defaults/main.yml`

### Medium — resilience/code quality

- [x] **SQS message validation — infinite retry on malformed messages.**
      Fixed 2026-03-30. Added up-front key check before unpacking body fields. Missing
      keys are logged and the message is deleted (return True) rather than retried.
      *Files:* `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`

- [x] **`failed_when: false` on `virsh net-start`.**
      Fixed 2026-03-30. Removed `failed_when: false` — a failed net-start now aborts
      the play. All downstream tasks (iptables rules, Cape bridge config) depend on the
      bridge existing; silent failure here would produce a misconfigured host.
      *Files:* `ansible/roles/networking/tasks/main.yml`

- [x] **s3-sync stub directory should be deleted.**
      Fixed 2026-03-30. Deleted `ansible/roles/s3-sync/` — role was superseded by
      sqs-agent (ADR-003) and not called from site.yml.
      *Files:* `ansible/roles/s3-sync/` (removed)

- [~] **`except Exception` too broad in sqs agent.** *(deferred)*
      Specific catches for `ClientError` and `requests.RequestException` already sit above
      it. The broad catch only fires on truly unexpected errors — DLQ max-receive is the
      backstop. Narrow further when the full error surface is better understood in production.
      *Files:* `ansible/roles/sqs-agent/templates/sqs_agent.py.j2`

---

## Review findings (2026-03-30)

Issues identified during second architecture/security review. Address criticals and highs
before Ansible role implementation.

### Critical — blocks terraform apply

- [x] **SQS module: missing `resource` declaration for `aws_secretsmanager_secret.baremetal_credentials`.**
      Line 246 of `aws/modules/sqs/main.tf` has the block body (name, description, kms_key_id, tags)
      but the `resource "aws_secretsmanager_secret" "baremetal_credentials" {` opener is missing.
      `terraform plan` will fail with a parse error.
      *Files:* `aws/modules/sqs/main.tf`

### Security — high priority

- [x] **VPC Flow Log IAM role uses `Resource = "*"`.**
      The `aws_iam_role_policy.flow_log` policy allows `logs:CreateLogGroup/Stream/PutLogEvents`
      on all CloudWatch log groups. Should be scoped to the specific flow log group ARN.
      *Files:* `aws/modules/vpc/main.tf`

- [x] **Packer: `shutdown_command` echoes `ssh_password` into build logs.**
      `echo '${var.ssh_password}' | sudo -S shutdown -P now` — the packer user already has
      `NOPASSWD:ALL` from user-data sudoers, so the password flag is unnecessary.
      Fix: `sudo shutdown -P now`.
      *Files:* `packer/ubuntu-sandbox.pkr.hcl`

- [x] **Packer: `pip3 install || true` silently swallows dependency failures.**
      A broken CAPEv2 requirements install produces a healthy-looking image that fails at runtime.
      Remove `|| true` so the build fails fast on dependency errors.
      *Files:* `packer/ubuntu-sandbox.pkr.hcl`

### Operational — medium priority

- [x] **Lambda CloudWatch log retention inconsistent with rest of stack.**
      Lambda logs retain 30 days; VPC flow logs and API Gateway logs retain 90 days.
      Forensic consistency argues for 90 days across all log groups.
      *Files:* `aws/modules/lambda/main.tf`

- [x] **SQS visibility timeout has no buffer for post-analysis S3 upload.**
      Fixed 2026-03-30. Raised default from 3600s to 5400s (90 min): 60 min worst-case
      analysis + 30 min buffer for report upload. Prevents duplicate detonations on
      slow or complex samples.
      *Files:* `aws/modules/sqs/variables.tf`

- [x] **`budget_alert_emails` variable has no non-empty validation.**
      Fixed 2026-03-30. Added validation block — `terraform plan` now fails with a clear
      error message if the list is empty rather than silently creating a budget that notifies nobody.
      *Files:* `aws/envs/prod/variables.tf`

- [ ] **`report_processor.py` uses `os.environ["AWS_REGION_NAME"]` without fallback.**
      `sample_submitter.py` uses `.get(..., "us-east-1")` — `report_processor.py` should match.
      **Deferred** — fix when implementing the real handler (post-Cape). File is a stub; no value in patching it now.
      *Files:* `src/report_processor.py`

### Documentation — medium priority

- [x] **CLAUDE.md "Build next" section lists completed work as pending.**
      Fixed 2026-03-30. Replaced stale 9-item list with a pointer to STATUS.md and
      the actual remaining work (Ansible roles + report_processor stub).
      *Files:* `CLAUDE.md`

- [x] **COST_ESTIMATE.md summary arithmetic is wrong.**
      Fixed 2026-03-30. Table was correct ($108/$148); narrative text had stale figures.
      Corrected narrative to match: ADVANCE-1 ~$148, RISE-1 ~$108.
      *Files:* `docs/COST_ESTIMATE.md`

- [x] **STATUS.md "Next session recommendation" section is redundant.**
      Fixed 2026-03-30. Removed — all items were already resolved and tracked in the findings sections.
      *Files:* `docs/STATUS.md`

- [x] **ARCHITECTURE.md implies Ansible roles are implemented.**
      Fixed 2026-03-30. Added status note above the roles table pointing to STATUS.md.
      *Files:* `ARCHITECTURE.md`

---

## Review findings (2026-03-29)

Issues identified during architecture/security review. Investigate and address
in the next round of implementation work.

### Security — high priority

- [x] **Bare metal IAM: long-lived access keys on a host that runs malware.**
      Fixed 2026-03-29. IAM user scoped to `sts:AssumeRole` only. Real SQS/S3/KMS
      permissions moved to `aws_iam_role.baremetal_agent` (1-hour sessions).
      Role ARN added to Secrets Manager secret. Queue policy updated to role ARN.
      CloudTrail remains the detection surface for anomalous AssumeRole calls.
      *Files:* `aws/modules/sqs/main.tf`, `aws/modules/sqs/outputs.tf`

- [x] **Lambda SG egress hardcodes VPC CIDR (`10.20.0.0/16`).**
      Fixed 2026-03-29. Removed inline egress blocks from Lambda SG. Added
      `aws_vpc_security_group_egress_rule` resources in `prod/main.tf`:
      port 5432 → RDS SG via `referenced_security_group_id`; port 443 → `var.vpc_cidr`.
      All cross-module SG wiring is now in the composition layer.
      *Files:* `aws/modules/lambda/main.tf`, `aws/envs/prod/main.tf`

- [x] **RDS security group allows unrestricted egress (`0.0.0.0/0`).**
      Fixed 2026-03-29. Explicit `egress = []` — Terraform will remove the
      default allow-all rule. SGs are stateful; response traffic needs no rule.
      *Files:* `aws/modules/rds/main.tf`

- [~] **S3 Object Lock uses GOVERNANCE mode, not COMPLIANCE.**
      Intentional decision — see ADR-007. GOVERNANCE is correct for current use case;
      COMPLIANCE would prevent purging samples under a legal takedown or policy change.
      Known limitation: does not meet evidentiary chain-of-custody standards.
      Upgrade path documented in ADR-007 and in-code comment. One-line change when needed.
      *Files:* `aws/modules/s3/main.tf`, `docs/DECISIONS.md` (ADR-007)

- [x] **No Secrets Manager rotation configured.**
      Fixed 2026-03-29. RDS password rotates every 30 days via AWS SAR rotation Lambda
      (`SecretsManagerRDSPostgreSQLRotationSingleUser`). Lambda runs in the VPC with
      its own SG (egress to RDS 5432 + Secrets Manager endpoint 443). Rotation Lambda
      ingress rule added to RDS SG in composition layer.
      Cape API key and WireGuard keys are not rotated — both are set manually and have
      no AWS-native rotation path. Operator rotates manually as needed.
      *Files:* `aws/envs/prod/main.tf`

### Operational — high priority

- [x] **No DLQ alarm.**
      Fixed 2026-03-29. `aws_cloudwatch_metric_alarm.dlq_depth` added to SQS module.
      Fires when any message lands in the DLQ. Optional `alarm_sns_topic_arns` variable
      wires it to an SNS topic — alarm exists and changes state regardless.
      *Files:* `aws/modules/sqs/main.tf`, `aws/modules/sqs/variables.tf`, `aws/modules/sqs/outputs.tf`

- [ ] **No VPC Flow Log alerting.** Logs go to CloudWatch but nothing watches
      them. **Deferred → future scope.** With tight SG rules in place, the VPC
      attack surface is narrow and flow log alerting has low signal-to-noise for
      this architecture. The detonation network (where malware runs) is on OVH —
      not visible to AWS VPC flow logs at all. CloudTrail (AssumeRole calls, S3
      access) is higher-value monitoring for this threat model. Logs retained for
      forensic use.

- [ ] **Reports bucket has no object lock or expiration.** Samples bucket has
      object lock (good), but reports accumulate indefinitely with no tamper
      protection and no lifecycle expiration.
      **Deferred → future scope.** Reports are re-generatable by re-running the
      sample — object lock has low value here. Existing lifecycle rule already
      moves reports to Glacier after 90 days, so accumulation cost is minimal.
      Expiration rule (e.g. 2 years) is a cost hygiene item, not a security issue.

- [x] **SQS visibility timeout (30 min) may be too short.**
      Fixed 2026-03-29. Default raised to 60 min in `variables.tf`.
      *Files:* `aws/modules/sqs/variables.tf`

### Architecture — medium priority

- [ ] **RDS ingress rule wired in composition layer, not the module.**
      If someone writes a new environment and forgets the rule, Lambda silently
      can't reach the DB. Consider accepting `allowed_security_group_ids` as a
      variable in the RDS module.
      *Files:* `aws/modules/rds/main.tf`, `aws/envs/prod/main.tf`

- [x] **Lambda deployment packages don't exist.**
      Fixed 2026-03-29. `src/report_processor.py` and `src/sample_submitter.py`
      created as functional stubs. `make lambda` builds the zips. tfvars.example
      updated with correct paths. `terraform apply` will now succeed.
      *Files:* `src/`, `Makefile`, `aws/envs/prod/terraform.tfvars.example`

- [x] **`shared/backend-aws.hcl` has placeholder bucket name.**
      Fixed 2026-03-29. Added `make configure-backend` — reads bootstrap outputs and
      writes the file with real values. First-time setup order documented in `make help`.
      *Files:* `Makefile`

### Operational — medium priority

- [x] **No budget alerts.**
      Fixed 2026-03-29. `aws_budgets_budget.monthly` alerts at 80% actual and 100%
      forecasted against a configurable limit (default $75/month). Email addresses set
      via `budget_alert_emails` in terraform.tfvars.
      *Files:* `aws/envs/prod/main.tf`, `aws/envs/prod/variables.tf`, `aws/envs/prod/terraform.tfvars.example`

- [ ] **No CloudWatch dashboard.** No unified view of Lambda errors, SQS queue
      depth, RDS connections, or S3 request rates.
      **Deferred → low priority / future scope**

- [ ] **No backup/restore documentation for RDS.** 7-day retention + final
      snapshot configured, but no documented restore procedure.
      **Deferred → low priority / future scope**

---

## Lambda handlers — implementation status

- [x] **`src/sample_submitter.py` — implemented 2026-03-29.**
      Validates `{filename, sha256, tags}` → sanitizes filename (path traversal strip)
      → generates pre-signed S3 PUT URL (15 min TTL) → enqueues SQS job
      → returns `{task_id, upload_url, expires_in, s3_key}`. boto3 clients
      initialised at module level for warm-start reuse. Full input validation
      and structured error responses.

- [ ] **`src/report_processor.py` — defer until Cape is running.**
      Needs real Cape JSON report output to define the parser and RDS schema correctly.
      Building it blind risks getting the schema wrong and rewriting it anyway.
      **Do after:** OVH provisioned → Ansible configured → Cape running → sample detonated
      → actual report JSON captured. Then implement parser + define RDS tables together.
      **Planned features (implement once real report JSON is available):**
      - Parse Cape report JSON → normalize IOCs → write to RDS (dedup via `INSERT ... ON CONFLICT DO NOTHING`)
      - Network behavior heuristics: evaluate `network.dns`, `network.http`, `network.tcp` for
        signals suggesting the sample went dormant due to INetSim (high NXDOMAIN rate, repeated
        connection attempts to same host, low API call count despite network probes, process exit
        within 30s with no file/registry writes). Alert operator with specific domain/IP clusters
        observed so they can decide whether selective passthrough is warranted for re-analysis.
      - TLS certificate pinning detection: repeated TLS handshake failures to same host → flag
        separately (passthrough won't help; different analysis approach needed)

---

## Deferred housekeeping

- **Sandbox AWS account root email** — created with a plus-addressed email on a mail
  host that does not support plus addressing. Root inbox is unreachable. Low risk since
  all operations go through IAM roles via Organizations, but root account recovery would
  be blocked if ever needed. Fix: log into the sandbox account as root via the AWS
  console and update the root email to a reachable address.

---

## Future scope (not started, not prioritised)

- RDS ingress rule: move from composition layer into RDS module (accept `allowed_security_group_ids` variable)
- CloudWatch dashboard: Lambda errors, SQS depth, RDS connections, S3 request rates
- RDS backup/restore runbook
- VPC Flow Log alerting — low value given tight SGs; CloudTrail is higher signal for this threat model
- Reports bucket expiration rule (~2 years) — cost hygiene; object lock not warranted (reports are re-generatable)
- Static analysis agent (Ghidra headless / Binary Ninja API)
- Memory forensics agent (Volatility 3 post-detonation)
- Agent orchestration layer (Step Functions or separate service)
- Windows guest Packer image (Cape detonation VM) — starting with Windows 10 22H2; evaluate adding Windows 11 once Win10 lab is stable and producing real sample volume
- Windows guest image rotation runbook — evaluation ISO expires every 90 days; document the rebuild-and-redeploy procedure (Packer rebuild → replace libvirt base image → restore clean snapshot) before first guest is deployed
- Cape injected agent (capemon DLL) — currently using cape-agent.py; evaluate capemon injection once evasion is observed in practice (see ADR-010)
- Microsoft Office guest profile — if LibreOffice macro compatibility proves insufficient for VBA-heavy samples, build a third snapshot with Microsoft Office evaluation installed; requires Microsoft account for ISO download (see ADR-013)
- Guest user activity simulation — mouse movement, file opens, simulated idle behavior to defeat activity-check evasion; high effort, marginal payoff for most samples; revisit if dormancy-on-idle is observed frequently in practice (see ADR-012)
- Guest network adapter MAC/OUI randomization — QEMU default OUI `52:54:00` is known; low priority, revisit if OUI-based detection is observed (see ADR-012)
- Alternative bare metal provider module (Vultr/Latitude.sh) if OVH proves unworkable
