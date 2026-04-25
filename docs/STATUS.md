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
│   ├── DECISIONS.md               ✓ ADR log (through ADR-016)
│   ├── SECURITY_CONSTRAINTS.md    ✓ non-negotiables with rationale
│   ├── COST_ESTIMATE.md           ✓ monthly cost breakdown
│   └── STATUS.md                  ✓ this file
│
├── packer/
│   ├── windows11-base.pkr.hcl     ✓ complete (Win11 Enterprise eval, UEFI/TPM, Python, cape-agent)
│   ├── windows11-guest.pkr.hcl    ✓ complete (boots from base, runs cleanup, disables WinRM)
│   ├── windows11-office.pkr.hcl   ✓ complete (boots from base, adds LibreOffice, macro security LOW)
│   ├── ubuntu-sandbox.pkr.hcl     ✓ complete (hardened Ubuntu 24.04 base)
│   ├── answer-files/
│   │   └── autounattend.xml       ✓ complete (unattended Win11 install, WinRM, eval ISO)
│   ├── scripts/windows/           ✓ complete (8 PowerShell provisioner scripts)
│   ├── ansible/
│   │   └── hardening.yml          ✓ complete (konstruktoid.hardening playbook)
│   └── http/
│       ├── meta-data              ✓ complete
│       └── user-data              ✓ complete (placeholder hash — run make packer-setup)
│
├── ansible/
│   ├── site.yml                   ✓ complete (10 roles in order)
│   ├── requirements.yml           ✓ complete (konstruktoid.hardening, community.general)
│   ├── inventory/
│   │   └── hosts.example          ✓ exists
│   ├── vars/
│   │   ├── main.yml               ✓ non-sensitive config (gitignored)
│   │   ├── secrets.yml            ✓ cape_api_key + bazaar_auth_key (gitignored, vault-encrypted)
│   │   └── secrets.yml.example    ✓ committed template
│   └── roles/
│       ├── hardening/             ✓ wraps konstruktoid.hardening (CIS baseline)
│       ├── kvm/                   ✓ libvirt, hugepages, groups, disable default net
│       ├── networking/            ✓ virbr-det bridge, iptables air-gap, INetSim INPUT rules
│       ├── inetsim/               ✓ DNS/HTTP/HTTPS/SMTP/FTP simulation on virbr-det
│       ├── wireguard/             ✓ keypair on host, peer from vars, wg-quick
│       ├── qemu-patched/          ✓ DSDT-patched QEMU build, cape user/repo, libvirt repair
│       ├── mongodb/               ✓ standalone MongoDB 8.0 (GPG, repo, install, systemd)
│       ├── cape/                  ✓ cape2.sh installer, config, token auth, ordered services
│       ├── cape-guests/           ✓ guest VM images, libvirt domains, automated snapshots
│       └── sample-feeder/         ✓ MalwareBazaar CLI for interactive sample ingestion
│
├── ovh/
│   ├── main.tf                    ✓ complete (firewall, SSH key, OS reinstall, provider v2)
│   ├── variables.tf               ✓ complete
│   ├── outputs.tf                 ✓ complete
│   └── terraform.tfvars.example   ✓ complete
│
├── aws/                           ✗ not deployed — retained for reference (ADR-016)
│
└── src/                           ✗ not deployed — Lambda handlers (retained for reference)
```

**Legend:** ✓ complete · ~ stub/partial · ✗ not built · ! needs fix

---

## Deployment status (2026-04-24)

Fully automated deployment validated 2026-04-23. SalatStealer detonated successfully
from fresh Ubuntu install through automated Ansible playbook. See ADR-016 for AWS
removal rationale.

### Deployment checklist

- [x] **WireGuard keys** — generate your laptop keypair.
      ```
      wg genkey | tee ~/wg-private.key | wg pubkey > ~/wg-public.key
      ```
      Paste the contents of `~/wg-public.key` into `ansible/vars/main.yml` → `wireguard_peer_pubkey`.

- [x] **Secrets** — copy `ansible/vars/secrets.yml.example` to `secrets.yml`, fill in values.
      ```
      cp ansible/vars/secrets.yml.example ansible/vars/secrets.yml
      # Edit secrets.yml: set cape_api_key and bazaar_auth_key
      ansible-vault encrypt ansible/vars/secrets.yml
      ```

- [x] **OVH bare metal provisioning** — provision server, apply firewall, install Ubuntu 24.04.
      ```
      cd ovh && terraform init && terraform apply
      ```
      Then update `ansible/inventory/hosts` with the server IP.

- [x] **Packer guest builds** — build Windows 11 guest images locally in WSL.
      Populate `packer/packer.auto.pkrvars.hcl` first (see checklist below).
      ```
      make image
      ```
      Then `scp` the two qcow2 files to `/home/ubuntu/` on the bare metal host.
      Ansible stages them to `/var/lib/libvirt/images/` automatically.

- [x] **Ansible** — configure bare metal host (KVM, Cape, INetSim, WireGuard, sample-feeder).
      ```
      ansible-galaxy install -r ansible/requirements.yml
      ansible-playbook -i ansible/inventory/hosts ansible/site.yml --ask-vault-pass
      ```
      Snapshots are created automatically during the playbook run.

- [ ] **Cape API key** — generate a real key from Cape web UI and update `secrets.yml`.
      Currently using a placeholder value.

---

## Deployment phases (simplified 2026-04-25)

AWS removed (ADR-016). Full deploy is now 5 phases.

### Phase 1 — OVH bare metal provisioning

```bash
cd ovh
cp terraform.tfvars.example terraform.tfvars  # fill in OVH API creds, admin CIDR, SSH key
terraform init && terraform apply             # ~12 min for OS install
ssh sandbox                                   # verify access
```

### Phase 2 — Secrets setup (one-time)

```bash
# WireGuard keypair
wg genkey | tee ~/wg-private.key | wg pubkey > ~/wg-public.key
# Paste public key into ansible/vars/main.yml → wireguard_peer_pubkey

# Vault secrets
cp ansible/vars/secrets.yml.example ansible/vars/secrets.yml
# Fill in cape_api_key and bazaar_auth_key
ansible-vault encrypt ansible/vars/secrets.yml
```

### Phase 3 — Packer guest images + upload

Build Windows 11 guest images locally in WSL, upload to host.

```bash
cd packer
make image                                              # ~2-3 hours
scp output-guest/windows11-guest.qcow2  sandbox:/home/ubuntu/
scp output/windows11-office.qcow2       sandbox:/home/ubuntu/
```

Ansible stages images from `/home/ubuntu/` to `/var/lib/libvirt/images/` automatically.

### Phase 4 — Ansible configuration

```bash
cd ansible
ansible-galaxy install -r requirements.yml
ansible-playbook -i inventory/hosts site.yml --ask-vault-pass
```

Roles: hardening → kvm → networking → inetsim → wireguard → qemu-patched →
mongodb → cape → cape-guests → sample-feeder.

`qemu-patched` is the slowest (~30-60 min). Snapshots are automated by `cape-guests`.

### Phase 5 — Smoke test

```bash
ssh sandbox
sudo -u cape sample-feeder  # submit a sample from MalwareBazaar
```

Verify in Cape web UI via WireGuard at `http://10.200.0.1:8000`.

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

- `Makefile` — `make image`, `make infra`, `make configure` entry points
- `ovh/` — OVH bare metal module: robot firewall (SSH + WireGuard allowlist), SSH key registration, Ubuntu 24.04 OS install
- `packer/ubuntu-sandbox.pkr.hcl` — hardened Ubuntu 24.04 image: KVM packages, CAPEv2 clone + deps, konstruktoid hardening, qcow2 output
- `packer/windows11-guest.pkr.hcl` — Windows 11 Enterprise eval, Python 3.12, cape-agent, anti-evasion, UEFI/TPM
- `packer/windows11-office.pkr.hcl` — Windows 11 + LibreOffice, macro security LOW, file associations
- `ansible/roles/hardening/` — wraps konstruktoid.hardening with production settings (key-only SSH)
- `ansible/roles/kvm/` — libvirt enabled, hugepages configured, cape user groups, default network disabled
- `ansible/roles/networking/` — virbr-det libvirt isolated network, iptables air-gap DROP rules, netfilter-persistent
- `ansible/roles/inetsim/` — network simulation for guest VM traffic (DNS, HTTP, HTTPS, SMTP, FTP)
- `ansible/roles/wireguard/` — generates host keypair, configures peer from vars, wg-quick@wg0 service
- `ansible/roles/cape/` — DSDT patch via kvm-qemu.sh, cape2.sh, config, services, automated snapshots
- `ansible/roles/sample-feeder/` — MalwareBazaar CLI tool for interactive sample ingestion

### Not deployed (retained for reference)

- `aws/` — full AWS data plane (VPC, S3, SQS, RDS, Lambda, API GW, KMS, Secrets Manager, CloudTrail). Removed per ADR-016. Code retained for potential S3-only re-deployment.
- `ansible/roles/sqs-agent/` — SQS polling agent. Removed from site.yml per ADR-016.
- `src/sample_submitter.py` — Lambda handler. No longer deployed.
- `src/report_processor.py` — Lambda stub. Never implemented.

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

```bash
# Start the VM and wait for cape-agent (first boot takes ~2.5 min)
virsh start clean
for i in $(seq 1 18); do
  curl -s --connect-timeout 3 http://192.168.100.10:8000/ && break
  echo "Waiting for agent... ($((i*10))s)"
  sleep 10
done

# Take external snapshot WITH memory state (required for UEFI/pflash VMs).
# Cape's check_snapshot_state requires state="running" — internal snapshots
# and disk-only snapshots are incompatible with UEFI/OVMF firmware.
virsh snapshot-create-as clean clean \
  --memspec file=/var/lib/libvirt/images/clean.memsnap,snapshot=external \
  --diskspec sda,file=/var/lib/libvirt/images/clean.overlay.qcow2,snapshot=external

# Repeat for office
virsh start office
for i in $(seq 1 18); do
  curl -s --connect-timeout 3 http://192.168.100.11:8000/ && break
  echo "Waiting for agent... ($((i*10))s)"
  sleep 10
done
virsh snapshot-create-as office office \
  --memspec file=/var/lib/libvirt/images/office.memsnap,snapshot=external \
  --diskspec sda,file=/var/lib/libvirt/images/office.overlay.qcow2,snapshot=external

# Shut down after snapshotting
virsh shutdown clean && virsh shutdown office
```

Cape restores from these snapshots at the start of each analysis run.
The `--memspec` flag saves the VM's memory state so Cape sees `state=running`
in the snapshot metadata. Without it, UEFI VMs produce `disk-snapshot` state
which Cape rejects.

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
- Analysis pipeline enrichment (spec approved: `docs/superpowers/specs/2026-04-19-analysis-pipeline-enrichment-design.md`)
  - Stage 1: Triage — YARA (community + custom rules), ssdeep, FLOSS, file type, smart routing
  - Stage 2: Dynamic — Cape (exists), always with memory=1
  - Stage 3: Memory forensics — Volatility 3 (spec: `2026-04-19-volatility3-integration-design.md`)
  - Stage 4: Static deep-dive — Ghidra headless on unpacked payloads from Cape
  - New Ansible roles: `triage`, `volatility`, `ghidra`
  - sqs-agent orchestrates all stages, merges results into single report JSON
  - Input sources: SQS (API Gateway) and sample-feeder CLI (MalwareBazaar)
- Custom Volatility plugins — stock plugins only for v1; custom plugins when analysis patterns emerge
- Custom Ghidra scripts — stock analysis only for v1; config extractors, protocol parsers later
- Cross-stage orchestration — Volatility shellcode extract → Ghidra disassembly, YARA family match → custom Ghidra config extractor; requires decision engine ("agent orchestration layer")
- Memory dump / Ghidra project archival to S3 — not v1; all artifacts re-generable from preserved samples
- Real-time analysis during detonation — VMI/Drakvuf or live Volatility snapshots; high effort, revisit if malware self-cleanup is observed
- MITRE ATT&CK mapping of analysis findings
- Automated YARA rule updates — manual or cron for v1
- Web UI for browsing enriched analysis results — use Cape UI + S3 reports for v1
- Report processor parsing of Volatility/Ghidra output into RDS — defer until real output is available
- Agent orchestration layer (Step Functions or separate service)
- Windows 10 guest Packer image — on hold pending ISO sourcing (Win10 eval ISO removed by Microsoft); Win11 images built and deployed
- Windows guest image rotation runbook — evaluation ISO expires every 90 days; document the rebuild-and-redeploy procedure (Packer rebuild → replace libvirt base image → restore clean snapshot) before first guest is deployed
- Cape agent Python 3.13+ upgrade — currently on 3.12 with cgi monkey-patch; upgrade to 3.13+ once CAPEv2 PR #2786 (cgi removal) is merged upstream. Drop monkey-patch from install-cape-agent.ps1 and pin to new agent commit
- Cape injected agent (capemon DLL) — currently using cape-agent.py; evaluate capemon injection once evasion is observed in practice (see ADR-010)
- Microsoft Office guest profile — if LibreOffice macro compatibility proves insufficient for VBA-heavy samples, build a third snapshot with Microsoft Office evaluation installed; requires Microsoft account for ISO download (see ADR-013)
- Guest user activity simulation — mouse movement, file opens, simulated idle behavior to defeat activity-check evasion; high effort, marginal payoff for most samples; revisit if dormancy-on-idle is observed frequently in practice (see ADR-012)
- Guest network adapter MAC/OUI randomization — QEMU default OUI `52:54:00` is known; low priority, revisit if OUI-based detection is observed (see ADR-012)
- QEMU build optimization — kvm-qemu.sh installs ~500 build-time dev packages (Xen, Spice, Bluetooth, Ceph, GTK headers) on the production host. Compile in a build container or CI pipeline instead, deploy only the binary + runtime deps. Reduces attack surface and deploy time significantly
- S3 evidence archival — standalone S3 bucket with Object Lock for tamper-proof sample/report preservation. Deploy only if chain-of-custody requirements emerge
- Bare metal integrity monitoring from AWS — detect sandbox escape or host compromise from an independent observer:
  - CloudWatch heartbeat: host pushes "healthy" metric every 5 min; missing data triggers alarm
  - CloudWatch canary: periodic SSH checks (iptables intact, expected processes, QEMU binary hash, open ports)
  - AIDE/rkhunter scan results shipped to S3 for external baseline comparison
  - CloudTrail alarms on unexpected STS AssumeRole patterns (new IPs, bulk access)
  - S3 access anomaly detection (unusual download patterns from reports bucket)
- Molecule tests for Ansible roles — container-based role testing for CI validation
- Alternative bare metal provider module (Vultr/Latitude.sh) if OVH proves unworkable
