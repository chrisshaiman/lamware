# Deployment Guide

Step-by-step deployment of the malware analysis sandbox from a clean starting point.
Follow in order — each phase depends on the one before it.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Secrets Setup](#2-secrets-setup)
3. [OVH Bare Metal Provisioning](#3-ovh-bare-metal-provisioning)
4. [DSDT Capture](#4-dsdt-capture)
5. [Ansible Configuration](#5-ansible-configuration)
6. [Packer Guest Image Builds](#6-packer-guest-image-builds)
7. [Libvirt Snapshots](#7-libvirt-snapshots)
8. [Smoke Test](#8-smoke-test)

> **AWS is not part of this deployment.** An earlier design submitted samples through
> API Gateway → S3 → SQS to an agent on the bare metal host. That data plane never
> worked (the Cape API is unreachable without WireGuard) and was decommissioned by
> ADR-016; the code was removed in #211. If you are following an older copy of this
> guide, skip anything mentioning Lambda, SQS, or `make lambda`.

---

## 1. Prerequisites

Everything that must be in place on your local machine before running any command.

### Accounts

- **OVHcloud US account** — bare metal server already ordered and in your account.
  The Terraform OVH module configures an existing server; it does not purchase one.

### Tools

Install all of these before starting. Verify versions with the commands shown.

> **Windows users:** Install WSL2 first and run all commands from a WSL2 terminal.
> The `make` targets are the primary workflow and require a Linux environment — there is
> no benefit to splitting tools between native Windows and WSL2. The one exception is the
> WireGuard GUI app (`wireguard-windows`), which manages the VPN tunnel at the OS level
> and should be installed on native Windows.

```bash
# Terraform >= 1.6
terraform -version

# Ansible >= 2.14
ansible --version

# Packer >= 1.10
packer --version

# WireGuard tools (wg genkey, wg pubkey)
wg --version

# Python 3.12+
python3 --version

# make
make --version

# OpenSSL (used by `make packer-setup` to hash the build password)
openssl version

# QEMU (required on the build host for the Windows Packer build — Linux only)
# apt-get install qemu-system-x86 qemu-utils
qemu-system-x86_64 --version
```

> **Note:** Packer Windows guest builds require QEMU and must run on Linux. Use the bare
> metal host itself (after Phase 7) or any Linux machine with 8 GB+ RAM and 100 GB+ disk.

### OVH API credentials

1. Go to <https://api.us.ovhcloud.com/createApp/> and create an application.
   Note the `application_key` and `application_secret`.

2. Create a consumer token with the required API rights:
   - `GET/PUT/POST/DELETE` on `/dedicated/server/*`
   - `GET/PUT/POST/DELETE` on `/ip/*`
   - `GET/PUT/POST/DELETE` on `/me/sshKey/*`

   The token creation flow is at <https://api.us.ovhcloud.com/1.0/auth/credential>.
   Follow the OVH documentation for the exact steps.

3. Export the credentials or set them in `ovh/terraform.tfvars` (see Phase 5):
   ```bash
   export OVH_ENDPOINT=ovhus
   export OVH_APPLICATION_KEY=<application_key>
   export OVH_APPLICATION_SECRET=<application_secret>
   export OVH_CONSUMER_KEY=<consumer_key>
   ```

### SSH keypair

Generate a dedicated Ed25519 key for Ansible and bare metal access:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/sandbox_ed25519 -C "malware-sandbox"
# Public key (needed in Phase 5):
cat ~/.ssh/sandbox_ed25519.pub
```

### Windows 10 evaluation ISO

Download the Windows 10 22H2 Enterprise Evaluation ISO from Microsoft:
<https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise>

Note the local path and compute its SHA-256 hash (needed in Phase 8):

```bash
sha256sum /path/to/Win10_22H2_EnterpriseEval.iso
```

---

## 2. Secrets Setup

Secrets live in `ansible/vars/secrets.yml`, encrypted with Ansible Vault. Non-secret
tuneables live in `ansible/vars/main.yml`. Both are gitignored and both have a
committed `.example` to copy from.

```bash
cp ansible/vars/main.yml.example    ansible/vars/main.yml
cp ansible/vars/secrets.yml.example ansible/vars/secrets.yml
# fill in secrets.yml, then encrypt it:
ansible-vault encrypt ansible/vars/secrets.yml
```

`secrets.yml.example` documents each value and how to generate it. At minimum you
need `cape_api_key`, `anthropic_api_key`, `pipeline_db_password`, `lamware_api_key`,
and `keycloak_smoke_test_password`; `bazaar_auth_key` is needed only for the
MalwareBazaar sample feeder.

Every playbook run then takes `--ask-vault-pass` (or `--vault-password-file`):

```bash
ansible-playbook site.yml -i inventory/hosts --ask-vault-pass
```

### 2a. WireGuard keys

Generate your laptop's WireGuard keypair:

```bash
wg genkey | tee ~/wg-private.key | wg pubkey > ~/wg-public.key
chmod 600 ~/wg-private.key
```

Paste the contents of `~/wg-public.key` into `ansible/vars/main.yml` → `wireguard_peer_pubkey`.

The server keypair is generated automatically on the host by the Ansible wireguard role.
The server's private key never leaves the host. After Ansible runs, the host's public key
is printed as a debug message — copy it into your laptop's WireGuard config.

Back up `~/wg-private.key` to your password manager (e.g., LastPass Secure Note).

### 2b. Cape API key

Generate the Cape API key into the vault file:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# paste into cape_api_key in ansible/vars/secrets.yml
```

> The DSDT string used to be a manual step here. It is now captured automatically
> from host firmware by the Cape Ansible role — see Phase 4.

### 2c. Update ansible/vars/main.yml

Fill in the host-specific values:

```yaml
# ansible/vars/main.yml
public_ip:             "<the OVH server's public IP>"
lamware_domain:        "lamware.example.com"
wireguard_peer_pubkey: "<contents of ~/wg-public.key>"
```

`site.yml` asserts the required variables are populated before doing any work, so a
missing value fails the run immediately rather than midway through.

---

## 3. OVH Bare Metal Provisioning

Registers your SSH key with OVH, applies the robot firewall (before OS install),
and installs Ubuntu 24.04.

### 3a. Find your server name

In the OVH Manager: Bare Metal Cloud → Dedicated Servers → your server →
General Information. The service name looks like `ns123456.ip-1-2-3.eu`.

### 3b. Configure OVH tfvars

```bash
cd ovh
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
ovh_application_key    = "<your application_key>"
ovh_application_secret = "<your application_secret>"
ovh_consumer_key       = "<your consumer_key>"

server_name    = "ns123456.ip-1-2-3.eu"   # from OVH Manager
admin_cidrs    = ["YOUR_IP/32"]            # your static IP — check: curl https://checkip.amazonaws.com
ssh_public_key = "ssh-ed25519 AAAA..."    # contents of ~/.ssh/sandbox_ed25519.pub
```

> **Important:** `admin_cidrs` controls the OVH robot firewall — the hardware-level
> firewall applied before traffic reaches the OS. SSH (22) and WireGuard (51820) are
> allowed only from these CIDRs. Set it to your actual static IP before applying.
> If you get locked out, you can recover via the OVH KVM console in the Manager.

### 3c. Apply

```bash
cd ovh
terraform init
terraform apply
```

OVH will reinstall the OS. This takes approximately 15–20 minutes.
The server is available once the OVH Manager shows status "Ready".

```bash
# Verify SSH access (may take a couple minutes after status shows Ready)
ssh -i ~/.ssh/sandbox_ed25519 root@<server-ip>
```

`make infra-ovh` writes the server IP to `ansible/inventory/hosts` automatically.
If you ran terraform directly, create the file manually:

```bash
# ansible/inventory/hosts
[sandbox]
<server-ip>  ansible_user=root  ansible_ssh_private_key_file=~/.ssh/sandbox_ed25519

[sandbox:vars]
ansible_python_interpreter=/usr/bin/python3
```

---

## 4. DSDT Capture

The DSDT string is a hardware-specific ACPI table hex dump used by CAPEv2 to patch
QEMU and defeat VM fingerprinting by malware. It can only be captured from the physical
host after the OS is installed. Without this, sandboxed malware can trivially detect it
is running in a VM.

SSH into the bare metal host and run:

```bash
apt-get install -y acpica-tools
cd /tmp
acpidump -b
iasl -d dsdt.dat
# This produces dsdt.dsl — the DSDT hex string is in the binary dsdt.dat
# Extract the hex dump:
xxd dsdt.dat | head -20   # verify it looks like hex data
```

The `dsdt_string` value used by CAPEv2's `kvm-qemu.sh` is the full hex string from
`dsdt.dat`. Extract it:

```bash
xxd -p dsdt.dat | tr -d '\n'
```

> **This phase is informational.** The Cape Ansible role captures the DSDT string
> directly from host firmware at run time, so there is no manual step and nothing to
> paste into a secret. The commands above are kept because reading the DSDT by hand is
> useful when debugging a guest that detects virtualisation — not because the
> deployment needs them.

---

## 5. Ansible Configuration

Configures the bare metal host: KVM/libvirt, CAPEv2, INetSim, WireGuard, Postgres,
the analysis pipeline, the API, and the dashboard. Secrets come from the Ansible Vault
file created in Phase 2 — no plaintext secrets are stored in the repo.

### 5a. Install Galaxy requirements

```bash
ansible-galaxy install -r ansible/requirements.yml --force-with-deps
```

The controller also needs a Python package that no Galaxy collection can supply —
`netaddr`, which backs the `ansible.utils.ipaddr` filter used by `vars/main.yml`
and the cape, frontend and api roles. Install it into the **same environment as
ansible**:

```bash
pip install -r ansible/requirements-python.txt
```

If ansible came from `uv tool install` or `pipx`, that environment is not the `pip`
on your PATH — use `uv tool install ansible-core --with netaddr` instead. Skipping
this fails partway through `site.yml` with `Failed to import the required Python
library (netaddr)`; `make configure` preflights it and stops early with the fix.

### 5b. Run the playbook

```bash
make configure
# Equivalent to:
# ansible-playbook -i ansible/inventory/hosts -u root \
#   --private-key ~/.ssh/sandbox_ed25519 ansible/site.yml
```

Expected runtime: **45–90 minutes**. The `kvm-qemu.sh` step (building a DSDT-patched
QEMU binary from source) takes 30–60 minutes and is guarded by a stamp file —
it only runs once and is skipped on re-runs.

### 5c. Verify services

SSH into the host and confirm all services are running:

```bash
ssh -i ~/.ssh/sandbox_ed25519 root@<server-ip>

systemctl status cape
systemctl status cape-web
systemctl status cape-processor
systemctl status inetsim
systemctl status wg-quick@wg0
systemctl status lamware-api
systemctl status nginx
systemctl status keycloak

# The pipeline is triggered by a path unit watching the spool directory, so
# pipeline-spool.service resting at inactive/dead is CORRECT — check the .path:
systemctl status pipeline-spool.path
```

All should show `active (running)`.

### 5d. Configure WireGuard on your laptop

Create your local WireGuard config using the keys from Phase 4a:

```ini
# /etc/wireguard/wg-sandbox.conf  (or use WireGuard app on macOS/Windows)
[Interface]
PrivateKey = <contents of ~/wg-private.key>
Address    = 10.200.0.2/32

[Peer]
PublicKey  = <host public key printed by Ansible>
Endpoint   = <server-ip>:51820
AllowedIPs = 10.200.0.1/32
```

```bash
wg-quick up wg-sandbox
# Verify tunnel:
ping 10.200.0.1
```

The Cape web UI is accessible at `http://10.200.0.1:8000` once the tunnel is up.

---

## 6. Packer Guest Image Builds

Builds two Windows 10 guest images:
- `windows10-guest.qcow2` — base image with Python and cape-agent (the `clean` snapshot)
- `windows10-office.qcow2` — extends the base with LibreOffice (the `office` snapshot)

**These builds must run on a Linux machine with QEMU installed.** Options:
- The bare metal host itself (after Phase 7) — preferred for production
- Any Linux machine with sufficient RAM (8 GB+) and disk (100 GB+)
- **WSL2 on Windows** — fully supported if your machine has 8 GB+ RAM free and 100 GB+
  disk available in the WSL2 volume. Install QEMU first:
  `sudo apt-get install -y qemu-system-x86 qemu-utils`

### 6a. One-time Packer setup

Run this once to generate the build password hash and install the Ansible hardening role
used during the Ubuntu base image build:

```bash
cp packer/http/user-data.example packer/http/user-data   # gitignored — copy once
make packer-setup
# Prompts for a build password (used only during Packer build, not in production)
# Prints:
#   1. The password hash — paste into packer/http/user-data
#   2. The ssh_password value — add to packer/packer.auto.pkrvars.hcl
```

Follow the printed instructions exactly.

### 6b. Populate packer.auto.pkrvars.hcl

Create `packer/packer.auto.pkrvars.hcl` (gitignored):

```hcl
# Packer build password (from make packer-setup)
winrm_password = "<password from packer-setup>"

# Windows 10 22H2 Enterprise Evaluation ISO
iso_path     = "/path/to/Win10_22H2_EnterpriseEval.iso"
iso_checksum = "sha256:<sha256sum output>"

# Python — get hash from python.org release page beside "Windows installer (64-bit)"
python_version  = "3.11.9"    # or current stable
python_checksum = "<sha256>"

# cape-agent.py — pin to a specific commit
# Find latest commit: https://github.com/kevoreilly/CAPEv2/commits/master/agent/agent.py
# Get the hash: curl -sL https://raw.githubusercontent.com/kevoreilly/CAPEv2/<commit>/agent/agent.py | sha256sum
cape_agent_commit = "<40-char commit SHA>"
cape_agent_sha256 = "<sha256>"

# LibreOffice — get hash from libreoffice.org download page (Checksum column, .msi row)
libreoffice_version  = "24.8.4"    # or current stable
libreoffice_checksum = "<sha256>"
```

### 6c. Build the base (Ubuntu) image

The Ubuntu sandbox image is built separately and is used as the host base image for OVH
BYOI (Bring Your Own Image) if needed. Skip if you used the OVH standard Ubuntu 24.04
template in Phase 5.

```bash
make image
```

### 6d. Build Windows guest images

Build both Windows images. These are large builds — expect 2–3 hours total.

```bash
cd packer
packer init windows10-guest.pkr.hcl
packer build -var-file=packer.auto.pkrvars.hcl windows10-guest.pkr.hcl

# After windows10-guest.qcow2 is complete:
packer init windows10-office.pkr.hcl
packer build -var-file=packer.auto.pkrvars.hcl windows10-office.pkr.hcl
```

Output files: `packer/output/windows10-guest.qcow2` and `packer/output/windows10-office.qcow2`.

### 6e. Copy images to the bare metal host

```bash
scp -i ~/.ssh/sandbox_ed25519 \
  packer/output/windows10-guest.qcow2 \
  root@<server-ip>:/var/lib/libvirt/images/

scp -i ~/.ssh/sandbox_ed25519 \
  packer/output/windows10-office.qcow2 \
  root@<server-ip>:/var/lib/libvirt/images/
```

### 6f. Re-run Ansible to define libvirt domains

Now that the images are on the host, re-run Ansible to define the libvirt domains
(Ansible skips already-completed steps via stamp files):

```bash
make configure
```

---

## 7. Libvirt Snapshots

Cape restores from a known-good snapshot before each analysis run. You must take these
snapshots manually after verifying the guest images are working.

SSH into the bare metal host:

```bash
ssh -i ~/.ssh/sandbox_ed25519 root@<server-ip>
```

**Clean snapshot (base Windows + cape-agent):**

```bash
# Start the VM and wait for cape-agent to be listening
virsh start clean
sleep 90

# Verify cape-agent is listening on port 8000
virsh domifaddr clean   # get the guest IP (should be 192.168.100.10)
curl http://192.168.100.10:8000   # expect a response from cape-agent

# Shut down cleanly before snapshotting
virsh shutdown clean
# Wait for shutdown (check status):
virsh list --all   # wait until clean shows "shut off"

# Take the snapshot
virsh snapshot-create-as clean --name clean --disk-only --atomic
```

**Office snapshot (Windows + cape-agent + LibreOffice):**

```bash
virsh start office
sleep 120   # LibreOffice first-run initialization takes longer

# Verify cape-agent
virsh domifaddr office   # should be 192.168.100.11
curl http://192.168.100.11:8000

virsh shutdown office
virsh list --all   # wait for shut off

virsh snapshot-create-as office --name office --disk-only --atomic
```

Verify both snapshots exist:

```bash
virsh snapshot-list clean
virsh snapshot-list office
```

---

## 8. Smoke Test

Verify the full pipeline before treating the system as operational.

Samples are submitted **on the host**, not through a cloud API. Connect WireGuard first —
nothing below is reachable without the tunnel.

### 8a. Post-deploy smoke gate

The Playwright gate exercises the live site end to end (auth, navigation, token
audience). It needs `keycloak_smoke_test_password` set in the vault.

```bash
make smoke
```

### 8b. Submit a test sample

EICAR is universally recognised by AV engines and completely harmless:

```bash
ssh -i ~/.ssh/sandbox_ed25519 root@<server-ip>

printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > /tmp/eicar.com

set -a; . /opt/pipeline/pipeline.env; set +a
/opt/pipeline/venv/bin/python -u /opt/pipeline/run-pipeline.py \
  /tmp/eicar.com --task-id smoke-eicar --filename eicar.com
```

### 8c. Watch it run

The command above runs the pipeline in the foreground, so it logs to your terminal.
For samples dropped into the spool directory instead, follow the unit:

```bash
journalctl -u pipeline-spool -f
```

### 8d. Verify the results landed

With WireGuard connected:

- Cape web UI — `http://10.200.0.1:8000`, analysis appears under Recent Analyses
- lamware dashboard — `https://<lamware_domain>`, the sample appears with its report

If the gate passes and the sample completes end to end, the sandbox is operational.

---

## Troubleshooting

### SSH locked out of OVH server

Use the OVH Manager KVM console: Bare Metal Cloud → Dedicated Servers →
your server → KVM / IPMI.

### Ansible fails on kvm-qemu.sh

Check `/tmp/kvm-qemu-patched.sh` was not left behind (it is removed on success).
Re-run with: `ansible-playbook ... --tags cape`

### WireGuard tunnel not connecting

Verify the server-side interface: `wg show wg0`. Check that UDP/51820 is open in
the OVH robot firewall and that `admin_cidrs` in `ovh/terraform.tfvars` matches
your current IP.

### Cape services not starting

```bash
journalctl -u cape -n 50
journalctl -u cape-web -n 50
# Common cause: kvm-qemu.sh did not complete successfully
# Check stamp file: ls -la /opt/.cape-kvm-qemu-installed
```

### Pipeline not picking up spooled samples

```bash
systemctl status pipeline-spool.path    # the .path unit is what watches the spool
journalctl -u pipeline-spool -n 50
# pipeline-spool.service sitting at inactive/dead is normal — it is path-triggered.
# CAPE_API_KEY comes from /opt/pipeline/pipeline.env, not the ambient environment.
```

### Packer build fails on WinRM timeout

The Windows installer takes 20–30 minutes. If Packer times out waiting for WinRM,
increase `communicator_timeout` in the pkr.hcl file. Default is 45m.

---

## Re-running after changes

| Change | What to re-run |
|--------|---------------|
| Ansible role change | `make configure`, or `make deploy TAGS=<role>` for one role |
| Terraform OVH change | `make infra-ovh` |
| Windows guest image change | Packer build + SCP + `make configure` + re-snapshot |
| Secret rotation | `ansible-vault edit ansible/vars/secrets.yml` + `make configure` |

---

*Author: Christopher Shaiman — Apache 2.0*
