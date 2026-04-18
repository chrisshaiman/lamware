# Deployment Guide

Step-by-step deployment of the malware analysis sandbox from a clean starting point.
Follow in order — each phase depends on the one before it.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [AWS Bootstrap](#2-aws-bootstrap)
3. [AWS Infrastructure](#3-aws-infrastructure)
4. [Secrets Setup](#4-secrets-setup)
5. [OVH Bare Metal Provisioning](#5-ovh-bare-metal-provisioning)
6. [DSDT Capture](#6-dsdt-capture)
7. [Ansible Configuration](#7-ansible-configuration)
8. [Packer Guest Image Builds](#8-packer-guest-image-builds)
9. [Libvirt Snapshots](#9-libvirt-snapshots)
10. [Smoke Test](#10-smoke-test)

---

## 1. Prerequisites

Everything that must be in place on your local machine before running any command.

### Accounts

- **AWS account** — dedicated to this project; do not share with other infrastructure.
  You need AdministratorAccess (or a policy covering IAM, EC2, S3, RDS, Lambda, SQS,
  API Gateway, KMS, Secrets Manager, CloudTrail, Budgets, VPC).
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

# AWS CLI v2
aws --version

# WireGuard tools (wg genkey, wg pubkey)
wg --version

# Python 3.11+ (local — for Lambda zip build via `make lambda`)
python3 --version

# make
make --version

# zip (used by `make lambda`)
zip --version

# OpenSSL (used by `make packer-setup` to hash the build password)
openssl version

# QEMU (required on the build host for the Windows Packer build — Linux only)
# apt-get install qemu-system-x86 qemu-utils
qemu-system-x86_64 --version
```

> **Note:** Packer Windows guest builds require QEMU and must run on Linux. Use the bare
> metal host itself (after Phase 7) or any Linux machine with 8 GB+ RAM and 100 GB+ disk.

### AWS credentials

Configure the AWS CLI with credentials for the sandbox account:

```bash
aws configure
# AWS Access Key ID:     <your key>
# AWS Secret Access Key: <your secret>
# Default region name:   us-east-1
# Default output format: json

# Verify:
aws sts get-caller-identity
```

If you use named profiles, export `AWS_PROFILE=sandbox` before running any `terraform`
or `make` command.

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

## 2. AWS Bootstrap

Creates the S3 bucket and DynamoDB table that store Terraform remote state for all
subsequent AWS deployments. Uses local state for its own state (intended — bootstrap
is run once and rarely touched again).

```bash
cd aws/bootstrap
terraform init
terraform apply
```

Terraform will show a plan with two resources: an S3 bucket and a DynamoDB table.
Review and confirm with `yes`.

After apply, record the outputs:

```bash
terraform output
# tfstate_bucket_name = "malware-sandbox-tfstate-<account-id>"
# tfstate_lock_table  = "malware-sandbox-tfstate-lock"
# aws_region          = "us-east-1"
```

Populate `shared/backend-aws.hcl` automatically:

```bash
cd ../..   # back to repo root
cp shared/backend-aws.hcl.example shared/backend-aws.hcl   # gitignored — copy once
make configure-backend
```

Verify `shared/backend-aws.hcl` now contains the real bucket name (no placeholder):

```bash
cat shared/backend-aws.hcl
```

---

## 3. AWS Infrastructure

Provisions VPC, S3, RDS, SQS, Lambda, API Gateway, KMS, Secrets Manager, CloudTrail,
and budget alerts. All AWS resources are created in a single `terraform apply`.

### 3a. Build Lambda ZIPs

The Terraform Lambda module references ZIP files that must exist before `plan` or `apply`.
Build them first:

```bash
make lambda
# Produces: src/report_processor.zip  src/sample_submitter.zip
```

### 3b. Configure prod tfvars

```bash
cd aws/envs/prod
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`. Required fields:

```hcl
aws_region  = "us-east-1"
name_prefix = "malware-sandbox"

# S3 bucket names must be globally unique. Include your AWS account ID.
samples_bucket_name = "malware-sandbox-samples-<your-account-id>"
reports_bucket_name = "malware-sandbox-reports-<your-account-id>"

# Budget alert — at least one email address
budget_alert_emails = ["you@example.com"]

# Lambda ZIP paths (relative to aws/envs/prod/ — built by make lambda)
report_processor_zip = "../../src/report_processor.zip"
sample_submitter_zip = "../../src/sample_submitter.zip"
```

Get your AWS account ID if you don't know it:

```bash
aws sts get-caller-identity --query Account --output text
```

### 3c. Init, plan, apply

```bash
terraform init -backend-config=../../shared/backend-aws.hcl
terraform plan -out=tfplan
# Review the plan — expect ~50-60 resources
terraform apply tfplan
```

### 3d. Record outputs

After apply, capture the ARNs you'll need for later phases:

```bash
terraform output
```

Record these values — you'll need them in Phase 4 and Phase 7:

| Output | Where used |
|--------|-----------|
| `baremetal_agent_secret_arn` | `ansible/vars/main.yml` → `secret_arn_baremetal` |
| `cape_api_secret_arn` | `ansible/vars/main.yml` → `secret_arn_cape` |
| `dsdt_secret_arn` | Reference only — updated in Phase 6 |
| `api_endpoint` | Note for sample submission clients |

---

## 4. Secrets Setup

Three Secrets Manager secrets are created by Terraform with placeholder values.
You must populate them with real values before Ansible can run.

### 4a. WireGuard keys

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

### 4b. Cape API key

Generate a random API key and update the Cape secret. The DSDT string is added later
(Phase 6) because it requires the physical hardware to be running.

```bash
CAPE_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "Cape API key: $CAPE_API_KEY"   # save this somewhere safe

aws secretsmanager put-secret-value \
  --secret-id "<cape_api_secret_arn>" \
  --secret-string "{
    \"api_key\":     \"$CAPE_API_KEY\",
    \"dsdt_string\": \"PLACEHOLDER — update after Phase 6\"
  }"
```

### 4c. Update ansible/vars/main.yml

`ansible/vars/main.yml` is gitignored — copy the example first:

```bash
cp ansible/vars/main.yml.example ansible/vars/main.yml
```

Fill in the three ARNs you recorded in Phase 3:

```yaml
# ansible/vars/main.yml
secret_arn_baremetal:  "arn:aws:secretsmanager:us-east-1:<account-id>:secret:..."
secret_arn_cape:      "arn:aws:secretsmanager:us-east-1:<account-id>:secret:..."
wireguard_peer_pubkey: "<contents of ~/wg-public.key>"
```

Also fill in the S3 bucket names:

```yaml
s3_bucket_samples: "malware-sandbox-samples-<account-id>"
s3_bucket_reports: "malware-sandbox-reports-<account-id>"
```

---

## 5. OVH Bare Metal Provisioning

Registers your SSH key with OVH, applies the robot firewall (before OS install),
and installs Ubuntu 24.04.

### 5a. Find your server name

In the OVH Manager: Bare Metal Cloud → Dedicated Servers → your server →
General Information. The service name looks like `ns123456.ip-1-2-3.eu`.

### 5b. Configure OVH tfvars

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

### 5c. Apply

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

## 6. DSDT Capture

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

Update the Cape secret with the real DSDT string (replace the placeholder from Phase 4):

```bash
# From your local machine
DSDT_STRING="<output of xxd -p dsdt.dat | tr -d '\n'>"
CAPE_API_KEY="<the key you generated in Phase 4>"

aws secretsmanager put-secret-value \
  --secret-id "<cape_api_secret_arn>" \
  --secret-string "{
    \"api_key\":     \"$CAPE_API_KEY\",
    \"dsdt_string\": \"$DSDT_STRING\"
  }"
```

Similarly update the DSDT secret (used as a reference; the Cape secret is what Ansible reads):

```bash
aws secretsmanager put-secret-value \
  --secret-id "<dsdt_secret_arn>" \
  --secret-string "{\"dsdt_string\": \"$DSDT_STRING\"}"
```

---

## 7. Ansible Configuration

Configures the bare metal host: KVM/libvirt, CAPEv2, INetSim, WireGuard, and the
SQS polling agent. Ansible reads secrets from Secrets Manager at run time — no secrets
are stored in the repo.

### 7a. Install Galaxy requirements

```bash
ansible-galaxy install -r ansible/requirements.yml --force-with-deps
```

### 7b. Run the playbook

```bash
make configure
# Equivalent to:
# ansible-playbook -i ansible/inventory/hosts -u root \
#   --private-key ~/.ssh/sandbox_ed25519 ansible/site.yml
```

Expected runtime: **45–90 minutes**. The `kvm-qemu.sh` step (building a DSDT-patched
QEMU binary from source) takes 30–60 minutes and is guarded by a stamp file —
it only runs once and is skipped on re-runs.

### 7c. Verify services

SSH into the host and confirm all services are running:

```bash
ssh -i ~/.ssh/sandbox_ed25519 root@<server-ip>

systemctl status cape
systemctl status cape-web
systemctl status cape-processor
systemctl status inetsim
systemctl status wg-quick@wg0
systemctl status sqs-agent
```

All should show `active (running)`.

### 7d. Configure WireGuard on your laptop

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

## 8. Packer Guest Image Builds

Builds two Windows 10 guest images:
- `windows10-guest.qcow2` — base image with Python and cape-agent (the `clean` snapshot)
- `windows10-office.qcow2` — extends the base with LibreOffice (the `office` snapshot)

**These builds must run on a Linux machine with QEMU installed.** Options:
- The bare metal host itself (after Phase 7) — preferred for production
- Any Linux machine with sufficient RAM (8 GB+) and disk (100 GB+)
- **WSL2 on Windows** — fully supported if your machine has 8 GB+ RAM free and 100 GB+
  disk available in the WSL2 volume. Install QEMU first:
  `sudo apt-get install -y qemu-system-x86 qemu-utils`

### 8a. One-time Packer setup

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

### 8b. Populate packer.auto.pkrvars.hcl

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

### 8c. Build the base (Ubuntu) image

The Ubuntu sandbox image is built separately and is used as the host base image for OVH
BYOI (Bring Your Own Image) if needed. Skip if you used the OVH standard Ubuntu 24.04
template in Phase 5.

```bash
make image
```

### 8d. Build Windows guest images

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

### 8e. Copy images to the bare metal host

```bash
scp -i ~/.ssh/sandbox_ed25519 \
  packer/output/windows10-guest.qcow2 \
  root@<server-ip>:/var/lib/libvirt/images/

scp -i ~/.ssh/sandbox_ed25519 \
  packer/output/windows10-office.qcow2 \
  root@<server-ip>:/var/lib/libvirt/images/
```

### 8f. Re-run Ansible to define libvirt domains

Now that the images are on the host, re-run Ansible to define the libvirt domains
(Ansible skips already-completed steps via stamp files):

```bash
make configure
```

---

## 9. Libvirt Snapshots

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

## 10. Smoke Test

Verify the full pipeline before treating the system as operational.

### 10a. Get the API endpoint

```bash
cd aws/envs/prod
terraform output api_endpoint
# e.g. https://abc123.execute-api.us-east-1.amazonaws.com
```

### 10b. Submit a test sample

Use the EICAR test file — universally recognised by AV engines, completely harmless:

```bash
# Create the EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com

# Submit via the API (requires an AWS credentials with the submitter IAM policy attached)
# The API returns a pre-signed S3 upload URL + job ID
curl -X POST "<api_endpoint>/submit" \
  -H "Content-Type: application/json" \
  -d '{"filename": "eicar.com", "tags": []}' \
  --aws-sigv4 "aws:amz:us-east-1:execute-api" \
  --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"
```

### 10c. Monitor the job

```bash
# Watch sqs-agent pick up the job (on the bare metal host via WireGuard)
ssh -i ~/.ssh/sandbox_ed25519 root@<server-ip>
journalctl -u sqs-agent -f
```

### 10d. Verify report in S3

```bash
aws s3 ls s3://<reports_bucket_name>/reports/ --recursive
```

### 10e. Check Cape web UI

With WireGuard connected, open `http://10.200.0.1:8000` in a browser.
The analysis should appear in the Recent Analyses list.

If all five checks pass, the sandbox is operational.

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

### SQS agent not picking up jobs

```bash
journalctl -u sqs-agent -n 50
# Check AWS credentials: the agent assumes a role via sts:AssumeRole
# Verify secret_arn_baremetal in ansible/vars/main.yml is correct
```

### Packer build fails on WinRM timeout

The Windows installer takes 20–30 minutes. If Packer times out waiting for WinRM,
increase `communicator_timeout` in the pkr.hcl file. Default is 45m.

---

## Re-running after changes

| Change | What to re-run |
|--------|---------------|
| Ansible role change | `make configure` |
| Terraform AWS change | `make infra-aws` |
| Terraform OVH change | `make infra-ovh` |
| Windows guest image change | Packer build + SCP + `make configure` + re-snapshot |
| Lambda code change | `make lambda && make infra-aws` |
| Secret rotation | `aws secretsmanager put-secret-value ...` + `make configure` |

---

*Author: Christopher Shaiman — Apache 2.0*
