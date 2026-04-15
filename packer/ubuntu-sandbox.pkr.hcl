# =============================================================================
# packer/ubuntu-sandbox.pkr.hcl
# Hardened Ubuntu 24.04 LTS base image for the malware analysis sandbox host.
#
# What this builds:
#   1. Ubuntu 24.04 LTS (autoinstall, unattended)
#   2. KVM/QEMU/libvirt packages pre-installed (config done by Ansible at runtime)
#   3. CAPEv2 cloned to /opt/CAPEv2, Python deps pre-installed
#   4. AWS CLI v2 installed
#   5. konstruktoid/ansible-role-hardening applied (CIS-aligned baseline)
#   6. Output: qcow2 image for OVH BYOI deployment
#
# Prerequisites (build host):
#   - Linux with KVM support (or WSL2 with KVM): kvm-ok
#   - Packer >= 1.10: packer --version
#   - QEMU: apt-get install qemu-system-x86
#   - Ansible: pip install ansible
#   - ansible-galaxy install konstruktoid.hardening -p packer/ansible/roles
#
# One-time setup (SSH password for build):
#   1. Generate a hash: openssl passwd -6 YOUR_CHOSEN_PASSWORD
#   2. Replace the PLACEHOLDER hash in packer/http/user-data identity.password
#   3. Set ssh_password = "YOUR_CHOSEN_PASSWORD" in packer/packer.auto.pkrvars.hcl
#
# Build:
#   make lambda   # ensure src/*.zip exist (not needed for packer, but good habit)
#   make image
#
# Post-build — upload to S3 for OVH BYOI:
#   aws s3 cp packer/output/ubuntu-sandbox.qcow2 s3://YOUR_BUCKET/images/
#   # Then use OVH API: POST /dedicated/server/{name}/bringYourOwnImage
#   # with the pre-signed S3 URL
# =============================================================================

packer {
  required_version = ">= 1.10"

  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "~> 1.0"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "ubuntu_iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/24.04/ubuntu-24.04.4-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  type    = string
  # Packer downloads SHA256SUMS and finds the entry matching the ISO filename
  default = "file:https://releases.ubuntu.com/24.04/SHA256SUMS"
}

variable "ssh_username" {
  type    = string
  default = "packer"
}

variable "ssh_password" {
  type      = string
  sensitive = true
  # No default — must be set in packer.auto.pkrvars.hcl
  # Must match the hash in packer/http/user-data identity.password
  # See file header for setup instructions
}

variable "disk_size" {
  type    = string
  default = "51200"  # 50 GB in MB — OS + KVM packages + CAPEv2 + analysis artefacts
}

variable "memory" {
  type    = number
  default = 4096  # MB — sufficient for image build; Cape VMs run on the deployed host
}

variable "cpus" {
  type    = number
  default = 2
}

variable "headless" {
  type    = bool
  default = true  # Set false temporarily if you need to debug the autoinstall
}

variable "ubuntu_output_directory" {
  type        = string
  description = "Directory for the output qcow2. Use a WSL-native path to avoid NTFS issues."
  # No default — must be set in packer.auto.pkrvars.hcl.
}

variable "cape_repo_url" {
  type    = string
  default = "https://github.com/kevoreilly/CAPEv2.git"
}

# =============================================================================
# Source: QEMU builder
# =============================================================================

source "qemu" "ubuntu_sandbox" {
  # --- ISO ---
  iso_url      = var.ubuntu_iso_url
  iso_checksum = var.ubuntu_iso_checksum

  # --- Output ---
  output_directory = var.ubuntu_output_directory
  vm_name          = "ubuntu-sandbox.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size

  # --- VM resources ---
  accelerator = "kvm"
  cpus        = var.cpus
  memory      = var.memory
  headless    = var.headless

  # q35 machine type + host CPU passthrough — matches the OVH bare metal target
  qemuargs = [
    ["-machine", "type=q35,accel=kvm"],
    ["-cpu", "host"],
  ]

  # --- HTTP server ---
  # Packer starts a local HTTP server in this directory; the Ubuntu autoinstall
  # cloud-init datasource fetches user-data and meta-data from it during boot
  http_directory = "${path.root}/http"

  # --- Boot command ---
  # Enter GRUB command line (c), load kernel + initrd, pass autoinstall datasource URL, boot
  boot_wait = "5s"
  boot_command = [
    "c",
    "linux /casper/vmlinuz --- autoinstall 'ds=nocloud-net;s=http://{{.HTTPIP}}:{{.HTTPPort}}/' ",
    "<enter><wait3>",
    "initrd /casper/initrd",
    "<enter><wait3>",
    "boot",
    "<enter>",
  ]

  # --- SSH communicator ---
  # Packer polls for SSH after the OS install completes and reboots (~15-30 min)
  ssh_username           = var.ssh_username
  ssh_password           = var.ssh_password
  ssh_timeout            = "90m"
  ssh_handshake_attempts = 300

  # NOPASSWD:ALL is set for the packer user in user-data — no password needed here.
  # Avoid echoing the password into Packer logs via the previous sudo -S pattern.
  shutdown_command = "sudo shutdown -P now"
}

# =============================================================================
# Build
# =============================================================================

build {
  name    = "ubuntu-sandbox"
  sources = ["source.qemu.ubuntu_sandbox"]

  # 1. Wait for cloud-init (autoinstall second stage) to fully finish
  provisioner "shell" {
    inline = [
      "echo '==> Waiting for cloud-init...'",
      "sudo cloud-init status --wait",
      "sudo apt-get update -qq",
    ]
  }

  # 2. KVM / QEMU / libvirt packages
  # Packages only — no service config, hugepage tuning, or bridge setup.
  # All runtime configuration is Ansible's job.
  provisioner "shell" {
    inline = [
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-kvm qemu-utils libvirt-daemon-system libvirt-clients bridge-utils virtinst cpu-checker libhugetlbfs-bin libguestfs-tools dnsmasq-base ovmf swtpm swtpm-tools python3-pip python3-dev python3-venv git curl unzip",
    ]
  }

  # 3. Clone CAPEv2
  # --depth 1 for speed; full history not needed on the host
  # Ansible creates the cape user and fixes ownership at configure time
  provisioner "shell" {
    inline = [
      "echo '==> Cloning CAPEv2...'",
      "sudo git clone --depth 1 ${var.cape_repo_url} /opt/CAPEv2",
    ]
  }

  # 4. Pre-install CAPEv2 Python dependencies
  # Avoids downloading packages every time Ansible re-runs on a rebuilt host.
  # cape2.sh / Ansible may install more deps at runtime — these are the base set.
  provisioner "shell" {
    inline = [
      "echo '==> Installing CAPEv2 system dependencies...'",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libssl-dev libffi-dev libfuzzy-dev ssdeep libmagic1 libjansson-dev libtlsh-dev build-essential cmake",
      "echo '==> Installing CAPEv2 Python dependencies...'",
      "sudo pip3 install --break-system-packages --ignore-installed -r /opt/CAPEv2/requirements.txt",
    ]
  }

  # 5. AWS CLI v2
  # Used by the sqs-agent systemd service to sync reports to S3
  provisioner "shell" {
    inline = [
      "echo '==> Installing AWS CLI v2...'",
      "curl -fsSL 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o /tmp/awscliv2.zip",
      "unzip -q /tmp/awscliv2.zip -d /tmp",
      "sudo /tmp/aws/install",
      "rm -rf /tmp/awscliv2.zip /tmp/aws",
      "aws --version",
    ]
  }

  # 6. Apply konstruktoid hardening (CIS-aligned baseline)
  # Runs last so all packages are in place before the system is locked down.
  # Prereq: ansible-galaxy install konstruktoid.hardening -p packer/ansible/roles
  provisioner "ansible" {
    playbook_file = "${path.root}/ansible/hardening.yml"

    ansible_env_vars = [
      "ANSIBLE_ROLES_PATH=${path.root}/ansible/roles",
      "ANSIBLE_HOST_KEY_CHECKING=False",
      "ANSIBLE_SSH_ARGS=-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
    ]

    extra_arguments = [
      "--extra-vars", "ansible_python_interpreter=/usr/bin/python3",
    ]
  }

  # 7. Cleanup — shrink image size
  # cloud-init clean: resets cloud-init state so it runs fresh on first boot of the deployed image
  # env_var_format + remote_folder: the hardening role mounts /tmp with noexec,
  # so Packer must upload and execute scripts from /var/tmp instead.
  provisioner "shell" {
    env_var_format = "export %s='%s'; "
    remote_folder  = "/var/tmp"
    inline = [
      "sudo apt-get clean",
      "sudo apt-get autoremove -y",
      "sudo rm -rf /tmp/* /var/tmp/*",
      "sudo cloud-init clean --logs",
      "sudo sync",
    ]
  }
}
