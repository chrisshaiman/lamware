# =============================================================================
# packer/windows10-office.pkr.hcl
# Extends the windows10-guest.qcow2 base image with LibreOffice for
# Office document detonation (ADR-013).
#
# What this builds:
#   Takes windows10-guest.qcow2 as input, boots it, installs LibreOffice,
#   configures macro security to allow all macros (required for detonation),
#   registers LibreOffice as the default handler for Office formats, and
#   exports windows10-office.qcow2.
#
# Why LibreOffice (ADR-013):
#   - No Microsoft account or license key required
#   - Handles .doc, .docm, .xls, .xlsm, .odt with reasonable VBA compatibility
#   - Microsoft Office deferred as future option if VBA compat proves insufficient
#
# WinRM credentials:
#   This build connects as the guest user (var.guest_username / var.guest_password)
#   rather than Administrator, because cleanup.ps1 in the base build disables
#   the Administrator account. The guest user is a local admin so all
#   provisioner operations work without elevation changes.
#
# Prerequisites:
#   - windows10-guest.qcow2 must exist (built by windows10-guest.pkr.hcl)
#   - packer.auto.pkrvars.hcl with:
#       base_image_path     = "output/windows10-guest.qcow2"
#       base_image_checksum = "sha256:<checksum>"
#       guest_password      = "Password123!"   # must match base build
#
# Build:
#   cd packer/
#   packer init windows10-office.pkr.hcl
#   packer build -var-file=packer.auto.pkrvars.hcl windows10-office.pkr.hcl
#
# After build:
#   Copy packer/output/windows10-office.qcow2 to the bare metal host.
#   Ansible's virsh define creates the `office` libvirt domain.
#   Then take the snapshot: virsh snapshot-create-as office office --disk-only --atomic
#
# Author: Christopher Shaiman
# License: Apache 2.0
# =============================================================================

packer {
  required_version = ">= 1.10"

  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.0"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "base_image_path" {
  type        = string
  description = "Path to the windows10-guest.qcow2 base image (output of windows10-guest.pkr.hcl)."
  # No default — must be set in packer.auto.pkrvars.hcl or via -var.
}

variable "base_image_checksum" {
  type        = string
  description = "SHA-256 checksum of the base image, prefixed with 'sha256:'."
  # Generate with: sha256sum packer/output/windows10-guest.qcow2
}

variable "guest_username" {
  type        = string
  description = "Guest user account name (must match the value used in the base build)."
  default     = "jsmith"
}

variable "guest_password" {
  type        = string
  sensitive   = true
  description = "Password for the guest user account (must match the base build)."
  default     = "Password123!"
}

variable "libreoffice_version" {
  type        = string
  description = "LibreOffice version to install. Must be set alongside libreoffice_checksum."
  # No default — must be set alongside libreoffice_checksum in packer.auto.pkrvars.hcl.
  # Find the latest release: https://www.libreoffice.org/download/download-libreoffice/
}

variable "libreoffice_checksum" {
  type        = string
  description = "SHA-256 hash of the LibreOffice Windows x86-64 MSI. Must match libreoffice_version."
  # No default — find on the LibreOffice download page (Checksum column / .sha256 file).
  # Or compute: sha256sum LibreOffice_<version>_Win_x86-64.msi
}

variable "disk_size" {
  type        = string
  description = "Output disk size in MB. Should be >= base image size (60 GB) + LibreOffice headroom."
  default     = "61440"   # 60 GB — same as base; qcow2 only grows as needed
}

variable "memory" {
  type        = number
  description = "RAM for the build VM in MB."
  default     = 4096
}

variable "cpus" {
  type        = number
  description = "vCPUs for the build VM."
  default     = 2
}

variable "headless" {
  type        = bool
  default     = true
}

# =============================================================================
# Source: QEMU builder — office image derived from guest base
# =============================================================================

source "qemu" "windows10_office" {

  # --- Base image ---
  # disk_image = true tells Packer to treat this as a full disk image (not ISO).
  # Packer copies the qcow2 to the output directory and boots it directly.
  iso_url      = "file://${var.base_image_path}"
  iso_checksum = var.base_image_checksum
  disk_image   = true

  # --- Output ---
  output_directory = "${path.root}/output"
  vm_name          = "windows10-office.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size

  # --- VM resources ---
  accelerator    = "kvm"
  cpus           = var.cpus
  memory         = var.memory
  headless       = var.headless
  disk_interface = "ide"
  net_device     = "e1000"

  qemuargs = [
    ["-machine", "type=q35,accel=kvm"],
    ["-cpu", "host"],
    ["-vga", "std"],
  ]

  # No floppy_files — OS is already installed in the base image.

  # Boot: the base image auto-logs on as the guest user (configured by
  # create-user.ps1 in the base build). WinRM starts via the scheduled task
  # that autounattend.xml left in place.
  boot_wait    = "5s"
  boot_command = ["<enter>"]

  # --- WinRM communicator ---
  # Connect as the guest user (Administrator is disabled by base cleanup.ps1).
  communicator   = "winrm"
  winrm_username = var.guest_username
  winrm_password = var.guest_password
  winrm_timeout  = "30m"   # Base image boots fast; no OS install wait needed
  winrm_port     = 5985
  winrm_use_ssl  = false

  shutdown_command = "shutdown /s /t 5 /f /d p:4:1"
  shutdown_timeout = "5m"
}

# =============================================================================
# Build
# =============================================================================

build {
  name    = "windows10-office"
  sources = ["source.qemu.windows10_office"]

  # ---------------------------------------------------------------------------
  # 1. Install LibreOffice
  # ---------------------------------------------------------------------------
  # Downloads and installs LibreOffice silently. LibreOffice is chosen over
  # Microsoft Office because it requires no license key or Microsoft account
  # (ADR-013). VBA macro execution is enabled so Office document malware runs.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/install-libreoffice.ps1"
    environment_vars = [
      "LIBREOFFICE_VERSION=${var.libreoffice_version}",
      "LIBREOFFICE_CHECKSUM=${var.libreoffice_checksum}",
      "GUEST_USERNAME=${var.guest_username}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 2. Cleanup
  # ---------------------------------------------------------------------------
  # Re-run the cleanup script to remove the LibreOffice installer temp files
  # and clear event logs written during this provisioning pass.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/cleanup.ps1"
  }
}
