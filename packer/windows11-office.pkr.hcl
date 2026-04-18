# =============================================================================
# packer/windows11-office.pkr.hcl
# Extends the windows11-base.qcow2 builder image with LibreOffice for
# Office document detonation (ADR-013).
#
# What this builds:
#   Takes windows11-base.qcow2 as input, boots it, installs LibreOffice,
#   configures macro security to allow all macros (required for detonation),
#   registers LibreOffice as the default handler for Office formats,
#   runs cleanup, and exports windows11-office.qcow2.
#
# Why LibreOffice (ADR-013):
#   - No Microsoft account or license key required
#   - Handles .doc, .docm, .xls, .xlsm, .odt with reasonable VBA compatibility
#   - Microsoft Office deferred as future option if VBA compat proves insufficient
#
# UEFI note:
#   The base image was built with UEFI/OVMF. This build must also use UEFI
#   so the existing EFI boot partition is recognized. The same OVMF firmware
#   and swtpm configuration are passed through.
#
# WinRM credentials:
#   Connects as Administrator — the base image keeps Administrator and WinRM
#   enabled for layered builds. Cleanup disables both at the end.
#
# Prerequisites:
#   - windows11-base.qcow2 must exist (built by windows11-base.pkr.hcl)
#   - packer.auto.pkrvars.hcl with:
#       win11_base_image_path     = "/path/to/windows11-base.qcow2"
#       win11_base_image_checksum = "sha256:<checksum>"
#
# Build:
#   cd packer/
#   packer init windows11-office.pkr.hcl
#   packer build -var-file=packer.auto.pkrvars.hcl windows11-office.pkr.hcl
#
# After build:
#   Copy packer/output/windows11-office.qcow2 to the bare metal host.
#   Ansible's virsh define creates the `office-w11` libvirt domain.
#   Then take the snapshot: virsh snapshot-create-as office-w11 office-w11 --disk-only --atomic
#
# Author: Christopher Shaiman
# License: Apache 2.0
# =============================================================================

packer {
  required_version = ">= 1.10"

  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "win11_base_image_path" {
  type        = string
  description = "Path to the windows11-base.qcow2 builder image."
}

variable "win11_base_image_checksum" {
  type        = string
  description = "SHA-256 checksum of the base image, prefixed with 'sha256:'."
}

variable "winrm_password" {
  type      = string
  sensitive = true
}

variable "guest_username" {
  type    = string
  default = "jsmith"
}

variable "libreoffice_version" {
  type        = string
  description = "LibreOffice version to install. Must be set alongside libreoffice_checksum."
}

variable "libreoffice_checksum" {
  type        = string
  description = "SHA-256 hash of the LibreOffice Windows x86-64 MSI. Must match libreoffice_version."
}

variable "disk_size" {
  type        = string
  description = "Output disk size in MB. Should be >= base image size (64 GB) + LibreOffice headroom."
  default     = "65536"   # 64 GB — same as base; qcow2 only grows as needed
}

variable "memory" {
  type        = number
  default     = 4096
}

variable "cpus" {
  type        = number
  default     = 2
}

variable "headless" {
  type        = bool
  default     = true
}

variable "ovmf_code" {
  type        = string
  description = "Path to OVMF_CODE_4M.fd on the build host."
  default     = "/usr/share/OVMF/OVMF_CODE_4M.fd"
}

variable "ovmf_vars" {
  type        = string
  description = "Path to OVMF_VARS_4M.fd on the build host."
  default     = "/usr/share/OVMF/OVMF_VARS_4M.fd"
}

# =============================================================================
# Source: QEMU builder — office image derived from Win11 guest base
# =============================================================================

source "qemu" "windows11_office" {

  # --- Base image ---
  iso_url      = "file://${var.win11_base_image_path}"
  iso_checksum = var.win11_base_image_checksum
  disk_image   = true

  # --- Output ---
  output_directory = "${path.root}/output-office"
  vm_name          = "windows11-office.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size

  # --- VM resources ---
  accelerator    = "kvm"
  cpus           = var.cpus
  memory         = var.memory
  headless       = var.headless
  disk_interface = "ide"
  net_device     = "e1000"

  # --- UEFI boot (must match base image) ---
  efi_boot          = true
  efi_firmware_code = var.ovmf_code
  efi_firmware_vars = var.ovmf_vars

  # --- QEMU machine type and TPM ---
  qemuargs = [
    ["-machine", "type=q35,accel=kvm"],
    ["-cpu", "host"],
    ["-vga", "std"],
  ]

  # vtpm = true — Packer manages swtpm lifecycle. See windows11-base.pkr.hcl
  # for explanation of why explicit TPM qemuargs must NOT be added alongside this.
  vtpm = true

  # Base image has WinRM enabled and auto-logs in as Administrator.
  # Short boot wait — no first-boot delay, WinRM is already configured.
  boot_wait    = "60s"
  boot_command = ["<enter>"]

  # --- WinRM communicator ---
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = var.winrm_password
  winrm_timeout  = "15m"
  winrm_port     = 5985
  winrm_use_ssl  = false

  # Disable Administrator after cleanup
  shutdown_command = "powershell -Command \"Disable-LocalUser -Name Administrator\"; shutdown /s /t 5 /f /d p:4:1"
  shutdown_timeout = "5m"
}

# =============================================================================
# Build
# =============================================================================

build {
  name    = "windows11-office"
  sources = ["source.qemu.windows11_office"]

  # ---------------------------------------------------------------------------
  # 1. Install LibreOffice
  # ---------------------------------------------------------------------------
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
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/cleanup.ps1"
  }
}
