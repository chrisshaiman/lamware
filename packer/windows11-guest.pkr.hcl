# =============================================================================
# packer/windows11-guest.pkr.hcl
# Production "clean" guest image — runs cleanup on the base image.
#
# What this builds:
#   Takes windows11-base.qcow2 as input, boots it, runs cleanup.ps1
#   (removes WinRM, disables Administrator, clears logs/temp), and exports
#   windows11-guest.qcow2 ready for Cape's "clean" snapshot.
#
# This is one of two production images derived from the base:
#   - windows11-guest.qcow2  (this file) — no office suite, "clean" snapshot
#   - windows11-office.qcow2 (windows11-office.pkr.hcl) — + LibreOffice
#
# Prerequisites:
#   - windows11-base.qcow2 must exist (built by windows11-base.pkr.hcl)
#   - packer.auto.pkrvars.hcl with:
#       win11_base_image_path     = "/path/to/windows11-base.qcow2"
#       win11_base_image_checksum = "sha256:<checksum>"
#
# Build:
#   packer build -var-file=packer.auto.pkrvars.hcl windows11-guest.pkr.hcl
#
# After build:
#   Copy to bare metal host → Ansible defines the `clean-w11` libvirt domain →
#   virsh snapshot-create-as clean-w11 clean-w11 --disk-only --atomic
#
# Author: Christopher Shaiman
# License: Apache 2.0
# =============================================================================

packer {
  # Pinned to the 1.16 series, not ">= 1.10". The builder version is an
  # input to the image: a different Packer can produce a different guest,
  # and nothing recorded which one built the images in use. Same defect as
  # the floating `sdk:10.0` base tag that broke the dotnet build (#514).
  # Patch releases inside 1.16.x are allowed so a security fix is not
  # blocked; a minor bump is a deliberate decision, not a surprise.
  required_version = "~> 1.16.0"

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

# =============================================================================
# Guest hardware profile
# -----------------------------------------------------------------------------
# Identical to windows11-base.pkr.hcl and to the libvirt domain. Every stage
# that boots this image must present the same machine: Windows re-evaluates its
# licence hardware hash on each boot, and a stage that differs re-binds it or
# invalidates it (#573). These are supplied by the Makefile from
# ansible/vars/main.yml, the same source the domain template reads.
# =============================================================================

variable "guest_cpu_model" {
  type        = string
  default     = ""
  description = "QEMU CPU model, e.g. Skylake-Client-v4. Never \"host\" — see windows11-base.pkr.hcl."
}

variable "guest_mac" {
  type        = string
  default     = ""
  description = "NIC MAC, matching the libvirt domain's."
}

variable "guest_smbios_manufacturer" {
  type    = string
  default = "Dell Inc."
}

variable "guest_smbios_product" {
  type    = string
  default = "OptiPlex 7090"
}

variable "guest_smbios_serial" {
  type        = string
  default     = ""
  description = "SMBIOS system + baseboard serial."
}

variable "guest_smbios_uuid" {
  type        = string
  default     = ""
  description = "SMBIOS system UUID; the libvirt domain UUID for this guest."
}

variable "guest_bios_vendor" {
  type    = string
  default = "Dell Inc."
}

variable "guest_bios_version" {
  type    = string
  default = "2.18.0"
}

variable "guest_bios_date" {
  type    = string
  default = "04/12/2024"
}

variable "win11_base_image_path" {
  type        = string
  description = "Path to the windows11-base.qcow2 base image."
}

variable "win11_base_image_checksum" {
  type        = string
  description = "SHA-256 checksum of the base image, prefixed with 'sha256:'."
}

variable "disk_size" {
  type    = string
  default = "65536"   # 64 GB — same as base
}

variable "memory" {
  type    = number
  default = 4096
}

variable "cpus" {
  type    = number
  default = 2
}

variable "headless" {
  type    = bool
  default = true
}

variable "winrm_password" {
  type      = string
  sensitive = true
}

variable "ovmf_code" {
  type    = string
  default = "/usr/share/OVMF/OVMF_CODE_4M.fd"
}

variable "ovmf_vars" {
  type    = string
  default = "/usr/share/OVMF/OVMF_VARS_4M.fd"
}

# =============================================================================
# Source: QEMU builder — clean guest derived from base
# =============================================================================

source "qemu" "windows11_guest" {

  # --- Base image ---
  iso_url      = "file://${var.win11_base_image_path}"
  iso_checksum = var.win11_base_image_checksum
  disk_image   = true

  # --- Output ---
  output_directory = "${path.root}/output-guest"
  vm_name          = "windows11-guest.qcow2"
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
    # Same hardware the base build presented and the same the domain will
    # present. This stage used to run -cpu host with no -smbios at all, so the
    # image was licensed against three different machines on its way to the
    # sandbox (#573).
    ["-cpu", "${var.guest_cpu_model},-hypervisor"],
    ["-vga", "std"],
    ["-smbios", "type=0,vendor=${var.guest_bios_vendor},version=${var.guest_bios_version},date=${var.guest_bios_date}"],
    ["-smbios", "type=1,manufacturer=${var.guest_smbios_manufacturer},product=${var.guest_smbios_product},version=Not Specified,serial=${var.guest_smbios_serial},uuid=${var.guest_smbios_uuid},family=OptiPlex"],
    ["-smbios", "type=2,manufacturer=${var.guest_smbios_manufacturer},product=0K1RTX,version=A00,serial=${var.guest_smbios_serial}"],
    ["-global", "e1000.rombar=0"],
    ["-global", "e1000.mac=${var.guest_mac}"],
  ]

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

  # Disable Administrator after cleanup (same pattern as old base build)
  shutdown_command = "powershell -Command \"Disable-LocalUser -Name Administrator\"; shutdown /s /t 5 /f /d p:4:1"
  shutdown_timeout = "5m"
}

# =============================================================================
# Build
# =============================================================================

build {
  name    = "windows11-guest"
  sources = ["source.qemu.windows11_guest"]

  # Only step: cleanup (WinRM removal, log clearing, temp cleanup)
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/cleanup.ps1"
  }

  # The guest inherits its licence state from the base. Check it here too --
  # this is the image Cape actually boots, and an expired one is shut down
  # hourly by WLMS mid-analysis (#553).
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/verify-license.ps1"
  }

  # Fail the build if Defender survived. A blocked disable script exits 0,
  # so without this the image ships with live antivirus (#548).
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/verify-defender-disabled.ps1"
  }
}
