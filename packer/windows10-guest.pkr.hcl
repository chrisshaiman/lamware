# =============================================================================
# packer/windows10-guest.pkr.hcl
# Windows 10 22H2 Enterprise guest VM image for Cape malware detonation.
#
# What this builds:
#   1. Windows 10 22H2 Enterprise Evaluation (unattended via autounattend.xml)
#   2. Windows Defender disabled — samples must run without AV interference
#   3. Python 3.x installed (required for cape-agent.py)
#   4. cape-agent.py installed, starts on boot via Scheduled Task
#   5. Realistic hostname, username, and decoy user files (anti-evasion, ADR-012)
#   6. Screen resolution set to 1920x1080 (anti-evasion, ADR-012)
#   7. Output: qcow2 — imported to the bare metal host, snapshots taken by Ansible
#
# Anti-evasion measures baked in (see docs/DECISIONS.md ADR-012):
#   - Screen resolution: 1920x1080
#   - CPU cores: 2, RAM: 4096 MB, disk: 60 GB
#   - Hostname: DESKTOP-XXXXXXX pattern (var.guest_hostname)
#   - Username: realistic first-name (var.guest_username)
#   - Decoy files: plausible Documents/Downloads/Desktop content
#   CPUID hypervisor bit mask is applied by libvirt at Cape analysis time
#   (ansible/roles/cape/ libvirt XML template, see ADR-012).
#
# Prerequisites (build host — Linux with KVM):
#   - Packer >= 1.10: packer --version
#   - QEMU: apt-get install qemu-system-x86
#   - windows-restart plugin: packer init .
#   - Windows 10 22H2 Enterprise evaluation ISO downloaded locally
#     Download from: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
#   - packer.auto.pkrvars.hcl with:
#       winrm_password = "Packer@Build1"   # must match autounattend.xml
#       iso_path       = "/path/to/Win10_22H2_EnterpriseEval.iso"
#       iso_checksum   = "sha256:<checksum>"
#
# Build:
#   cd packer/
#   packer init windows10-guest.pkr.hcl
#   packer build -var-file=packer.auto.pkrvars.hcl windows10-guest.pkr.hcl
#
# After build:
#   Copy packer/output/windows10-guest.qcow2 to the bare metal host.
#   Ansible roles/cape/ imports it and creates clean + office snapshots.
#   See docs/STATUS.md for the full workflow.
#
# Evaluation ISO notes (ADR-009):
#   - 90-day evaluation period — rebuild when it expires
#   - ImageIndex 1 is the only edition in the eval ISO (Enterprise Evaluation)
#   - If using a multi-edition ISO, set iso_image_name to the exact edition string
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
    windows-restart = {
      source  = "github.com/hashicorp/windows-restart"
      version = "~> 1.0"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "iso_path" {
  type        = string
  description = "Local path to the Windows 10 22H2 Enterprise evaluation ISO."
  # No default — must be set in packer.auto.pkrvars.hcl.
  # Download from https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
}

variable "iso_checksum" {
  type        = string
  description = "SHA-256 checksum of the ISO, prefixed with 'sha256:'."
  # Verify with: sha256sum Win10_22H2_EnterpriseEval.iso
}

variable "winrm_password" {
  type        = string
  sensitive   = true
  description = "Password for the built-in Administrator account during the Packer build."
  # MUST match the AdministratorPassword in answer-files/autounattend.xml.
  # Recommended: override in packer.auto.pkrvars.hcl, do not commit that file.
  default     = "Packer@Build1"
}

variable "guest_hostname" {
  type        = string
  description = "Hostname baked into the guest image. Uses DESKTOP-XXXXXXX pattern (ADR-012)."
  # Rebuild with a different hostname to rotate the machine identity.
  # Cape analysis VMs all share this hostname from the snapshot.
  default     = "DESKTOP-WK7B3L2"
}

variable "guest_username" {
  type        = string
  description = "Local user account created on the guest (realistic first-name pattern, ADR-012)."
  default     = "jsmith"
}

variable "guest_password" {
  type        = string
  sensitive   = true
  description = "Password for the guest user account (var.guest_username)."
  default     = "Password123!"
}

variable "disk_size" {
  type        = string
  description = "Guest disk size in MB."
  default     = "61440"  # 60 GB (ADR-012)
}

variable "memory" {
  type        = number
  description = "Guest RAM in MB."
  default     = 4096  # ADR-012
}

variable "cpus" {
  type        = number
  description = "Guest vCPU count."
  default     = 2  # ADR-012
}

variable "headless" {
  type        = bool
  description = "Run without display. Set false to debug the install via VNC."
  default     = true
}

variable "python_version" {
  type        = string
  description = "Python version to install (used to construct the download URL)."
  default     = "3.11.9"
}

# =============================================================================
# Source: QEMU builder — Windows 10 guest
# =============================================================================

source "qemu" "windows10_guest" {

  # --- ISO ---
  # Local path only — Microsoft prohibits automated ISO downloads.
  # See file header for the download link.
  iso_url      = "file://${var.iso_path}"
  iso_checksum = var.iso_checksum

  # --- Output ---
  output_directory = "${path.root}/output"
  vm_name          = "windows10-guest.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size

  # --- VM resources ---
  # CPU count and RAM match the ADR-012 anti-evasion spec.
  # Accelerator: KVM required on the Linux build host.
  accelerator = "kvm"
  cpus        = var.cpus
  memory      = var.memory
  headless    = var.headless

  # --- Disk and network interfaces ---
  # IDE disk interface: Windows 10 in QEMU does not include VirtIO drivers
  # by default. IDE is simpler and avoids the driver injection step.
  # e1000 NIC: widely supported, no additional drivers needed.
  disk_interface = "ide"
  net_device     = "e1000"

  # --- QEMU machine type ---
  # q35 with KVM accel — same chipset as the Ubuntu host build.
  # CPU is host passthrough during the Packer build for performance.
  # The CPUID hypervisor bit mask is applied at Cape analysis time by libvirt
  # (ansible/roles/cape/ libvirt XML template), not during the Packer build.
  qemuargs = [
    ["-machine", "type=q35,accel=kvm"],
    ["-cpu", "host"],
    # Standard VGA with 16 MB VRAM supports 1920x1080. QXL is not used here
    # since it requires the SPICE guest tools — std VGA keeps the build simple.
    ["-vga", "std"],
  ]

  # --- Unattended install via virtual floppy ---
  # Packer creates a virtual floppy image containing autounattend.xml.
  # Windows Setup auto-detects it at A:\autounattend.xml during the
  # windowsPE pass and runs fully unattended.
  floppy_files = ["${path.root}/answer-files/autounattend.xml"]

  # --- Boot command ---
  # The floppy + ISO is sufficient for Windows to boot and auto-install.
  # A brief wait before pressing enter avoids hitting the floppy before
  # the QEMU VGA output is ready.
  boot_wait    = "3s"
  boot_command = ["<enter>"]

  # --- WinRM communicator ---
  # autounattend.xml enables WinRM via FirstLogonCommands before Packer
  # connects. WinRM uses HTTP (unencrypted) with basic auth — build network only.
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = var.winrm_password
  winrm_timeout  = "4h"   # Windows Setup + OOBE + WinRM enable takes ~45-90 min
  winrm_port     = 5985
  winrm_use_ssl  = false

  # Graceful shutdown after provisioning
  shutdown_command = "shutdown /s /t 5 /f /d p:4:1"
  shutdown_timeout = "10m"
}

# =============================================================================
# Build
# =============================================================================

build {
  name    = "windows10-guest"
  sources = ["source.qemu.windows10_guest"]

  # ---------------------------------------------------------------------------
  # 1. System configuration — hostname, power, updates, WinRM hardening
  # ---------------------------------------------------------------------------
  # Runs first so all subsequent steps see the correct hostname.
  # Renames the computer from the autounattend placeholder (DESKTOP-PKRBLD)
  # to var.guest_hostname, then triggers a restart.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/configure-system.ps1"
    environment_vars = [
      "GUEST_HOSTNAME=${var.guest_hostname}",
    ]
  }

  # Restart after hostname change (requires windows-restart plugin)
  provisioner "windows-restart" {
    restart_check_command = "powershell -Command \"(hostname) -eq '${var.guest_hostname}'\""
    restart_timeout       = "10m"
  }

  # ---------------------------------------------------------------------------
  # 2. Disable Windows Defender
  # ---------------------------------------------------------------------------
  # Malware samples must execute without AV interference. Enterprise SKU allows
  # full Defender suppression via Group Policy registry keys (ADR-009).
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/disable-defender.ps1"
  }

  # ---------------------------------------------------------------------------
  # 3. Install Python
  # ---------------------------------------------------------------------------
  # cape-agent.py requires Python 3. Installed to C:\Python3 with PATH updated.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/install-python.ps1"
    environment_vars = [
      "PYTHON_VERSION=${var.python_version}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 4. Install Cape agent (cape-agent.py)
  # ---------------------------------------------------------------------------
  # Downloads agent.py from the CAPEv2 repo, installs to C:\cape-agent\,
  # and creates a Scheduled Task to start it at boot (SYSTEM account).
  # Cape host connects to the agent on port 8000 to submit samples, start
  # analysis, and collect results.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/install-cape-agent.ps1"
  }

  # ---------------------------------------------------------------------------
  # 5. Create realistic guest user account
  # ---------------------------------------------------------------------------
  # Creates var.guest_username as a local admin (malware typically expects admin
  # context). Profile directories are created so decoy files land in the right
  # places. The Administrator build account is disabled in cleanup.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/create-user.ps1"
    environment_vars = [
      "GUEST_USERNAME=${var.guest_username}",
      "GUEST_PASSWORD=${var.guest_password}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 6. Set screen resolution to 1920x1080
  # ---------------------------------------------------------------------------
  # Anti-evasion: malware checking screen dimensions should see a realistic
  # desktop size, not the 800x600 or 1024x768 defaults common in VMs (ADR-012).
  # Set via registry; takes effect on next boot (which Cape handles at analysis
  # time by restoring the snapshot and booting fresh).
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/set-resolution.ps1"
  }

  # ---------------------------------------------------------------------------
  # 7. Create decoy user files
  # ---------------------------------------------------------------------------
  # Populates the guest user's Documents, Downloads, and Desktop with realistic
  # files (ADR-012). Malware that enumerates files to determine if the machine
  # looks used should find plausible content. Files are benign text/office stubs.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/create-decoy-files.ps1"
    environment_vars = [
      "GUEST_USERNAME=${var.guest_username}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 8. Cleanup
  # ---------------------------------------------------------------------------
  # Removes temp files, clears event logs, disables auto-logon, and trims the
  # image size before Packer converts to qcow2.
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/cleanup.ps1"
  }
}
