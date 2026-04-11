# =============================================================================
# packer/windows11-guest.pkr.hcl
# Windows 11 Enterprise Evaluation guest VM image for Cape malware detonation.
#
# What this builds:
#   1. Windows 11 Enterprise Evaluation (unattended via win11-autounattend.xml)
#   2. UEFI boot with OVMF firmware (required by Windows 11)
#   3. TPM 2.0 emulation via swtpm (required by Windows 11, also anti-evasion)
#   4. Windows Defender disabled — samples must run without AV interference
#   5. Python 3.x installed (required for cape-agent.py)
#   6. cape-agent.py installed, starts on boot via Scheduled Task
#   7. Realistic hostname, username, and decoy user files (anti-evasion, ADR-012)
#   8. Screen resolution set to 1920x1080 (anti-evasion, ADR-012)
#   9. Output: qcow2 — imported to the bare metal host, snapshots taken by Ansible
#
# Anti-evasion measures baked in (see docs/DECISIONS.md ADR-012):
#   - Screen resolution: 1920x1080
#   - CPU cores: 2, RAM: 4096 MB, disk: 64 GB
#   - Hostname: DESKTOP-XXXXXXX pattern (var.guest_hostname)
#   - Username: realistic first-name (var.guest_username)
#   - Decoy files: plausible Documents/Downloads/Desktop content
#   - TPM 2.0 present (swtpm) — real machines have TPMs, VMs often don't
#   CPUID hypervisor bit mask is applied by libvirt at Cape analysis time
#   (ansible/roles/cape/ libvirt XML template, see ADR-012).
#
# Prerequisites (build host — Linux with KVM):
#   - Packer >= 1.10: packer --version
#   - QEMU: apt-get install qemu-system-x86 ovmf swtpm
#   - QEMU plugin ~> 1.1: packer init .
#   - Windows 11 Enterprise evaluation ISO downloaded locally
#     Download from: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
#   - packer.auto.pkrvars.hcl with:
#       winrm_password      = "Packer@Build1"   # must match win11-autounattend.xml
#       win11_iso_path      = "/path/to/Win11_EnterpriseEval.iso"
#       win11_iso_checksum  = "sha256:<checksum>"
#
# autounattend.xml delivery:
#   Embedded directly in the Win11 ISO at the root using xorriso:
#     xorriso -indev win11.iso -outdev win11-unattend.iso \
#       -boot_image any keep \
#       -map answer-files/win11-autounattend.xml /autounattend.xml --
#   WinPE finds autounattend.xml on the boot ISO at startup — no secondary
#   drive needed. The modified ISO path is set in packer.auto.pkrvars.hcl.
#   Set win11_iso_path and win11_iso_checksum in packer.auto.pkrvars.hcl
#   to point to the modified ISO.
#
# Build:
#   cd packer/
#   packer init windows11-guest.pkr.hcl
#   packer build -var-file=packer.auto.pkrvars.hcl windows11-guest.pkr.hcl
#
# After build:
#   Copy packer/output/windows11-guest.qcow2 to the bare metal host.
#   Ansible roles/cape/ imports it and creates clean-w11 + office-w11 snapshots.
#   See docs/STATUS.md for the full workflow.
#
# Evaluation ISO notes (ADR-009):
#   - 90-day evaluation period — rebuild when it expires
#   - ImageIndex 1 is the only edition in the eval ISO (Enterprise Evaluation)
#   - win11-autounattend.xml includes BypassTPMCheck, BypassSecureBootCheck,
#     and BypassRAMCheck as belt-and-suspenders alongside swtpm
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
    # windows-restart is built into Packer core since v1.7 — no plugin entry needed
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "win11_iso_path" {
  type        = string
  description = "Local path to the Windows 11 Enterprise evaluation ISO."
  # No default — must be set in packer.auto.pkrvars.hcl.
  # Download from https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
}

variable "win11_iso_checksum" {
  type        = string
  description = "SHA-256 checksum of the ISO, prefixed with 'sha256:'."
  # Verify with: sha256sum Win11_EnterpriseEval.iso
}

variable "winrm_password" {
  type        = string
  sensitive   = true
  description = "Password for the built-in Administrator account during the Packer build."
  # MUST match the AdministratorPassword in answer-files/win11-autounattend.xml.
  default     = "Packer@Build1"
}

variable "guest_hostname" {
  type        = string
  description = "Hostname baked into the guest image. Uses DESKTOP-XXXXXXX pattern (ADR-012)."
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
  default     = "65536"  # 64 GB — Windows 11 minimum requirement
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

variable "output_directory" {
  type        = string
  description = "Directory for the output qcow2. Override to a WSL-native path (e.g. /home/user/packer-output) to avoid NTFS locking issues."
  default     = "output"
}

variable "python_version" {
  type        = string
  description = "Python version to install (used to construct the download URL)."
  # No default — must be set alongside python_checksum in packer.auto.pkrvars.hcl.
}

variable "python_checksum" {
  type        = string
  description = "SHA-256 hash of the Python Windows amd64 installer. Must match python_version."
}

variable "cape_agent_commit" {
  type        = string
  description = "CAPEv2 repo commit SHA to download agent.py from. Pin this to prevent supply chain attacks."
}

variable "cape_agent_sha256" {
  type        = string
  description = "SHA-256 hash of agent.py at the pinned commit. Verified after download."
}

# OVMF firmware paths — these are the standard locations on Debian/Ubuntu.
# Override if your build host uses different paths.
variable "ovmf_code" {
  type        = string
  description = "Path to OVMF_CODE_4M.fd (UEFI firmware code) on the build host."
  default     = "/usr/share/OVMF/OVMF_CODE_4M.fd"
}

variable "ovmf_vars" {
  type        = string
  description = "Path to OVMF_VARS_4M.ms.fd (UEFI firmware variables with MS Secure Boot keys) on the build host."
  # Use the .ms.fd variant (pre-enrolled MS Secure Boot keys).
  # With the Win11 ISO on USB XHCI (not SATA), the pre-enrolled SATA boot entries
  # fail fast ("Not Found" — device absent) rather than timing out. OVMF then
  # falls through to the bootindex=1 USB dynamic entry and boots the Win11 ISO.
  # Empty OVMF_VARS_4M.fd has no boot entries at all, causing OVMF to drop to the
  # UEFI interactive shell regardless of bootindex.
  default     = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
}

# =============================================================================
# Source: QEMU builder — Windows 11 guest
# =============================================================================

source "qemu" "windows11_guest" {

  # --- ISO ---
  iso_url      = "file://${var.win11_iso_path}"
  iso_checksum = var.win11_iso_checksum

  # --- Output ---
  output_directory = var.output_directory
  vm_name          = "windows11-guest.qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size

  # --- VM resources ---
  accelerator = "kvm"
  cpus        = var.cpus
  memory      = var.memory
  headless    = var.headless

  # --- UEFI boot (required by Windows 11) ---
  # OVMF provides the UEFI firmware. The 4M variant supports Secure Boot
  # key enrollment if needed in the future.
  efi_boot          = true
  efi_firmware_code = var.ovmf_code
  efi_firmware_vars = var.ovmf_vars

  # --- Disk and network interfaces ---
  disk_interface = "ide"
  net_device     = "e1000"

  # --- QEMU machine type and drive layout ---
  #
  # Why full qemuargs:
  #   The Packer QEMU plugin v1.1.x assigns disk and ISO both to IDE index=0 when
  #   disk_interface="ide", causing a QEMU conflict. Full qemuargs lets us place the
  #   disk on ICH9 IDE (ide-hd) and the Win11 ISO on USB XHCI
  #   (avoids AHCI ATAPI read timeout under nested KVM, RH BZ#1443345).
  #
  # Drive layout:
  #   ide.0 unit=0: main guest disk (ICH9 IDE HDD, installation target)
  #   xhci0:        Win11 ISO (with autounattend.xml at root) as USB CD-ROM (no bootindex — see below)
  #   pflash unit=0/1: OVMF firmware (explicit — suppressed by Packer when qemuargs has -drive)
  #
  # Note: q35 ICH9 IDE (ide.0) only supports unit=0 — cannot use unit=1.
  # autounattend.xml is embedded in the Win11 ISO itself — no secondary drive needed.
  qemuargs = [
    ["-machine", "type=q35,accel=kvm"],
    ["-cpu", "host"],
    ["-vga", "std"],
    # QEMU human monitor on a Unix socket — enables direct keystroke injection
    # and VM control from vm_agent.py without touching the VNC channel.
    # Usage: echo "sendkey ret" | socat - UNIX-CONNECT:<output_dir>/qemu-monitor.sock
    ["-monitor", "unix:${var.output_directory}/qemu-monitor.sock,server,nowait"],
    ["-drive", "if=pflash,format=raw,readonly=on,unit=0,file=${var.ovmf_code}"],
    ["-drive", "if=pflash,format=raw,unit=1,file=${var.output_directory}/efivars.fd"],
    ["-device", "ide-hd,bus=ide.0,unit=0,drive=drive0"],
    ["-drive", "file=${var.output_directory}/windows11-guest.qcow2,if=none,id=drive0,cache=writeback,discard=ignore,format=qcow2"],
    ["-device", "qemu-xhci,id=xhci0"],
    ["-device", "usb-storage,bus=xhci0.0,drive=cdrom0"],
    ["-drive", "file=${var.win11_iso_path},media=cdrom,id=cdrom0,readonly=on,if=none"],
    # autounattend.xml is embedded in the Win11 ISO at /autounattend.xml.
    # WinPE scans the boot ISO root at startup — found immediately, no secondary drive.
  ]

  # --- swtpm (TPM 2.0 emulation) ---
  vtpm = true

  # --- Boot ---
  # OVMF drops to the UEFI interactive shell in nested KVM: USB enumeration
  # completes after OVMF's initial boot attempt. No bootindex is set on the USB
  # device — bootindex=1 was removed because it created a dynamic UEFI entry that
  # overrode the Windows NVRAM boot entry on every Packer-triggered reboot, forcing
  # manual intervention. Without it, initial boot still lands in the UEFI shell
  # (handled by boot_command below), and post-install reboots find the Windows
  # NVRAM entry written by setup.exe and boot directly.
  #
  # boot_wait covers: OVMF init (~10s) + USB enumerate + 5s shell countdown = ~25s.
  # boot_command types the two-step boot sequence at the Shell> prompt:
  #   FS0: — switches to the Win11 ISO ISO9660/Joliet data partition
  #   efi\boot\bootx64.efi — launches the Windows PE bootloader
  boot_wait    = "30s"
  # After bootx64.efi launches, Windows bootmgr shows "Press any key to boot
  # from CD or DVD..." for ~2-3 seconds. <wait1> presses Enter quickly enough
  # to catch it. startup.nsh is NOT on the unattend disk — it caused a spurious
  # first boot attempt that raced with this command and caused bootmgr to time out.
  #
  # Original Win11 ISO is UDF. OVMF mounts UDF on USB block devices as FS1:.
  boot_command = ["FS1:<enter>", "EFI\\BOOT\\bootx64.efi<enter>", "<wait1>", "<enter>"]

  # --- WinRM communicator ---
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
  name    = "windows11-guest"
  sources = ["source.qemu.windows11_guest"]

  # ---------------------------------------------------------------------------
  # 1. System configuration — hostname, power, updates, WinRM hardening
  # ---------------------------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/configure-system.ps1"
    environment_vars = [
      "GUEST_HOSTNAME=${var.guest_hostname}",
    ]
  }

  # Restart after hostname change
  provisioner "windows-restart" {
    restart_check_command = "powershell -Command \"(hostname) -eq '${var.guest_hostname}'\""
    restart_timeout       = "10m"
  }

  # ---------------------------------------------------------------------------
  # 2. Disable Windows Defender
  # ---------------------------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/disable-defender.ps1"
  }

  # ---------------------------------------------------------------------------
  # 3. Install Python
  # ---------------------------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/install-python.ps1"
    environment_vars = [
      "PYTHON_VERSION=${var.python_version}",
      "PYTHON_CHECKSUM=${var.python_checksum}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 4. Install Cape agent (cape-agent.py)
  # ---------------------------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/install-cape-agent.ps1"
    environment_vars = [
      "CAPE_AGENT_COMMIT=${var.cape_agent_commit}",
      "CAPE_AGENT_SHA256=${var.cape_agent_sha256}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 5. Create realistic guest user account
  # ---------------------------------------------------------------------------
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
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/set-resolution.ps1"
  }

  # ---------------------------------------------------------------------------
  # 7. Create decoy user files
  # ---------------------------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/create-decoy-files.ps1"
    environment_vars = [
      "GUEST_USERNAME=${var.guest_username}",
    ]
  }

  # ---------------------------------------------------------------------------
  # 8. Cleanup
  # ---------------------------------------------------------------------------
  provisioner "powershell" {
    script = "${path.root}/scripts/windows/cleanup.ps1"
  }
}
