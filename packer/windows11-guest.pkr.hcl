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
#   - Autounattend floppy: run `make autounattend-floppy` once (re-run after editing autounattend.xml)
#   - packer.auto.pkrvars.hcl with:
#       winrm_password      = "Packer@Build1"   # must match win11-autounattend.xml
#       win11_iso_path      = "/path/to/Win11_EnterpriseEval.iso"
#       win11_iso_checksum  = "sha256:<checksum>"
#
# autounattend.xml delivery:
#   A virtual floppy (A:) containing autounattend.xml is attached via -fda.
#   WinPE checks A: before all other drives — the most reliable delivery
#   method for QEMU Windows builds, independent of ISO filesystem type.
#   Pre-build: run `make autounattend-floppy` once per autounattend.xml change.
#
# Build:
#   make autounattend-floppy        # run once, re-run after editing autounattend.xml
#   make win11-image
#   # or directly: cd packer/ && packer build -var-file=packer.auto.pkrvars.hcl windows11-guest.pkr.hcl
#
# After build:
#   Copy packer/output/windows11-guest.qcow2 to the bare metal host.
#   Ansible roles/cape/ imports it and creates clean-w11 + office-w11 snapshots.
#   See docs/STATUS.md for the full workflow.
#
# Troubleshooting:
#   To watch the VM's display in real-time (boot, Setup, OOBE), set headless=false:
#     packer build -var headless=false -var-file=packer.auto.pkrvars.hcl windows11-guest.pkr.hcl
#   This opens a QEMU window via WSLg (Windows 11 ships WSLg by default).
#   Much faster than VNC for debugging boot or installer issues.
#   Do NOT connect a separate VNC client while Packer is typing boot_command —
#   wait until "Waiting for WinRM" appears in the build log.
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
  # No default — set in packer.auto.pkrvars.hcl.
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
  # No default — set in packer.auto.pkrvars.hcl.
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
  description = "Run without display. Set false to show QEMU window for debugging (see Troubleshooting below)."
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

variable "autounattend_img_path" {
  type        = string
  description = "Path to the autounattend floppy image (FAT12, 1.44 MB) containing autounattend.xml at the root. Create with: make autounattend-floppy. Set in packer.auto.pkrvars.hcl."
  # No default — must be set in packer.auto.pkrvars.hcl.
}

variable "efivars_path" {
  type        = string
  description = "Path for the writable OVMF VARS file (efivars.fd). Must be outside output_directory — packer -force deletes the output directory before QEMU starts, which would destroy efivars.fd if it lived there. make win11-image copies a fresh OVMF_VARS_4M.fd here before each build."
  # /tmp works for all Linux/WSL builds without any per-machine configuration.
  # Override in packer.auto.pkrvars.hcl if you need a persistent location.
  default     = "/tmp/packer-win11-efivars.fd"
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
  description = "Path to OVMF_VARS_4M.fd (empty UEFI firmware variables) on the build host."
  # Use the EMPTY vars file (not .ms.fd).
  #
  # OVMF_VARS_4M.fd is empty: no boot entries, no Secure Boot keys. Boot order
  # is controlled entirely by QEMU bootindex args (CDROM=0, HDD=1). After
  # Windows Setup runs, it writes its own UEFI boot entry to efivars.fd.
  #
  # Secure Boot: empty vars = OVMF "Setup Mode" (not enforced). autounattend.xml
  # includes BypassSecureBootCheck as belt-and-suspenders. No key enrollment needed.
  #
  # IMPORTANT: make win11-image copies a fresh OVMF_VARS_4M.fd to efivars.fd
  # before each build so stale NVRAM entries from failed builds never carry over.
  default     = "/usr/share/OVMF/OVMF_VARS_4M.fd"
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

  # --- Disk, CDROM, and network interfaces ---
  disk_interface = "ide"
  net_device     = "e1000"
  machine_type   = "q35"

  # --- Minimal qemuargs — only what Packer can't configure natively ---
  #
  # IMPORTANT: When qemuargs is present, Packer's QEMU plugin (v1.1.4) drops
  # ALL auto-generated drives — pflash (OVMF), disk, and CDROM. We MUST
  # include them all explicitly here. Without pflash: SeaBIOS instead of UEFI.
  # Without disk: WinPE crashes immediately (no target disk found).
  #
  # Packer still handles: network (e1000 + WinRM port forward), VNC, memory,
  # SMP, TPM.
  # Both disk and CDROM land on the SAME built-in ICH9 AHCI controller
  # (different ports), which is critical — a separate AHCI controller splits
  # CDROM partitions and breaks cdboot.efi (RH BZ#1443345).
  qemuargs = [
    ["-cpu", "host"],
    ["-vga", "std"],
    # OVMF UEFI firmware — pflash drives for UEFI boot (required by Win11).
    # Code is read-only, vars is writable (stores UEFI boot entries).
    ["-drive", "if=pflash,format=raw,readonly=on,file=${var.ovmf_code}"],
    ["-drive", "if=pflash,format=raw,file=${var.efivars_path}"],
    # Hard disk — IDE on the built-in ICH9 controller. Packer creates the
    # qcow2 but doesn't attach it when qemuargs is present.
    # bootindex=1: OVMF tries HDD after CDROM (bootindex=0) times out.
    ["-device", "ide-hd,bus=ide.0,unit=0,drive=hdd0,bootindex=1"],
    ["-drive", "file=${var.output_directory}/windows11-guest.qcow2,id=hdd0,format=qcow2,if=none"],
    # QEMU monitor socket — useful for manual debugging (screendumps, etc.)
    ["-monitor", "unix:${var.output_directory}/qemu-monitor.sock,server,nowait"],
    # Virtual floppy (A:) with autounattend.xml — WinPE checks A: first
    ["-fda", var.autounattend_img_path],
    # Suppress e1000 PXE ROM to prevent OVMF network boot loops
    ["-global", "e1000.rombar=0"],
    # CDROM on ide.1 (same built-in ICH9 as HDD on ide.0).
    # bootindex=0 → OVMF boots CDROM first (no UEFI Shell needed).
    # bootindex=1 on HDD → after "Press any key" times out on subsequent
    # reboots, OVMF falls through to HDD where Windows Boot Manager lives.
    ["-device", "ide-cd,bus=ide.1,unit=0,drive=cdrom0,bootindex=0"],
    ["-drive", "file=${var.win11_iso_path},media=cdrom,id=cdrom0,readonly=on,if=none"],
  ]

  # --- swtpm (TPM 2.0 emulation) ---
  vtpm = true

  # --- Boot ---
  # With bootindex=0 on the CDROM, OVMF boots from CDROM directly — no
  # UEFI Shell, no startup.nsh needed.
  #
  # Boot flow:
  #   1. OVMF boots from CDROM (bootindex=0) → bootx64.efi loads (~5-8s)
  #   2. "Press any key to boot from CD or DVD..." appears (~5s timeout)
  #   3. boot_command sends Enter via VNC to catch the prompt
  #   4. WinPE loads → autounattend.xml on A: (floppy) drives unattended install
  #
  # Subsequent reboots: "Press any key" times out (no VNC input) → OVMF
  # falls through to the Windows Boot Manager entry that Setup wrote to
  # efivars → Windows continues setup from HDD. No CDROM eject needed.
  #
  boot_wait    = "1s"
  boot_command = [
    # Rapid Enters to catch "Press any key to boot from CD or DVD..."
    # With bootindex=0, the prompt appears very quickly after boot.
    # Enters every 1s from 1-15s covers the entire window.
    "<enter><wait1><enter><wait1><enter><wait1><enter><wait1><enter>",
    "<wait1><enter><wait1><enter><wait1><enter><wait1><enter><wait1><enter>",
    "<wait1><enter><wait1><enter><wait1><enter><wait1><enter><wait1><enter>"
  ]

  # --- WinRM communicator ---
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = var.winrm_password
  winrm_timeout  = "4h"   # Windows Setup + OOBE + WinRM enable takes ~45-90 min
  winrm_port     = 5985
  winrm_use_ssl  = false

  # Graceful shutdown after provisioning
  # Disable Administrator account (no longer needed after provisioning), then
  # shut down. Must be in shutdown_command, not cleanup.ps1 — cleanup runs
  # over WinRM as Administrator, so disabling the account there kills the
  # WinRM session before Packer can send the shutdown command.
  shutdown_command = "powershell -Command \"Disable-LocalUser -Name Administrator\"; shutdown /s /t 5 /f /d p:4:1"
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
