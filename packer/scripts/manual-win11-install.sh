#!/bin/bash
# manual-win11-install.sh — Boot Windows 11 ISO in QEMU for interactive install.
# No Packer, no autounattend. Install via VNC, then run provisioners manually.
#
# Usage: ./manual-win11-install.sh
#   Connect VNC to localhost:5900 after launch.
#   boot-helper.sh runs in the background to handle UEFI boot.
#
# After install completes:
#   1. Enable WinRM manually in the guest (PowerShell as Admin):
#      winrm quickconfig -q
#      winrm set winrm/config/service '@{AllowUnencrypted="true"}'
#      winrm set winrm/config/service/auth '@{Basic="true"}'
#      net user Administrator Packer@Build1 /active:yes
#   2. Shut down the guest
#   3. Output: $WIN11_OUTPUT_DIR/windows11-guest.qcow2
#
# Author: Christopher Shaiman
# License: Apache 2.0

set -euo pipefail

# Source .env from repo root if it exists
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
[ -f "$REPO_ROOT/.env" ] && export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)

# --- Configuration (set via .env or environment) ---
ISO_PATH="${WIN11_ISO_PATH:?Set WIN11_ISO_PATH in .env}"
OUTPUT_DIR="${WIN11_OUTPUT_DIR:?Set WIN11_OUTPUT_DIR in .env}"
QCOW2="${OUTPUT_DIR}/windows11-guest.qcow2"
EFIVARS="${OUTPUT_DIR}/efivars.fd"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS_TEMPLATE="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
MONITOR_SOCK="${OUTPUT_DIR}/qemu-monitor.sock"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Pre-flight checks ---
[ -f "$ISO_PATH" ] || { echo "ERROR: ISO not found at $ISO_PATH"; exit 1; }
[ -f "$OVMF_CODE" ] || { echo "ERROR: OVMF_CODE not found. Run: sudo apt-get install ovmf"; exit 1; }
[ -f "$OVMF_VARS_TEMPLATE" ] || { echo "ERROR: OVMF_VARS not found."; exit 1; }
command -v qemu-system-x86_64 >/dev/null || { echo "ERROR: qemu-system-x86_64 not found."; exit 1; }
command -v socat >/dev/null || { echo "ERROR: socat not found. Run: sudo apt-get install socat"; exit 1; }
command -v swtpm >/dev/null || { echo "ERROR: swtpm not found. Run: sudo apt-get install swtpm"; exit 1; }

# --- Setup output directory ---
mkdir -p "$OUTPUT_DIR"

# --- Create or reuse disk image ---
if [ ! -f "$QCOW2" ] || [ "$(stat -c%s "$QCOW2")" -lt 1048576 ]; then
  echo "==> Creating fresh 64GB qcow2 disk..."
  qemu-img create -f qcow2 "$QCOW2" 64G
else
  echo "==> Reusing existing disk: $QCOW2 ($(du -h "$QCOW2" | cut -f1))"
fi

# --- Fresh OVMF vars (clean NVRAM) ---
echo "==> Copying fresh OVMF VARS to $EFIVARS..."
cp "$OVMF_VARS_TEMPLATE" "$EFIVARS"

# --- Start swtpm (TPM 2.0 emulation) ---
TPMDIR="${OUTPUT_DIR}/tpm"
mkdir -p "$TPMDIR"
# Kill any existing swtpm
pkill -f "swtpm socket.*${TPMDIR}" 2>/dev/null || true
sleep 1
echo "==> Starting swtpm..."
swtpm socket \
  --tpmstate dir="$TPMDIR" \
  --ctrl type=unixio,path="${TPMDIR}/swtpm.sock" \
  --tpm2 \
  --log level=0 &
SWTPM_PID=$!
sleep 1

# --- Start boot-helper in background ---
echo "==> Starting boot-helper (will send Enter for 'Press any key' prompt)..."
"$SCRIPT_DIR/boot-helper.sh" "$MONITOR_SOCK" "$ISO_PATH" "$OUTPUT_DIR" &
HELPER_PID=$!

# --- Launch QEMU ---
echo "==> Starting QEMU..."
echo "    VNC: localhost:5950"
echo "    Monitor socket: $MONITOR_SOCK"
echo "    Install Windows interactively via VNC."
echo ""
echo "    NOTE: No autounattend — you'll click through the installer manually."
echo "    When asked for a product key, click 'I don't have a product key'."
echo "    Select 'Windows 11 Enterprise Evaluation'."
echo ""

qemu-system-x86_64 \
  -machine type=q35,accel=kvm \
  -cpu host \
  -smp 2 \
  -m 4096 \
  -vga std \
  -drive if=pflash,format=raw,readonly=on,unit=0,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,unit=1,file="$EFIVARS" \
  -drive file="$QCOW2",if=ide,format=qcow2 \
  -device ide-cd,bus=ide.1,unit=0,drive=cdrom0,bootindex=0 \
  -drive file="$ISO_PATH",media=cdrom,id=cdrom0,readonly=on,if=none \
  -global e1000.rombar=0 \
  -net nic,model=e1000 -net user,hostfwd=tcp::5985-:5985 \
  -chardev socket,id=chrtpm,path="${TPMDIR}/swtpm.sock" \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 \
  -monitor unix:"$MONITOR_SOCK",server,nowait \
  -vnc :50

# --- Cleanup ---
echo "==> QEMU exited. Cleaning up..."
kill "$SWTPM_PID" 2>/dev/null || true
kill "$HELPER_PID" 2>/dev/null || true
echo "==> Disk image: $QCOW2"
echo "==> Done."
