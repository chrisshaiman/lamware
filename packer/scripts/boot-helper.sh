#!/bin/bash
# boot-helper.sh — Press Enter for the "Press any key to boot from CD or DVD"
# prompt via QEMU monitor sendkey. Falls back to typing the full UEFI shell
# boot command if bootindex doesn't work.
#
# With SATA CDROM + bootindex=0, OVMF boots the ISO directly — the main job
# is just pressing Enter for bootmgr's "Press any key" prompt.
#
# If bootindex fails (e.g., OVMF drops to the UEFI shell instead), this script
# also types the full shell boot command as a fallback.
#
# Usage: boot-helper.sh <qemu-monitor-socket-path> <iso-path> <output-dir>
#   Called by: make win11-image (runs in background before packer build)
#
# Author: Christopher Shaiman
# License: Apache 2.0

set -euo pipefail

SOCK="${1:?Usage: boot-helper.sh <qemu-monitor-socket-path> <iso-path> <output-dir>}"
ISO_PATH="${2:?Usage: boot-helper.sh <qemu-monitor-socket-path> <iso-path> <output-dir>}"
OUTPUT_DIR="${3:?Usage: boot-helper.sh <qemu-monitor-socket-path> <iso-path> <output-dir>}"
QCOW2="${OUTPUT_DIR}/windows11-guest.qcow2"
KEY_DELAY=0.05  # seconds between keystrokes

send_key() {
  echo "sendkey $1" | socat - UNIX-CONNECT:"$SOCK" 2>/dev/null
  sleep "$KEY_DELAY"
}

send_char() {
  local c="$1"
  case "$c" in
    [A-Z]) send_key "shift-$(echo "$c" | tr 'A-Z' 'a-z')" ;;
    [a-z]) send_key "$c" ;;
    [0-9]) send_key "$c" ;;
    ':')   send_key "shift-semicolon" ;;
    '\')   send_key "backslash" ;;
    '.')   send_key "dot" ;;
    ' ')   send_key "spc" ;;
    *)     echo "boot-helper: unknown char '$c'" >&2 ;;
  esac
}

send_string() {
  local str="$1"
  for (( i=0; i<${#str}; i++ )); do
    send_char "${str:$i:1}"
  done
}

echo "boot-helper: waiting for QEMU monitor socket at $SOCK ..."

# Wait up to 120s for the socket to appear (QEMU needs to start first)
for i in $(seq 1 120); do
  [ -S "$SOCK" ] && break
  sleep 1
done

if [ ! -S "$SOCK" ]; then
  echo "boot-helper: ERROR — socket $SOCK did not appear after 120s" >&2
  exit 1
fi

# --- Boot keystrokes are handled by Packer boot_command (via VNC) ---
#
# Boot flow with OVMF (empty NVRAM vars):
#   1. OVMF enumerates devices → no boot entries → drops to UEFI Interactive Shell
#   2. Shell auto-executes startup.nsh from the floppy (A:) after 1s countdown
#   3. startup.nsh runs: FS0:\EFI\BOOT\bootx64.efi (the CDROM boot loader)
#   4. "Press any key to boot from CD or DVD..." prompt appears
#   5. Packer's boot_command sends Enter at multiple intervals to catch the prompt
#   6. WinPE loads → autounattend.xml on A: takes over
#
# boot-helper.sh only handles:
#   - CDROM eject/re-insert (prevents reboot loop after WinPE starts Setup)
#   - Periodic screendumps for OOBE diagnostics

echo "boot-helper: socket found. Packer boot_command handles boot keystrokes."
echo "boot-helper: No CDROM eject needed — CDROM has no bootindex, so OVMF boots"
echo "boot-helper: from HDD after Windows Setup writes a boot entry to efivars."

# --- Periodic screendumps for OOBE diagnostics ---
# Capture a screenshot every 60s so we can see where OOBE is (or where it stalled).
# Stops after 90 minutes or when the monitor socket disappears (QEMU shut down).
DUMP_DIR="${OUTPUT_DIR}/screendumps"
mkdir -p "$DUMP_DIR"
echo "boot-helper: starting screendump capture to ${DUMP_DIR}/ (every 60s, up to 90 min)..."

DUMP_WAITED=0
DUMP_MAX=5400  # 90 min
while [ "$DUMP_WAITED" -lt "$DUMP_MAX" ]; do
  if [ ! -S "$SOCK" ]; then
    echo "boot-helper: monitor socket gone — QEMU shut down. Stopping screendumps."
    break
  fi
  TIMESTAMP=$(date +%Y%m%d-%H%M%S)
  echo "screendump ${DUMP_DIR}/screen-${TIMESTAMP}.ppm" | socat - UNIX-CONNECT:"$SOCK" 2>/dev/null || true
  sleep 60
  DUMP_WAITED=$((DUMP_WAITED + 60))
done

echo "boot-helper: screendump capture finished. Check ${DUMP_DIR}/ for OOBE progress images."
