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

# --- Primary path: bootindex=0 on SATA CDROM ---
# OVMF boots the ISO directly. bootmgr shows "Press any key to boot from CD
# or DVD..." after ~10-12s. Send Enter to confirm.
echo "boot-helper: socket found. Waiting 12s for 'Press any key' prompt..."
sleep 12
send_key ret
echo "boot-helper: sent Enter for 'Press any key' prompt."

# --- Fallback: UEFI shell (if bootindex didn't work) ---
# Wait a bit, then send the full shell boot command in case we landed at Shell>.
# If WinPE is already loading (primary path worked), these keystrokes are harmless
# because WinPE doesn't have a text input prompt during early boot.
sleep 15
echo "boot-helper: sending fallback shell boot command..."
send_key ret  # dismiss startup.nsh countdown or get fresh Shell> prompt
sleep 2
send_string 'FS1:\EFI\BOOT\bootx64.efi'
sleep 0.2
send_key ret

# Handle "Press any key" if the fallback triggered it
sleep 3
send_key ret

echo "boot-helper: boot commands sent. WinPE should be loading."

# --- Eject + re-insert CDROM to prevent reboot loop ---
# The ISO uses cdboot_noprompt.efi — boots WinPE immediately on every reboot
# without any "Press any key" timeout. bootindex=0 makes OVMF try the CDROM
# first, so WinPE reboots into itself endlessly (~20s cycles).
#
# Fix: poll the qcow2 disk image until Windows Setup starts writing to it
# (>20MB = partitioning/file copy underway), then eject the CDROM to break
# the boot loop and re-insert so WinPE can still read install.wim.
# A fixed sleep doesn't work — nested KVM timing is unpredictable.
echo "boot-helper: waiting for Windows Setup to write to disk (polling ${QCOW2})..."
WAITED=0
MAX_WAIT=1800  # 30 min — if nothing by then, Setup failed
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
  if [ -f "$QCOW2" ]; then
    SIZE=$(stat -c%s "$QCOW2" 2>/dev/null || echo 0)
    SIZE_MB=$((SIZE / 1048576))
    if [ "$SIZE_MB" -gt 20 ]; then
      echo "boot-helper: qcow2 is ${SIZE_MB}MB — Setup is writing. Proceeding with eject."
      break
    fi
  fi
  sleep 10
  WAITED=$((WAITED + 10))
  if [ $((WAITED % 60)) -eq 0 ]; then
    SIZE_MB=$((${SIZE:-0} / 1048576))
    echo "boot-helper: waiting... (${WAITED}s, qcow2: ${SIZE_MB}MB)"
  fi
done

if [ "$WAITED" -ge "$MAX_WAIT" ]; then
  echo "boot-helper: WARNING — qcow2 never grew past 20MB after ${MAX_WAIT}s. Setup may have failed." >&2
  echo "boot-helper: skipping CDROM eject. Check VNC for errors." >&2
  exit 0
fi

echo "boot-helper: ejecting CDROM to break reboot loop..."
echo "eject cdrom0" | socat - UNIX-CONNECT:"$SOCK" 2>/dev/null
sleep 2
echo "boot-helper: re-inserting ISO so WinPE can access install.wim..."
echo "change cdrom0 ${ISO_PATH}" | socat - UNIX-CONNECT:"$SOCK" 2>/dev/null
echo "boot-helper: CDROM cycled. install.wim accessible, reboot loop broken."
