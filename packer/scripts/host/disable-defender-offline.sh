#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Disable Windows Defender by editing the image's registry hives OFFLINE.
#
# WHY THIS EXISTS (#548): every hook an answer file offers runs either before the
# target hives exist (windowsPE, which edits WinPE's own in-memory registry) or
# after Windows -- and therefore Tamper Protection -- is up (specialize,
# oobeSystem). The 25H2 base build proved it: the specialize pass ran, and
# Defender deleted its values before first login. DisableAntiSpyware has been
# deprecated and actively removed since Windows 10 2004, and Tamper Protection
# restores WinDefend\Start.
#
# Offline, nothing is defending them. TamperProtection=0 is the load-bearing
# value; with it set, the specialize writes stop being reverted and become
# genuine belt-and-braces rather than the only mechanism.
#
# Needs root: modprobe, qemu-nbd, mount.
#
# Usage: sudo packer/scripts/host/disable-defender-offline.sh [image.qcow2]

set -euo pipefail

IMG="${1:-$HOME/packer-output/windows11-base.qcow2}"
NBD="${NBD_DEV:-/dev/nbd0}"
MNT="$(mktemp -d /tmp/win-offline.XXXXXX)"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -f "$IMG" ] || { echo "ERROR: no image at $IMG" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root (modprobe/qemu-nbd/mount)" >&2; exit 1; }

cleanup() {
  mountpoint -q "$MNT" && umount "$MNT" || true
  qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || true
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> image: $IMG"
modprobe nbd max_part=8
qemu-nbd --disconnect "$NBD" >/dev/null 2>&1 || true
qemu-nbd --connect="$NBD" "$IMG"
# udev is not running under WSL2, so give the kernel a moment to expose parts
for _ in $(seq 1 20); do [ -e "${NBD}p1" ] && break; sleep 0.5; done

# The Windows partition is the largest NTFS one -- p1 is the ESP, p2 MSR, p4 the
# recovery image. Picking by size rather than by number, because the layout
# shifts between builds and a wrong guess silently edits the recovery hive.
WINPART=""; BEST=0
for p in "${NBD}"p*; do
  sz=$(blockdev --getsize64 "$p" 2>/dev/null || echo 0)
  if blkid -o value -s TYPE "$p" 2>/dev/null | grep -q ntfs && [ "$sz" -gt "$BEST" ]; then
    BEST=$sz; WINPART=$p
  fi
done
[ -n "$WINPART" ] || { echo "ERROR: no NTFS partition found on $NBD" >&2; exit 1; }
echo "==> windows partition: $WINPART ($((BEST/1024/1024/1024)) GB)"

mount -t ntfs-3g "$WINPART" "$MNT"
CFG="$MNT/Windows/System32/config"
[ -f "$CFG/SOFTWARE" ] || { echo "ERROR: $CFG/SOFTWARE not found - wrong partition?" >&2; exit 1; }

cp -a "$CFG/SOFTWARE" "$CFG/SOFTWARE.pre-defender-off"
cp -a "$CFG/SYSTEM"   "$CFG/SYSTEM.pre-defender-off"
echo "==> hives backed up in place (*.pre-defender-off)"

hivexregedit --merge --prefix 'HKEY_LOCAL_MACHINE\SOFTWARE' \
  "$CFG/SOFTWARE" "$HERE/defender-off-software.reg"
hivexregedit --merge --prefix 'HKEY_LOCAL_MACHINE\SYSTEM' \
  "$CFG/SYSTEM"   "$HERE/defender-off-system.reg"
echo "==> hives merged"

# Read the values back OUT of the hive. Writing without verifying is how #548
# shipped: a step that reported success and changed nothing.
echo "==> verifying:"
hivexregedit --export --prefix 'HKEY_LOCAL_MACHINE\SYSTEM' \
  "$CFG/SYSTEM" '\ControlSet001\Services\WinDefend' 2>/dev/null \
  | grep -iE '"Start"' | sed 's/^/    WinDefend /'
hivexregedit --export --prefix 'HKEY_LOCAL_MACHINE\SOFTWARE' \
  "$CFG/SOFTWARE" '\Microsoft\Windows Defender\Features' 2>/dev/null \
  | grep -iE '"TamperProtection"' | sed 's/^/    Features  /'

sync
echo "==> done. Next: make win11-guest  (verify-defender-disabled.ps1 is the real test)"
