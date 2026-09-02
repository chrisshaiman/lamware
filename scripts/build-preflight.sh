#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Preflight for the Windows 11 Packer build.
#
# The prerequisites were spread across three files and no single one was
# complete: DEPLOYMENT.md listed qemu but not ovmf/swtpm/mtools/packer, the
# ovmf+swtpm line lived in a comment at the top of windows11-base.pkr.hcl, and
# mtools/unzip only in packer/README.md. Membership of the `kvm` group was
# written down nowhere. A first-time builder found each one by failing.
#
# Everything here is checked by DOING it, not by looking for a proxy:
# /dev/kvm is opened rather than stat'd (the device node is present and
# world-visible on a box where the user cannot open it), and the Packer version
# is compared against the constraint parsed out of the templates rather than a
# number duplicated here that could drift from them.

set -uo pipefail
cd "$(dirname "$0")/.."

MISSING=0
PACKER_DIR=packer
PKRVARS="$PACKER_DIR/packer.auto.pkrvars.hcl"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

ok()   { grn "  OK       $1"; }
fail() { red "  MISSING  $1"; printf '           %s\n' "$2"; MISSING=$((MISSING+1)); }
warn() { ylw "  WARN     $1"; printf '           %s\n' "$2"; }

echo "==> Build host preflight (Windows 11 guest images)"
echo

# --- tools -----------------------------------------------------------------
echo "Tools"

if command -v packer >/dev/null; then
  have=$(packer version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  # The constraint lives in the templates. Parse it so this check cannot drift
  # from what Packer itself will enforce (#520).
  want=$(grep -hoE 'required_version *= *"[^"]+"' "$PACKER_DIR"/*.pkr.hcl \
         | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  if [ "${have%.*}" = "${want%.*}" ]; then
    ok "packer $have (templates require ~> $want)"
  else
    fail "packer $have, but the templates require ~> $want" \
         "See packer/README.md — install the pinned release, do not use the apt repo."
  fi
else
  want=$(grep -hoE 'required_version *= *"[^"]+"' "$PACKER_DIR"/*.pkr.hcl \
         | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  fail "packer (need ~> $want)" "Install per packer/README.md — pinned binary, checksum verified."
fi

for t in qemu-system-x86_64 qemu-img swtpm mformat mcopy unzip; do
  if command -v "$t" >/dev/null; then ok "$t"; else
    case $t in
      qemu-system-x86_64|qemu-img) pkg="qemu-system-x86 qemu-utils" ;;
      swtpm)                       pkg="swtpm" ;;
      mformat|mcopy)               pkg="mtools" ;;
      unzip)                       pkg="unzip" ;;
    esac
    fail "$t" "sudo apt install $pkg"
  fi
done

# --- KVM -------------------------------------------------------------------
echo
echo "Virtualisation"

if ! grep -qE '\b(vmx|svm)\b' /proc/cpuinfo; then
  fail "CPU virtualisation (vmx/svm)" "Enable VT-x/AMD-V in firmware. Under WSL2, nested virtualisation must be on."
elif [ ! -e /dev/kvm ]; then
  fail "/dev/kvm" "Load the kvm module, or enable nested virtualisation for this VM."
elif { : < /dev/kvm; } 2>/dev/null; then
  ok "/dev/kvm openable"
else
  fail "/dev/kvm is present but this user cannot open it" \
       "sudo usermod -aG kvm $USER   — then restart your session (WSL: wsl --shutdown)"
fi

# --- firmware --------------------------------------------------------------
echo
echo "UEFI firmware"

# The templates default to the Debian/Ubuntu layout. Other distros put these
# elsewhere, which is why both are overridable variables — report the override
# rather than only the default, or this check lies on a host that is fine.
for v in ovmf_code:OVMF_CODE_4M.fd ovmf_vars:OVMF_VARS_4M.fd; do
  var=${v%%:*}; file=${v##*:}
  # awk over the whole variable block, not a fixed -A window: ovmf_vars puts
  # its default 14 lines below the header, so a short window silently yields an
  # empty path and reports "not found" on a host where the file is present.
  path=$(awk -v v="variable \"$var\"" '
      index($0,v)==1 {inb=1} inb && /default/ {print; exit}' \
      "$PACKER_DIR/windows11-base.pkr.hcl" | grep -oE '/[^"]+\.fd' | head -1)
  [ -f "$PKRVARS" ] && ovr=$(grep -oE "^ *$var *= *\"[^\"]+\"" "$PKRVARS" 2>/dev/null \
         | grep -oE '/[^"]+' | head -1) || ovr=""
  [ -n "$ovr" ] && path=$ovr
  if [ -f "$path" ]; then ok "$var -> $path"; else
    fail "$var -> $path not found" \
         "sudo apt install ovmf   (other distros: set $var in $PKRVARS)"
  fi
done

# --- build inputs ----------------------------------------------------------
echo
echo "Build inputs"

if [ -f "$PKRVARS" ]; then
  ok "$PKRVARS"
  for var in win11_iso_path win11_iso_checksum winrm_password \
             python_checksum cape_agent_commit cape_agent_sha256; do
    val=$(grep -oE "^ *$var *= *\"[^\"]*\"" "$PKRVARS" | sed -E 's/.*= *"(.*)"/\1/')
    if [ -z "$val" ] || printf '%s' "$val" | grep -qE '^<|CHANGEME'; then
      fail "$var unset in $PKRVARS" "See $PACKER_DIR/packer.auto.pkrvars.hcl.example"
    elif [ "$var" = win11_iso_path ] && [ ! -f "$val" ]; then
      fail "win11_iso_path points at a file that does not exist" "$val"
    else
      ok "$var"
    fi
  done
else
  fail "$PKRVARS" "cp $PACKER_DIR/packer.auto.pkrvars.hcl.example $PKRVARS, then fill it in."
fi

# --- capacity --------------------------------------------------------------
echo
echo "Capacity"

free_gb=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
[ "${free_gb:-0}" -ge 100 ] && ok "disk ${free_gb}G free" \
  || fail "disk ${free_gb}G free, need ~100G" "base 64G + guest + office outputs"

ram_gb=$(free -g | awk '/^Mem:/{print $2}')
[ "${ram_gb:-0}" -ge 8 ] && ok "RAM ${ram_gb}G" \
  || warn "RAM ${ram_gb}G is below the documented 8G" "The build asks for 4G; other work on this box will contend."

# --- verdict ---------------------------------------------------------------
echo
if [ "$MISSING" -eq 0 ]; then
  grn "==> Ready. Next: make win11-base   (45-90 min; run under tmux)"
else
  red "==> $MISSING prerequisite(s) missing. Fix the lines above, then re-run: make build-preflight"
  exit 1
fi
