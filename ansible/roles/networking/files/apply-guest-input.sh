#!/bin/bash
# Load the guest chain (ADR-020, amended 2026-10-05) from a rendered rules file
# and put its INPUT jump at position 1. Run by roles/networking once per address family.
#
#   apply-guest-input.sh <iptables|ip6tables> <rules-file> <bridge> <chain>
#
# Prints "changed" when the live INPUT or chain differs afterwards, "unchanged"
# otherwise -- the task's changed_when reads it.
#
# A script rather than tasks because the jump has to be placed by rule NUMBER:
# insert at 1 first, then delete any later copies, so there is never a moment
# with no jump at all. ansible.builtin.iptables can only insert or delete by
# spec, and deleting by spec takes the first match -- the new rule at position 1.
set -euo pipefail

cmd=${1:?family} rules=${2:?rules file} bridge=${3:?bridge} chain=${4:?chain}
case "$cmd" in
    iptables|ip6tables) ;;
    *) echo "unknown family: $cmd" >&2; exit 2 ;;
esac
jump="-A INPUT -i $bridge -j $chain"

snapshot() {
    "$cmd" -w -S "$chain" 2>/dev/null || true
    "$cmd" -w -S INPUT
}
before=$(snapshot)

# One transaction: with --noflush, the `:chain` line creates the chain or
# empties it and the -A lines refill it. Never half-built; the order on the
# host is the order in the file.
"${cmd}-restore" -w --noflush "$rules"

first=$("$cmd" -w -S INPUT | awk '/^-A INPUT /{print; exit}')
if [ "$first" != "$jump" ]; then
    "$cmd" -w -I INPUT 1 -i "$bridge" -j "$chain"
fi
# Later copies, highest rule number first so the remaining numbers stay valid.
"$cmd" -w -S INPUT \
    | awk -v j="$jump" '/^-A INPUT /{ n++; if (n > 1 && $0 == j) print n }' \
    | sort -rn \
    | while read -r n; do "$cmd" -w -D INPUT "$n"; done

after=$(snapshot)
if [ "$before" = "$after" ]; then echo unchanged; else echo changed; fi
