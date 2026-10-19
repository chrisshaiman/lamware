#!/bin/bash
# =============================================================================
# lamware-persist-firewall — save the live iptables rule sets for
# netfilter-persistent WITHOUT the chains other agents own (#580).
#
# `netfilter-persistent save` is `iptables-save` of the live tables, and the
# live tables include podman's port-publish chains (CNI-HOSTPORT-DNAT, CNI-DN-*;
# NETAVARK-* on newer podman) with a DNAT aimed at the container IP of the
# moment. Restored at boot, that DNAT lands ahead of the one podman creates for
# the new container, and every connection to the published port goes to an
# address nothing holds: the local model "listening" for six days while every
# request timed out (#580), and again after the 2026-10-18 reboot.
#
# Podman recreates its chains when a container starts. Nothing else does, so
# dropping them from what is persisted loses nothing of ours.
#
# Usage:  lamware-persist-firewall            # write /etc/iptables/rules.v4 and .v6
#         lamware-persist-firewall --filter   # stdin -> stdout, for tests
# =============================================================================
set -euo pipefail

filter() {
    awk '!/CNI-|NETAVARK/'
}

if [ "${1:-}" = "--filter" ]; then
    filter
    exit 0
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for family in 4 6; do
    save=iptables-save; restore=iptables-restore
    if [ "$family" = 6 ]; then save=ip6tables-save; restore=ip6tables-restore; fi
    "$save" | filter > "$tmp"
    # A rule set that would not restore is worse than none: fail here, loudly.
    "$restore" --test "$tmp"
    install -m 0640 -o root -g root "$tmp" "/etc/iptables/rules.v$family"
done
