#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Shared plumbing for "start a long job on the sandbox and watch it".
#
# Sourced, not executed. Two functions, both of which exist because the obvious
# version is wrong:
#
#   remote_unit_busy    `systemctl is-active --quiet` is NOT usable on a
#                       Type=oneshot unit. Such a unit reports `activating` for
#                       its ENTIRE run, and is-active is true only for `active`,
#                       so the obvious check says "not running" throughout. That
#                       has bitten this project three times -- the third inside a
#                       guard written specifically to prevent it, which then
#                       applied a config change mid-batch and killed task 1166.
#
#   remote_unit_follow  tails the log until the unit leaves the running states,
#                       then reports ActiveState/Result. Detaching the tail must
#                       not kill the job: the batch runs under systemd precisely
#                       so a dropped ssh session cannot take it down.

RUNNING_STATES="activating|active|reloading|deactivating"

remote_unit_busy() {
  local host="$1" unit="$2" state
  state=$(ssh "$host" "systemctl show -p ActiveState --value ${unit}.service" 2>/dev/null)
  [[ "$state" =~ ^($RUNNING_STATES)$ ]]
}

remote_unit_state() {
  ssh "$1" "systemctl show -p ActiveState --value ${2}.service" 2>/dev/null
}

remote_unit_follow() {
  local host="$1" unit="$2" log="$3"
  ssh "$host" "
    sudo touch '$log'
    sudo tail -f -n +1 '$log' &
    TAILPID=\$!
    while :; do
      st=\$(systemctl show -p ActiveState --value ${unit}.service)
      case \"\$st\" in activating|active|reloading|deactivating) sleep 10 ;; *) break ;; esac
    done
    sleep 2; kill \$TAILPID 2>/dev/null
    echo
    echo \"==> ${unit} finished: \$(systemctl show -p ActiveState,Result --value ${unit}.service | paste -sd/)\"
  "
}
