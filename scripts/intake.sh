#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Front door for corpus intake: detonate an owner-approved list of new samples.
#
# Breadth needs new detonations, and the auto-feeder picks ONE sample per cycle
# from MalwareBazaar's latest 100 -- it cannot take a reviewed list. This runs a
# committed manifest (scripts/intake/*.json: sha256 + MalwareBazaar signature)
# through the feeder's own download code and the normal pipeline, one sample at a
# time, under a one-shot systemd unit on the sandbox. Promotion into the eval
# corpus is a separate, reviewed step (lamware_eval.promote).
#
# THIS DETONATES LIVE MALWARE. Operator-typed, enables nothing, and refuses to
# start while another batch, an eval, or the auto-feeder is running.
set -uo pipefail
# shellcheck source=scripts/lib/remote-oneshot.sh
. "$(dirname "$0")/lib/remote-oneshot.sh"

HOST=${SANDBOX_HOST:-sandbox}
MANIFEST=${MANIFEST:-}
UNIT=lamware-intake
say() { printf '==> %s\n' "$*"; }

if [ -z "$MANIFEST" ] || [ ! -f "$MANIFEST" ]; then
  echo "usage: make intake MANIFEST=scripts/intake/<batch>.json" >&2
  exit 2
fi
NAME=$(basename "$MANIFEST" .json)
B=/opt/pipeline/intake/$NAME
N=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$MANIFEST") || exit 2

for u in "$UNIT" lamware-detonate auto-feeder; do
  if remote_unit_busy "$HOST" "$u"; then
    echo "ERROR: $u is $(remote_unit_state "$HOST" "$u") -- refusing to start a second detonation path." >&2
    exit 1
  fi
done
if ssh "$HOST" "systemctl list-units --type=service --state=active,activating --no-legend 'lamware-eval*' | grep -q ."; then
  echo "ERROR: an eval unit is running; the pipeline's interpret stage would contend for the model." >&2
  exit 1
fi
if ssh "$HOST" "test -e /opt/pipeline/control/PAUSE"; then
  echo "ERROR: /opt/pipeline/control/PAUSE exists." >&2
  exit 1
fi

say "batch=$NAME samples=$N -> $B"
say "THIS DETONATES LIVE MALWARE on $HOST."
ssh "$HOST" "sudo install -d -o root -g lamware -m 2770 /opt/pipeline/intake '$B'" || exit 1
ssh "$HOST" "sudo tee '$B/manifest.json' >/dev/null && sudo chmod 0644 '$B/manifest.json'" < "$MANIFEST" || exit 1
ssh "$HOST" "sudo tee '$B/intake_download.py' >/dev/null && sudo chmod 0755 '$B/intake_download.py'" < "$(dirname "$0")/lib/intake_download.py" || exit 1
ssh "$HOST" "sudo tee '$B/intake_run.sh' >/dev/null && sudo chmod 0755 '$B/intake_run.sh'" < "$(dirname "$0")/lib/intake_run.sh" || exit 1
ssh "$HOST" "sudo tee /etc/systemd/system/${UNIT}.service >/dev/null" <<UNITEOF
[Unit]
Description=lamware corpus intake batch $NAME (one-shot, operator-started)
After=network-online.target cape.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $B/intake_run.sh $B
TimeoutStartSec=infinity
UNITEOF
ssh "$HOST" "sudo systemctl daemon-reload && sudo systemctl start --no-block ${UNIT}.service" || exit 1
say "started; following $B/intake.log (Ctrl-C detaches, the batch keeps running)"
remote_unit_follow "$HOST" "$UNIT" "$B/intake.log"
