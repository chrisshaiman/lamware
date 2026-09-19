#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Front door for the repeated-detonation measurement.
#
# This exists because its absence had a cost. lamware_eval evaluates LLM arms
# over a frozen report.json and never detonates, so "run this sample N times and
# tell me how much the observation varies" had no code path. Every #518 batch
# was therefore a fresh shell script on the host -- 13 between 2026-09-04 and
# 2026-09-17. They diverged: only the last one pinned the guest, and tasks
# 1132/1133 were discarded for silently running on `office`.
#
# Runs under systemd on the sandbox, not over the ssh session. A 20-run batch is
# hours long and MUST survive a disconnect: an earlier attempt used
# `nohup ... &` inside an ssh command and was killed by a signal partway
# through, leaving a truncated log, an untouched report, and no error anywhere.
#
# THIS DETONATES LIVE MALWARE. It is deliberately a foreground, explicit,
# operator-typed command. It starts a one-shot unit and enables nothing.

set -uo pipefail
# shellcheck source=scripts/lib/remote-oneshot.sh
. "$(dirname "$0")/lib/remote-oneshot.sh"

HOST=${SANDBOX_HOST:-sandbox}
SAMPLE=${SAMPLE:-}
RUNS=${RUNS:-20}
MACHINE=${MACHINE:-clean}
PACKAGE=${PACKAGE:-exe}
UNIT=lamware-detonate
REMOTE_LOG=/opt/pipeline/detonate-logs/${UNIT}.log

if [ -z "$SAMPLE" ]; then
  cat >&2 <<'USAGE'
usage: make detonate SAMPLE=<path-on-sandbox> [RUNS=20] [MACHINE=clean] [PACKAGE=exe]

  e.g. make detonate SAMPLE=/opt/pipeline/post-rebuild-samples/quasarrat_1f2b2263/quasarrat.exe RUNS=20

Prints a tier-stratified scorecard. The pooled mean is reported ONLY alongside
the strata, and labelled not-a-measurement whenever more than one tier appears --
mixing tiers is what produced the #518 "noise floor".
USAGE
  exit 2
fi

say() { printf '==> %s\n' "$*"; }

# Refuse to start a second batch on top of a running one. Two analyses in flight
# lets CAPE use the office machine concurrently and invalidates BOTH (batch.I2).
if remote_unit_busy "$HOST" "$UNIT"; then
  echo "ERROR: ${UNIT}.service is $(remote_unit_state "$HOST" "$UNIT") -- a batch is already running." >&2
  echo "       Two tasks in flight would let CAPE use both guests concurrently." >&2
  echo "       Follow it with:  ssh $HOST 'sudo tail -f $REMOTE_LOG'" >&2
  exit 1
fi

say "sample=$SAMPLE runs=$RUNS machine=$MACHINE (pinned)"
say "THIS DETONATES LIVE MALWARE on $HOST."

ssh "$HOST" "sudo test -r '$SAMPLE'" || { echo "ERROR: sample not readable on $HOST: $SAMPLE" >&2; exit 1; }

# TimeoutStartSec=infinity, not a number. Type=oneshot sits in `activating` for
# its entire run, and a 20-run batch outlives any default.
ssh "$HOST" "sudo mkdir -p /opt/pipeline/detonate-logs && sudo chown pipeline:lamware /opt/pipeline/detonate-logs && sudo tee /etc/systemd/system/${UNIT}.service >/dev/null" <<EOF
[Unit]
Description=lamware repeated-detonation batch (one-shot, operator-started)
After=network-online.target cape.service
Wants=network-online.target

[Service]
Type=oneshot
User=pipeline
Group=pipeline
SupplementaryGroups=lamware
WorkingDirectory=/opt/pipeline
Environment=HOME=/home/pipeline
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/opt/pipeline/pipeline.env
ExecStart=/bin/bash -c '/opt/pipeline/venv/bin/python -m lamware_detonate run --sample "$SAMPLE" --runs $RUNS --machine $MACHINE --package $PACKAGE > $REMOTE_LOG 2>&1'
TimeoutStartSec=infinity
EOF

ssh "$HOST" "sudo systemctl daemon-reload && sudo systemctl start --no-block ${UNIT}.service" || exit 1
say "started; following $REMOTE_LOG (Ctrl-C detaches, the batch keeps running)"
echo

# Follow until the unit leaves the running states. See remote-oneshot.sh for why
# `systemctl is-active --quiet` cannot be used on a Type=oneshot unit.
remote_unit_follow "$HOST" "$UNIT" "$REMOTE_LOG"
