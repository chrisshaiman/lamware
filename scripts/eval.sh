#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Front door for the LLM-arm evaluation harness (lamware_eval).
#
# The harness has existed and been tested since July. It had no entry point in
# the Makefile, so running it meant remembering the full `python -m` invocation
# and where the corpus manifest lives -- and its last output on the host is
# dated 2026-08-31. A harness nobody can start is a harness nobody uses.
#
# This does NOT detonate anything: lamware_eval reads each sample's frozen
# report.json and re-runs only the interpretation arm against it. For
# measurement of the DETONATION itself see scripts/detonate.sh.

set -uo pipefail
# shellcheck source=scripts/lib/remote-oneshot.sh
. "$(dirname "$0")/lib/remote-oneshot.sh"

HOST=${SANDBOX_HOST:-sandbox}
ARMS=${ARMS:-}
CORPUS=${CORPUS:-/opt/pipeline/eval/corpus.json}
LABEL=${LABEL:-eval}
SAMPLES=${SAMPLES:-}
UNIT=lamware-eval
REMOTE_LOG=/opt/pipeline/eval-logs/${UNIT}.log

if [ -z "$ARMS" ]; then
  cat >&2 <<'USAGE'
usage: make eval ARMS=<csv> [CORPUS=...] [LABEL=...] [SAMPLES=<sha-prefix-or-family,...>]

  e.g. make eval ARMS=qwen@30 LABEL=baseline
       make eval ARMS=qwen@30 SAMPLES=salat        # one sample, for a smoke check

Arms come from lamware_eval.arms._REGISTRY; every arm's model must also be
registered in the LiteLLM config (enforced by test_every_arm_model_has_a_litellm_entry).
USAGE
  exit 2
fi

say() { printf '==> %s\n' "$*"; }

if remote_unit_busy "$HOST" "$UNIT"; then
  echo "ERROR: ${UNIT}.service is $(remote_unit_state "$HOST" "$UNIT") -- an eval is already running." >&2
  echo "       Follow it with:  ssh $HOST 'sudo tail -f $REMOTE_LOG'" >&2
  exit 1
fi

SEL=""
[ -n "$SAMPLES" ] && SEL="--samples $SAMPLES"

say "arms=$ARMS corpus=$CORPUS label=$LABEL ${SAMPLES:+samples=$SAMPLES}"

ssh "$HOST" "sudo test -r '$CORPUS'" || { echo "ERROR: corpus not readable on $HOST: $CORPUS" >&2; exit 1; }

# TimeoutStartSec=infinity: a full-corpus local sweep is many hours, and
# Type=oneshot sits in `activating` for all of it.
ssh "$HOST" "sudo mkdir -p /opt/pipeline/eval-logs && sudo chown pipeline:lamware /opt/pipeline/eval-logs && sudo tee /etc/systemd/system/${UNIT}.service >/dev/null" <<EOF
[Unit]
Description=lamware LLM-arm evaluation sweep (one-shot, operator-started)
After=network-online.target
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
ExecStart=/bin/bash -c '/opt/pipeline/venv/bin/python -m lamware_eval run --corpus "$CORPUS" --arms "$ARMS" --label "$LABEL" $SEL > $REMOTE_LOG 2>&1'
TimeoutStartSec=infinity
EOF

ssh "$HOST" "sudo systemctl daemon-reload && sudo systemctl start --no-block ${UNIT}.service" || exit 1
say "started; following $REMOTE_LOG (Ctrl-C detaches, the sweep keeps running)"
echo
remote_unit_follow "$HOST" "$UNIT" "$REMOTE_LOG"
