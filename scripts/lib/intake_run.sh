#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Host side of `make intake`: detonate each sample of a batch manifest through the
# SAME path the auto-feeder uses -- download as auto-feeder, then
# `sudo -u pipeline run-pipeline <sample> --filename --bazaar-family` -- one at a
# time. The pipeline pins the guest itself (derive_machine -> cape_machine=clean
# for executables, then verify_ran_on). Installed and started by scripts/intake.sh
# as a one-shot unit so it survives a dropped ssh session.
#
#   intake_run.sh <batch_dir>      (batch_dir holds manifest.json)
set -u
B=${1:?batch dir}
# Overridable for tests only.
RUN_PIPELINE=${INTAKE_RUN_PIPELINE:-/usr/local/bin/run-pipeline}
REPORTS=${INTAKE_REPORTS_DIR:-/opt/pipeline/reports}
PAUSE=${INTAKE_PAUSE_FILE:-/opt/pipeline/control/PAUSE}
PY=${INTAKE_PYTHON:-/usr/bin/python3}
LOG="$B/intake.log"
STATUS="$B/status.tsv"
say() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

entries=$(python3 -c 'import json,sys
for e in json.load(open(sys.argv[1])):
    print(e["sha256"], e["signature"], sep="\t")' "$B/manifest.json") || { say "bad manifest"; exit 2; }

say "batch start: $(printf '%s\n' "$entries" | wc -l) samples"
while IFS=$'\t' read -r sha sig; do
    [ -n "$sha" ] || continue
    if grep -q "^$sha" "$STATUS" 2>/dev/null; then say "skip $sha (already in status)"; continue; fi
    if [ -e "$PAUSE" ]; then say "PAUSE file present -- stopping"; break; fi
    d="$B/$sha"
    out=$(sudo -u auto-feeder "$PY" "$B/intake_download.py" "$sha" "$d" 2>>"$LOG") \
        || { say "download FAILED $sha ($sig)"; printf '%s\t%s\tdownload_failed\t-\n' "$sha" "$sig" >> "$STATUS"; continue; }
    path=${out%%$'\t'*}; name=${out#*$'\t'}
    say "pipeline start $sha ($sig) $name"
    before=$(ls -1t "$REPORTS" 2>/dev/null | head -1)
    sudo -u pipeline timeout 5400 "$RUN_PIPELINE" "$path" --filename "$name" --bazaar-family "$sig" >> "$LOG" 2>&1
    rc=$?
    after=$(ls -1t "$REPORTS" 2>/dev/null | head -1)
    [ "$after" = "$before" ] && after="-"
    printf '%s\t%s\trc=%s\t%s\n' "$sha" "$sig" "$rc" "$after" >> "$STATUS"
    say "pipeline done $sha rc=$rc report=$after"
    # The staged copy is not needed after the run: CAPE keeps its own in storage.
    rm -rf --one-file-system "$d"
done <<< "$entries"
say "batch end"
