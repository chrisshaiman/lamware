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
# Root-owned code (scripts/intake.sh installs it); never run from the batch dir.
LIB=${INTAKE_LIB:-/usr/local/lib/lamware/intake}
DL="$B/dl"
LOG="$B/intake.log"
STATUS="$B/status.tsv"
say() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

entries=$(python3 -c 'import json,sys
for e in json.load(open(sys.argv[1])):
    print(e["sha256"], e["signature"], sep="\t")' "$B/manifest.json") || { say "bad manifest"; exit 2; }

# The batch's LLM profile (ADR-036), written by intake.sh. Empty or absent means the
# deployment's default (ADR-038): no --llm-profile is passed, and run-pipeline uses it.
PROFILE=$(head -1 "$B/llm_profile" 2>/dev/null)
case "$PROFILE" in *[!a-z0-9-]*) say "bad llm_profile '$PROFILE'"; exit 2 ;; esac
PROFILE_ARGS=()
[ -n "$PROFILE" ] && PROFILE_ARGS=(--llm-profile "$PROFILE")

say "batch start: $(printf '%s\n' "$entries" | wc -l) samples, llm_profile=${PROFILE:-(deployment default)}"
while IFS=$'\t' read -r sha sig; do
    [ -n "$sha" ] || continue
    case "$sha" in *[!0-9a-f]*) say "skip: not a sha256: $sha"; continue ;; esac
    [ ${#sha} -eq 64 ] || { say "skip: not a sha256: $sha"; continue; }
    if grep -q "^$sha" "$STATUS" 2>/dev/null; then say "skip $sha (already in status)"; continue; fi
    if [ -e "$PAUSE" ]; then say "PAUSE file present -- stopping"; break; fi
    d="$DL/$sha"
    out=$(sudo -u auto-feeder "$PY" "$LIB/intake_download.py" "$sha" "$d" 2>>"$LOG") \
        || { say "download FAILED $sha ($sig)"; printf '%s\t%s\tdownload_failed\t-\n' "$sha" "$sig" >> "$STATUS"; continue; }
    path=${out%%$'\t'*}; name=${out#*$'\t'}
    say "pipeline start $sha ($sig) $name"
    before=$(ls -1t "$REPORTS" 2>/dev/null | head -1)
    sudo -u pipeline timeout 5400 "$RUN_PIPELINE" "$path" --filename "$name" --bazaar-family "$sig" \
        "${PROFILE_ARGS[@]}" >> "$LOG" 2>&1
    rc=$?
    after=$(ls -1t "$REPORTS" 2>/dev/null | head -1)
    [ "$after" = "$before" ] && after="-"
    printf '%s\t%s\trc=%s\t%s\n' "$sha" "$sig" "$rc" "$after" >> "$STATUS"
    say "pipeline done $sha rc=$rc report=$after"
    # The staged copy is not needed after the run: CAPE keeps its own in storage.
    # As auto-feeder, which owns it: root does not delete inside another account's dir.
    sudo -u auto-feeder rm -rf --one-file-system "$d"
done <<< "$entries"
say "batch end"
