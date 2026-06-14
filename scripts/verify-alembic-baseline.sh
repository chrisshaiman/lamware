#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Proves the Alembic 0001 baseline reproduces the live malware_analysis schema.
# Builds a scratch DB from `alembic upgrade head`, dumps both schemas, and diffs.
# Run ON THE HOST as a user that can `sudo -u postgres`.
#
# Usage: scripts/verify-alembic-baseline.sh [prod_db_name]
set -euo pipefail

DB_PROD="${1:-malware_analysis}"
DB_SCRATCH="alembic_baseline_check"
RUNNER="/opt/lamware-migrations"

cleanup() { sudo -u postgres dropdb --if-exists "${DB_SCRATCH}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] Recreating scratch DB ${DB_SCRATCH}"
sudo -u postgres dropdb --if-exists "${DB_SCRATCH}"
sudo -u postgres createdb "${DB_SCRATCH}"

echo "[*] Building scratch DB from alembic head"
# Run from /tmp: Alembic 1.16+ probes ./pyproject.toml from the CWD, and the
# postgres user cannot traverse the invoking user's home dir (-> PermissionError).
# /tmp is readable by postgres and has no pyproject.toml, so discovery no-ops.
( cd /tmp && sudo -u postgres env ALEMBIC_DATABASE_URL="postgresql+psycopg2:///${DB_SCRATCH}" \
    "${RUNNER}/venv/bin/alembic" -c "${RUNNER}/alembic.ini" upgrade head )

echo "[*] Dumping schemas (comments/blank lines stripped, lines sorted)"
sudo -u postgres pg_dump --schema-only --no-owner --no-privileges "${DB_PROD}" \
    | grep -vE '^--|^$' | grep -v 'alembic_version' | sort > /tmp/prod_schema.txt
sudo -u postgres pg_dump --schema-only --no-owner --no-privileges "${DB_SCRATCH}" \
    | grep -vE '^--|^$' | grep -v 'alembic_version' | sort > /tmp/scratch_schema.txt

echo "[*] Diffing"
if diff -u /tmp/prod_schema.txt /tmp/scratch_schema.txt; then
    echo "[OK] Baseline reproduces the prod schema."
else
    echo "[FAIL] Schemas differ — investigate before trusting 0001." >&2
    exit 1
fi
