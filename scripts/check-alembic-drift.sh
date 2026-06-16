#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Run the Alembic drift sentinel on the host against a throwaway scratch DB
# (PostgreSQL 16, prod match). Builds an isolated recon copy of api/ in /tmp as the
# INVOKING user (normal venv creation), then runs only the pytest process as the
# postgres user for peer-auth DDL. Tears the scratch DB down on exit.
#
# Why split users: building a venv as the postgres user in /tmp tripped a symlink
# permission error; creating it as the invoking user is the well-trodden path. The
# recon tree is made world-readable/executable so postgres can read the code +
# run the venv, and the test runs with PYTHONDONTWRITEBYTECODE so postgres needs
# no write access. DDL (DROP/CREATE SCHEMA, upgrade head) needs postgres → peer auth.
#
# Usage: copy a synced api/ tree to the host, then:
#   scripts/check-alembic-drift.sh /path/to/synced/api
set -euo pipefail

SRC="${1:?usage: check-alembic-drift.sh <path-to-synced-api-dir>}"
SCRATCH="alembic_drift_check"
RECON="/tmp/alembic-drift-recon"

cleanup() { sudo -u postgres dropdb --if-exists "${SCRATCH}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] Staging recon copy of api/ at ${RECON} (as $(id -un))"
sudo rm -rf "${RECON}"   # sudo: clears any prior run's postgres-owned remnants
mkdir -p "${RECON}"
cp -a "${SRC}/." "${RECON}/"

echo "[*] Building recon venv (alembic + sqlmodel + psycopg2 + pytest)"
python3 -m venv "${RECON}/.venv"
"${RECON}/.venv/bin/pip" -q install \
    "alembic>=1.13" "sqlmodel>=0.0.22" "psycopg2-binary>=2.9" pytest

echo "[*] Making recon world-readable/executable so postgres can run it"
chmod -R a+rX "${RECON}"

echo "[*] Recreating scratch DB ${SCRATCH}"
sudo -u postgres dropdb --if-exists "${SCRATCH}"
sudo -u postgres createdb "${SCRATCH}"

echo "[*] Running drift test as postgres (peer-auth DDL; no bytecode writes)"
URL="postgresql+psycopg2:///${SCRATCH}"
sudo -u postgres bash -c "cd '${RECON}' && \
    PYTHONDONTWRITEBYTECODE=1 \
    LAMWARE_MIGRATION_TEST_URL='${URL}' ALEMBIC_DATABASE_URL='${URL}' \
    '${RECON}/.venv/bin/pytest' -p no:cacheprovider tests/test_alembic_drift.py -v"
