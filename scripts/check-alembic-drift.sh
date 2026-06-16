#!/usr/bin/env bash
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Run the Alembic drift sentinel on the host against a throwaway scratch DB
# (PostgreSQL 16, prod match). Tears the scratch DB down on exit.
#
# IMPORTANT: this host mounts /tmp noexec/restricted (CIS hardening baseline), so a
# venv cannot be built/run there. The recon dir therefore lives under /opt — the
# same exec-allowed location as the deployed migration runner (/opt/lamware-migrations).
# All work runs as the postgres user, which owns the /opt recon dir and provides
# peer-auth DDL for DROP/CREATE SCHEMA + `alembic upgrade head`.
#
# Usage: copy a synced api/ tree to the host, then:
#   scripts/check-alembic-drift.sh /path/to/synced/api
set -euo pipefail

SRC="${1:?usage: check-alembic-drift.sh <path-to-synced-api-dir>}"
SCRATCH="alembic_drift_check"
RECON="/opt/alembic-drift-recon"

cleanup() { sudo -u postgres dropdb --if-exists "${SCRATCH}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] Staging recon copy of api/ at ${RECON} (postgres-owned; /opt is exec-allowed)"
sudo rm -rf "${RECON}"
sudo mkdir -p "${RECON}"
sudo cp -a "${SRC}/." "${RECON}/"
sudo chown -R postgres:postgres "${RECON}"

echo "[*] Building recon venv (alembic + sqlmodel + psycopg2 + pytest)"
# Plain venv (symlinks) — matches the proven /opt/lamware-migrations runner recipe
# on this host; --copies produced a venv without a working pip.
sudo -u postgres python3 -m venv "${RECON}/.venv"
sudo -u postgres "${RECON}/.venv/bin/pip" -q install \
    "alembic>=1.13" "sqlmodel>=0.0.22" "psycopg2-binary>=2.9" pytest

echo "[*] Recreating scratch DB ${SCRATCH}"
sudo -u postgres dropdb --if-exists "${SCRATCH}"
sudo -u postgres createdb "${SCRATCH}"

echo "[*] Running drift test (peer auth as postgres)"
URL="postgresql+psycopg2:///${SCRATCH}"
sudo -u postgres bash -c "cd '${RECON}' && \
    PYTHONDONTWRITEBYTECODE=1 \
    LAMWARE_MIGRATION_TEST_URL='${URL}' ALEMBIC_DATABASE_URL='${URL}' \
    '${RECON}/.venv/bin/pytest' -p no:cacheprovider tests/test_alembic_drift.py -v"
