# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""One-time backfill of cross-sample relationship edges over the existing corpus.

Run by the operator after deploy:
    set -a; . /opt/pipeline/pipeline.env; set +a
    /opt/pipeline/venv/bin/python /opt/pipeline/backfill_relationships.py

Going forward, db_ingest writes edges incrementally per analysis. This script is
a thin entrypoint; the logic lives in lamware_pipeline.relationships.backfill_all.
"""
import os
import sys

from lamware_pipeline.config import PipelineConfig
from lamware_pipeline.relationships import backfill_all


def main() -> int:
    cfg = PipelineConfig.load(
        os.environ.get("LAMWARE_PIPELINE_CONFIG", "/opt/pipeline/config.json")
    )
    password = os.environ.get("PIPELINE_DB_PASSWORD", "")
    if not password:
        print("[!] PIPELINE_DB_PASSWORD not set — source /opt/pipeline/pipeline.env first")
        return 1

    import psycopg2
    conn = psycopg2.connect(
        host=cfg.db_host, port=cfg.db_port, dbname=cfg.db_name,
        user=cfg.db_user, password=password,
    )
    try:
        total = backfill_all(conn, cfg)
        print(f"Backfill complete: {total} new edge(s) written.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
