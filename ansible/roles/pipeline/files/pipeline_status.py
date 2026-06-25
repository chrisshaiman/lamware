"""
Pipeline status tracking — real-time stage progress in PostgreSQL.

Creates the analysis row at pipeline START so the dashboard can show
progress for running analyses. Each stage start/complete is logged
as an event for timing and debugging.

Author: Christopher Shaiman
License: Apache 2.0
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from lamware_pipeline.config import PipelineConfig


# -------------------------------------------------------------------------
# Configuration (injected by Ansible template)
# -------------------------------------------------------------------------

_CFG = PipelineConfig.load(
    os.environ.get("LAMWARE_PIPELINE_CONFIG", "/opt/pipeline/config.json")
)
DB_HOST = _CFG.db_host
DB_PORT = _CFG.db_port
DB_NAME = _CFG.db_name
DB_USER = _CFG.db_user
DB_PASSWORD = os.environ.get("PIPELINE_DB_PASSWORD", "")


def _get_conn():
    """Get a database connection. Returns None if unavailable."""
    if not DB_PASSWORD:
        return None
    try:
        import psycopg2
        return psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD,
        )
    except Exception:
        return None


def create_analysis_row(task_id: str, sample_path: str,
                        filename: str = "") -> int | None:
    """Create analysis + sample rows at pipeline START.

    Computes SHA256 from the sample file and upserts the sample row.
    Creates a minimal analysis row with pipeline_status='running'.
    Returns analysis_id, or None if DB is unavailable.
    """
    conn = _get_conn()
    if not conn:
        return None

    try:
        # Compute SHA256 from the actual sample file
        sha256 = hashlib.sha256(Path(sample_path).read_bytes()).hexdigest()

        cur = conn.cursor()

        # Upsert sample
        cur.execute("""
            INSERT INTO samples (sha256, filename)
            VALUES (%s, %s)
            ON CONFLICT (sha256) DO UPDATE SET
                last_seen = NOW(),
                filename = COALESCE(EXCLUDED.filename, samples.filename)
            RETURNING id
        """, (sha256, filename or Path(sample_path).name))
        sample_id = cur.fetchone()[0]

        # Create analysis row
        cur.execute("""
            INSERT INTO analyses (sample_id, task_id, started_at,
                                  pipeline_status, current_stage)
            VALUES (%s, %s, NOW(), 'running', 'initializing')
            RETURNING id
        """, (sample_id, task_id))
        analysis_id = cur.fetchone()[0]

        conn.commit()
        cur.close()
        conn.close()
        return analysis_id

    except Exception as e:
        print(f"  [!] Failed to create early analysis row: {e}")
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        return None


def update_stage(analysis_id: int | None, stage: str, status: str,
                 detail: str = "") -> None:
    """Log a stage event and update the analysis row.

    Fast: single INSERT + UPDATE, autocommit, connection opened and closed.
    """
    if not analysis_id:
        return

    conn = _get_conn()
    if not conn:
        return

    try:
        conn.autocommit = True
        cur = conn.cursor()

        # Log the event
        cur.execute("""
            INSERT INTO pipeline_stage_events
                (analysis_id, stage, status, detail)
            VALUES (%s, %s, %s, %s)
        """, (analysis_id, stage, status, detail[:500] if detail else ""))

        # Update denormalized columns on analyses
        if status == "started":
            cur.execute("""
                UPDATE analyses
                SET current_stage = %s, pipeline_status = 'running'
                WHERE id = %s
            """, (stage, analysis_id))
        elif status in ("completed", "failed"):
            cur.execute("""
                UPDATE analyses SET current_stage = %s WHERE id = %s
            """, (stage, analysis_id))

        # Notify WebSocket listeners
        cur.execute(
            "NOTIFY pipeline_events, %s",
            [json.dumps({
                "event": "stage_update",
                "analysis_id": analysis_id,
                "stage": stage,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })]
        )

        cur.close()
        conn.close()

    except Exception:
        # Status tracking must never crash the pipeline
        try:
            conn.close()
        except Exception:
            pass


def complete_pipeline(analysis_id: int | None, status: str = "completed",
                      stage_timings: dict | None = None) -> None:
    """Mark the pipeline as complete/failed."""
    if not analysis_id:
        return

    conn = _get_conn()
    if not conn:
        return

    try:
        conn.autocommit = True
        cur = conn.cursor()

        import psycopg2.extras
        cur.execute("""
            UPDATE analyses
            SET pipeline_status = %s,
                current_stage = NULL,
                completed_at = NOW(),
                stage_timings = %s
            WHERE id = %s
        """, (status, psycopg2.extras.Json(stage_timings or {}), analysis_id))

        # Notify WebSocket listeners
        event = "analysis_complete" if status == "completed" else "analysis_failed"
        cur.execute(
            "NOTIFY pipeline_events, %s",
            [json.dumps({
                "event": event,
                "analysis_id": analysis_id,
                "stage_timings": stage_timings or {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })]
        )

        cur.close()
        conn.close()

    except Exception:
        try:
            conn.close()
        except Exception:
            pass
