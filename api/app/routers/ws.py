# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# WebSocket endpoint for real-time pipeline updates.
#
# Clients connect to /ws/pipeline?api_key=<key> and receive:
# 1. Current pipeline state on connect (same as GET /api/pipeline/status)
# 2. Typed events as stages transition (stage_update, analysis_complete, etc.)
#
# Events arrive via PostgreSQL LISTEN/NOTIFY — the pipeline orchestrator
# issues NOTIFY pipeline_events after each stage write.

import asyncio
import json
import logging

import asyncpg
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select

from ..config import settings
from ..database import engine
from ..models.analysis import Analysis
from ..models.sample import Sample
from ..ws_manager import manager

log = logging.getLogger(__name__)

router = APIRouter()

# Same constants as pipeline.py
ACTIVE_STATUSES = {"running", "pending"}


def _get_current_state(session: Session) -> dict:
    """Query current pipeline state — same as GET /api/pipeline/status."""
    from datetime import datetime, timedelta, timezone

    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    stmt = (
        select(Analysis, Sample)
        .join(Sample, Sample.id == Analysis.sample_id)
        .where(
            (Analysis.pipeline_status.in_(list(ACTIVE_STATUSES)))
            | (
                (Analysis.pipeline_status == "completed")
                & (Analysis.completed_at >= cutoff)
            )
        )
        .order_by(Analysis.started_at.desc())
    )
    rows = session.exec(stmt).all()

    running = []
    recent = []
    for analysis, sample in rows:
        entry = {
            "id": analysis.id,
            "task_id": analysis.task_id,
            "pipeline_status": analysis.pipeline_status,
            "current_stage": analysis.current_stage,
            "stage_timings": analysis.stage_timings or {},
            "started_at": analysis.started_at.isoformat() if analysis.started_at else None,
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
            "severity": analysis.severity,
            "malscore": analysis.malscore,
            "malware_family_guess": analysis.malware_family_guess,
            "sample": {
                "sha256": sample.sha256,
                "filename": sample.filename,
                "file_type": sample.file_type,
            },
        }
        if analysis.pipeline_status in ACTIVE_STATUSES:
            running.append(entry)
        else:
            recent.append(entry)

    return {
        "running": running,
        "recent_completed": recent,
        "as_of": datetime.now(tz=timezone.utc).isoformat(),
    }


@router.websocket("/ws/pipeline")
async def websocket_pipeline(
    websocket: WebSocket,
    api_key: str = Query(default=""),
):
    """WebSocket endpoint for real-time pipeline status updates."""
    # Auth — same logic as REST: empty settings.api_key = dev mode (allow all)
    if settings.api_key and api_key != settings.api_key:
        await websocket.close(code=1008, reason="Invalid API key")
        return

    await manager.connect(websocket)

    try:
        # Send current state on connect
        try:
            with Session(engine) as session:
                state = _get_current_state(session)
        except Exception:
            state = {"running": [], "recent_completed": [], "as_of": ""}
        await websocket.send_json(state)

        # Keep connection alive — wait for client disconnect
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)


# -------------------------------------------------------------------------
# PostgreSQL LISTEN background task — started once on app startup
# -------------------------------------------------------------------------

async def _pg_listener() -> None:
    """Listen on the pipeline_events PG channel and broadcast to WebSocket clients."""
    dsn = (
        f"postgresql://{settings.db_user}:{settings.db_password}"
        f"@{settings.db_host}:{settings.db_port}/{settings.db_name}"
    )

    while True:
        try:
            conn = await asyncpg.connect(dsn)
            log.info("PG LISTEN connected — broadcasting pipeline events")

            await conn.add_listener("pipeline_events", _on_notification)

            # Keep connection alive until it drops
            while True:
                await asyncio.sleep(60)
                await conn.execute("SELECT 1")

        except asyncio.CancelledError:
            log.info("PG LISTEN task cancelled — shutting down")
            try:
                await conn.close()
            except Exception:
                pass
            return

        except Exception as e:
            log.warning("PG LISTEN connection lost (%s), reconnecting in 5s", e)
            await asyncio.sleep(5)


def _on_notification(conn, pid, channel, payload):
    """Callback for PG NOTIFY — runs in asyncpg's event loop."""
    try:
        message = json.loads(payload)
        asyncio.create_task(manager.broadcast(message))
    except json.JSONDecodeError:
        log.warning("Invalid JSON in PG NOTIFY payload: %s", payload[:200])


_listener_task: asyncio.Task | None = None


async def start_pg_listener() -> None:
    """Start the PG LISTEN background task. Call from app startup."""
    global _listener_task
    if not settings.db_password:
        log.warning("No DB password configured — PG LISTEN disabled")
        return
    _listener_task = asyncio.create_task(_pg_listener())


async def stop_pg_listener() -> None:
    """Cancel the PG LISTEN background task. Call from app shutdown."""
    global _listener_task
    if _listener_task:
        _listener_task.cancel()
        try:
            await _listener_task
        except asyncio.CancelledError:
            pass
