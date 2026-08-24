# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# WebSocket endpoint for real-time pipeline updates.
#
# Clients connect to /ws/pipeline and authenticate via first message:
# 1. Current pipeline state on connect (same as GET /api/pipeline/status)
# 2. Typed events as stages transition (stage_update, analysis_complete, etc.)
#
# Events arrive via PostgreSQL LISTEN/NOTIFY — the pipeline orchestrator
# issues NOTIFY pipeline_events after each stage write.

import asyncio
import json
import logging
import time
from datetime import UTC

import asyncpg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select

from ..config import settings
from ..database import build_pg_dsn, engine
from ..models.analysis import Analysis
from ..models.sample import Sample
from ..ws_manager import manager

log = logging.getLogger(__name__)

router = APIRouter()

# Same constants as pipeline.py
ACTIVE_STATUSES = {"running", "pending"}


def _get_current_state(session: Session) -> dict:
    """Query current pipeline state — same as GET /api/pipeline/status."""
    from datetime import datetime, timedelta

    cutoff = datetime.now(tz=UTC) - timedelta(hours=24)
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
        "as_of": datetime.now(tz=UTC).isoformat(),
    }


# Absolute ceiling on a WebSocket session, applied when the token's own `exp` is
# further out (or absent). nginx sets proxy_read_timeout 86400 on /ws/, so without a
# deadline here a session could outlive a ~5-minute Keycloak token by up to 24 hours:
# disabling a user in Keycloak would not disconnect them (#208).
_MAX_WS_SESSION_S = 900.0

# Seconds to close BEFORE the token actually expires, so the client is told to
# reconnect while its token is still valid rather than racing the boundary.
_WS_EXPIRY_MARGIN_S = 10.0


@router.websocket("/ws/pipeline")
async def websocket_pipeline(websocket: WebSocket):
    """
    WebSocket endpoint for real-time pipeline status updates.

    Auth: client sends {"type": "auth", "token": "<jwt>"} as first message
    within 5 seconds.

    The accept()-then-authenticate shape is forced by the protocol: browsers cannot
    set an Authorization header on a WebSocket handshake, so the token has to arrive
    in-band. What follows accept() is therefore the whole of the auth boundary, and
    every rejection path below is logged — REST logged failed auth and this file did
    not, which made credential stuffing on /ws/ invisible (#208).
    """
    await websocket.accept()

    from ..auth import _log_failed_auth, _validate_jwt

    # --- Auth via first message (5s timeout) ---
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        msg = json.loads(raw)
    except (TimeoutError, json.JSONDecodeError):
        _log_failed_auth(websocket, "WS auth timeout or malformed first message")
        await websocket.close(code=4001, reason="Auth timeout or invalid message")
        return
    except WebSocketDisconnect:
        return

    # isinstance first: json.loads happily returns a list, int, str or None for
    # a valid-JSON non-object frame, and only JSONDecodeError is caught above. A
    # first frame of "[]" therefore reached .get() and raised AttributeError,
    # which nothing catches — the handler died and _log_failed_auth never ran,
    # so an unauthenticated caller could crash the connection leaving no record.
    if not isinstance(msg, dict) or msg.get("type") != "auth" or not msg.get("token"):
        _log_failed_auth(websocket, "WS first message was not an auth frame")
        await websocket.close(code=4001, reason="First message must be auth with JWT token")
        return

    # Bind the principal. The result used to be discarded, so the connection carried
    # no identity and nothing on the channel was attributable to a user (#208).
    try:
        auth = await _validate_jwt(msg["token"])
    except Exception as e:
        _log_failed_auth(websocket, f"WS token rejected: {e}")
        await websocket.close(code=4001, reason="Invalid token")
        return

    # Parity with the REST twin. GET /api/pipeline/status is guarded by require_auth,
    # NOT require_role, so authentication alone is the correct bar for the same data
    # over a different transport. Stated explicitly because the asymmetry this issue
    # is about came from nobody writing down what the bar was.
    principal = auth.user_id or auth.email or "unknown"

    # --- Authenticated — join broadcast pool ---
    if not manager.track(websocket, principal=principal):
        # Authentication succeeded; the account is simply holding too many
        # sockets. 1013 "try again later" rather than an auth code, so a client
        # with a leak retries instead of prompting for credentials it already has.
        log.warning("WS connection limit reached for %s", principal)
        await websocket.close(code=1013, reason="Too many concurrent connections")
        return

    deadline = (
        auth.exp - _WS_EXPIRY_MARGIN_S
        if auth.exp is not None
        else time.time() + _MAX_WS_SESSION_S
    )
    deadline = min(deadline, time.time() + _MAX_WS_SESSION_S)

    try:
        # Send current state
        try:
            with Session(engine) as session:
                state = _get_current_state(session)
        except Exception as exc:
            # An empty state is what a genuinely idle platform looks like, so
            # sending one on a failed query told every connecting client "nothing
            # is running" when the truth was "I could not look". Same principle
            # as correlation_warnings and spend.py:_zeroed — the shape stays, the
            # reason rides along.
            log.warning("WS initial state query failed: %s", exc)
            state = {
                "running": [],
                "recent_completed": [],
                "as_of": "",
                "error": "state query failed",
            }
        await websocket.send_json(state)

        # Keep alive until the client disconnects OR the session deadline passes.
        # The timeout is what enforces expiry: an idle socket never returns from
        # receive_text(), so without it the deadline would only be checked on traffic
        # the client controls -- which is exactly the client we are bounding.
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=remaining)
            except TimeoutError:
                break
        log.info("WS session expired for %s — closing to force re-auth", principal)
        await websocket.close(code=4003, reason="Session expired — reauthenticate")
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)


# -------------------------------------------------------------------------
# PostgreSQL LISTEN background task — started once on app startup
# -------------------------------------------------------------------------

async def _pg_listener() -> None:
    """Listen on the pipeline_events PG channel and broadcast to WebSocket clients."""
    dsn = build_pg_dsn()

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


# Strong references to in-flight broadcast tasks.
#
# asyncio.create_task() returns the ONLY strong reference to the task; the event loop
# holds a weak one. Discarding it lets a broadcast be garbage collected mid-flight, so
# notifications drop silently under load — precisely when the drop matters and least
# when it would be noticed. `_listener_task` below already stores its handle, so the
# pattern was understood in this file and just not applied here (#208).
_broadcast_tasks: set[asyncio.Task] = set()


def _on_notification(conn, pid, channel, payload):
    """Callback for PG NOTIFY — runs in asyncpg's event loop."""
    try:
        message = json.loads(payload)
    except json.JSONDecodeError:
        log.warning("Invalid JSON in PG NOTIFY payload: %s", payload[:200])
        return

    task = asyncio.create_task(manager.broadcast(message))
    _broadcast_tasks.add(task)
    task.add_done_callback(_broadcast_tasks.discard)


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
