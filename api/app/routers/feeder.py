# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Auto-feeder control endpoints.
#
# The auto-feeder is a separate process that watches a directory and submits
# new samples to the pipeline. It reads two control signals:
#
#   PAUSE file  — if this file exists, the feeder skips submission.
#   state.json  — JSON file tracking consecutive_failures, total_samples_fed,
#                 llm_cost_usd, last_submitted, etc.
#
# These endpoints let the API control the feeder without needing a separate
# management socket. The feeder itself polls the PAUSE file on each iteration.
#
# All file I/O is wrapped in try/except. A missing state.json returns a
# "feeder_not_running" status rather than a 500.

import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

log = logging.getLogger(__name__)

from ..auth import AuthContext, require_auth, require_role
from ..audit import log_audit
from ..config import settings
from ..database import get_session

router = APIRouter(prefix="/api/feeder", tags=["feeder"])


@router.get("/status")
async def feeder_status(
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """
    Return the auto-feeder's current state.

    Reads state.json and checks for the PAUSE file. Returns a status field
    of 'paused', 'running', or 'unknown' (state.json missing/unreadable).
    """
    state = _read_state()
    paused = os.path.exists(settings.pause_file)

    if state is None:
        status = "unknown"
    elif paused:
        status = "paused"
    else:
        status = "running"

    return {
        "status": status,
        "paused": paused,
        "state": state,
        "as_of": datetime.now(tz=timezone.utc).isoformat(),
    }


@router.post("/pause")
async def feeder_pause(
    auth: AuthContext = Depends(require_role("analyst")),
    session: Session = Depends(get_session),
) -> dict:
    """
    Pause the auto-feeder by creating the PAUSE file.

    The feeder checks for this file at the start of each submission loop
    iteration and skips processing while it exists.
    """
    try:
        # touch — open for writing without truncating (creates if absent)
        with open(settings.pause_file, "a"):
            os.utime(settings.pause_file, None)
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not create PAUSE file: {exc}",
        ) from exc

    log_audit(session, auth, action="feeder_pause", resource_type="feeder")

    return {"status": "paused", "pause_file": settings.pause_file}


@router.post("/resume")
async def feeder_resume(
    auth: AuthContext = Depends(require_role("analyst")),
    session: Session = Depends(get_session),
) -> dict:
    """
    Resume the auto-feeder: remove the PAUSE file and reset consecutive
    failures to 0 in state.json.

    Resetting failures prevents a backoff lockout from blocking resumption
    after a deliberate pause.
    """
    # Remove PAUSE file — ignore if it doesn't exist
    try:
        os.remove(settings.pause_file)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not remove PAUSE file: {exc}",
        ) from exc

    # Reset consecutive_failures in state.json so the feeder doesn't stay in
    # backoff mode after resuming from a deliberate pause.
    if not _update_state({"consecutive_failures": 0}):
        log.warning("Resume succeeded (PAUSE removed) but failed to reset failure counter")

    log_audit(session, auth, action="feeder_resume", resource_type="feeder")

    return {"status": "running"}


@router.post("/reset")
async def feeder_reset(
    auth: AuthContext = Depends(require_role("analyst")),
    session: Session = Depends(get_session),
) -> dict:
    """
    Reset the consecutive failure counter in state.json.

    Useful when the feeder has hit the failure threshold and entered backoff
    without the operator wanting to fully pause/resume. Does not touch the
    PAUSE file.
    """
    if not _update_state({"consecutive_failures": 0}):
        raise HTTPException(
            status_code=500,
            detail="Failed to update state.json — check file permissions",
        )

    log_audit(session, auth, action="feeder_reset", resource_type="feeder")

    return {"status": "ok", "consecutive_failures": 0}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_state() -> dict | None:
    """Read state.json. Returns None if missing or malformed."""
    try:
        with open(settings.auto_feeder_state) as f:
            return json.load(f)
    except Exception:
        return None


def _update_state(updates: dict) -> bool:
    """
    Merge updates into state.json.

    Reads the existing state, applies updates, writes back atomically via a
    temp file rename. Returns True on success, False on failure.
    """
    state_path = settings.auto_feeder_state
    tmp_path = state_path + ".tmp"

    try:
        try:
            with open(state_path) as f:
                state = json.load(f)
        except Exception:
            state = {}

        state.update(updates)

        with open(tmp_path, "w") as f:
            json.dump(state, f, indent=2, default=str)

        os.replace(tmp_path, state_path)
        return True
    except Exception as exc:
        log.error("Failed to update state.json: %s", exc)
        return False
