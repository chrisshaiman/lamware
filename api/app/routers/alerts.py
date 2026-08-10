# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Operational health / alerts endpoint.
#
# Aggregates health signals from several sources:
#   - Network monitor status.json  (air-gap, QEMU, watched processes)
#   - Auto-feeder state.json       (consecutive failures, cost, sample counts)
#   - PAUSE file                   (pipeline paused?)
#   - Disk usage (shutil)          (root filesystem)
#   - Latest ntfy digest           (last alert digest timestamp)
#   - DB cost query                (today's LLM spend)
#
# All file reads are wrapped in try/except so a missing or malformed file
# degrades gracefully — the key is still present in the response, just null.
#
# The cost query uses raw SQL via text() because SQLModel doesn't handle
# PostgreSQL interval literals well (e.g. NOW() - INTERVAL '1 day').

import json
import os
import shutil
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlmodel import Session

from ..auth import AuthContext, require_auth
from ..config import settings
from ..database import get_session

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
async def get_alerts(
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Return operational health status for the sandbox platform.

    Combines file-based status signals with a DB cost query. All file reads
    are fault-tolerant — a missing file returns null rather than 500.
    """
    return {
        "network_monitor": _read_network_monitor(),
        "auto_feeder": _read_auto_feeder(),
        "paused": _check_pause_file(),
        "disk": _read_disk_usage(),
        "latest_digest": _read_latest_digest(),
        "cost_today_usd": _query_cost_today(session),
        "as_of": datetime.now(tz=UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# File readers — each returns a dict or None on failure
# ---------------------------------------------------------------------------


def _read_network_monitor() -> dict | None:
    """Read /opt/network-monitor/status.json."""
    try:
        with open(settings.network_monitor_status) as f:
            return json.load(f)
    except Exception:
        return None


def _read_auto_feeder() -> dict | None:
    """Read /opt/auto-feeder/state.json."""
    try:
        with open(settings.auto_feeder_state) as f:
            return json.load(f)
    except Exception:
        return None


def _check_pause_file() -> bool:
    """Return True if the PAUSE file exists (pipeline is paused)."""
    try:
        return os.path.exists(settings.pause_file)
    except Exception:
        return False


def _read_disk_usage() -> dict | None:
    """
    Return disk usage for the root filesystem.

    shutil.disk_usage returns (total, used, free) in bytes. We convert to GB
    and compute a used_pct so the frontend can show a simple gauge.
    """
    try:
        usage = shutil.disk_usage("/")
        total_gb = usage.total / (1024 ** 3)
        used_gb = usage.used / (1024 ** 3)
        free_gb = usage.free / (1024 ** 3)
        return {
            "total_gb": round(total_gb, 1),
            "used_gb": round(used_gb, 1),
            "free_gb": round(free_gb, 1),
            "used_pct": round(usage.used / usage.total * 100, 1),
        }
    except Exception:
        return None


def _read_latest_digest() -> dict | None:
    """Read /opt/ntfy-alerts/latest-digest.json, stamped with its own age.

    The file is only rewritten on a day that produced analyses — "no analyses
    today" correctly declines to overwrite it. That is sensible behaviour and
    it left the endpoint unable to tell a digest written this morning from one
    written six days ago: on 2026-08-09 it was serving `generated_at` of
    2026-08-03 with nothing to say so (#351).

    Age is computed here rather than in the frontend so every consumer gets it,
    and so "how stale" is answered by the thing that read the file.
    """
    try:
        with open(settings.digest_file) as f:
            digest = json.load(f)
    except Exception:
        return None

    generated = digest.get("generated_at")
    if generated:
        try:
            when = datetime.fromisoformat(generated)
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            age_h = (datetime.now(UTC) - when).total_seconds() / 3600
            digest["age_hours"] = round(age_h, 1)
            # A digest older than ~36h means yesterday's run also produced
            # nothing, or the cron is not running at all. Those look identical
            # from here, which is why this reports the fact rather than a cause.
            digest["stale"] = age_h > 36
        except (TypeError, ValueError):
            digest["age_hours"] = None
            digest["stale"] = None
    else:
        digest["age_hours"] = None
        digest["stale"] = None
    return digest


# ---------------------------------------------------------------------------
# DB query — cost today
# ---------------------------------------------------------------------------


def _query_cost_today(session: Session) -> float | None:
    """
    Sum llm_cost_usd for analyses started in the last 24 hours.

    Uses raw SQL with text() because SQLModel's ORM layer doesn't handle
    PostgreSQL INTERVAL literals (INTERVAL '1 day') cleanly via select().
    The result is a single Decimal or None; we cast to float for JSON.
    """
    sql = text(
        """
        SELECT COALESCE(SUM(llm_cost_usd), 0)
        FROM   analyses
        WHERE  started_at >= NOW() - INTERVAL '1 day'
          AND  llm_cost_usd IS NOT NULL
        """
    )
    try:
        result = session.exec(sql).scalar()  # type: ignore[call-overload]
        return float(result) if result is not None else 0.0
    except Exception:
        return None
