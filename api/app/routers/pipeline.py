# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Pipeline status endpoint — running and recent analyses with stage info.
#
# Queries analyses with pipeline_status in ('running', 'pending') and those
# completed within the last 24 hours. Returns stage_timings and current_stage
# so the frontend can render a live progress view.

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ..auth import AuthContext, require_auth
from ..database import get_session
from ..models.analysis import Analysis
from ..models.sample import Sample

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])

# Statuses considered "active" — always returned regardless of age.
ACTIVE_STATUSES = {"running", "pending"}

# How far back to look for recently completed analyses.
RECENT_WINDOW_HOURS = 24


@router.get("/status")
async def pipeline_status(
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Return running/pending analyses and those completed in the last 24 hours.

    Each entry includes stage_timings (per-stage elapsed seconds) and
    current_stage so clients can render a progress indicator.
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=RECENT_WINDOW_HOURS)

    # Fetch active and recently completed analyses together.
    # The OR predicate is expressed via SQLAlchemy's | operator on column
    # expressions. Result set is small (pipeline throughput is low), so no
    # subquery optimisation needed.
    stmt = (
        select(Analysis, Sample)
        .join(Sample, Sample.id == Analysis.sample_id)  # type: ignore[arg-type]
        .where(
            (Analysis.pipeline_status.in_(list(ACTIVE_STATUSES)))  # type: ignore[union-attr]
            | (
                (Analysis.pipeline_status == "completed")
                & (Analysis.completed_at >= cutoff)
            )
        )
        .order_by(Analysis.started_at.desc())  # type: ignore[union-attr]
    )

    rows = session.exec(stmt).all()

    running = []
    recent = []

    for analysis, sample in rows:
        entry = _format_entry(analysis, sample)
        if analysis.pipeline_status in ACTIVE_STATUSES:
            running.append(entry)
        else:
            recent.append(entry)

    return {
        "running": running,
        "recent_completed": recent,
        "as_of": datetime.now(tz=timezone.utc).isoformat(),
    }


def _format_entry(analysis: Analysis, sample: Sample) -> dict:
    """Serialize one analysis row for the pipeline status response."""
    return {
        "id": analysis.id,
        "task_id": analysis.task_id,
        "pipeline_status": analysis.pipeline_status,
        "current_stage": analysis.current_stage,
        "stage_timings": analysis.stage_timings or {},
        "started_at": analysis.started_at.isoformat() if analysis.started_at else None,
        "completed_at": (
            analysis.completed_at.isoformat() if analysis.completed_at else None
        ),
        "severity": analysis.severity,
        "malscore": analysis.malscore,
        "malware_family_guess": analysis.malware_family_guess,
        "sample": {
            "sha256": sample.sha256,
            "filename": sample.filename,
            "file_type": sample.file_type,
        },
    }
