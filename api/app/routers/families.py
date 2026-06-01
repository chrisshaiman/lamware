# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Malware family browser endpoint.
#
# malware_family_guess is a free-text column on the analyses table, populated
# by the AI interpretation stage. This endpoint groups analyses by that value
# and counts occurrences so analysts can see which families have been observed
# and how frequently. Null and 'unknown' rows are excluded — they carry no
# attribution signal.

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlmodel import Session, select

from ..auth import AuthContext, require_auth
from ..database import get_session
from ..models.analysis import Analysis

router = APIRouter(prefix="/api/families", tags=["families"])


@router.get("")
async def list_families(
    q: str | None = Query(
        default=None, description="Search family name (substring match)"
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> list[dict]:
    """
    List all detected malware families with analysis counts.

    Groups analyses by malware_family_guess (set by the AI interpretation
    stage). Excludes rows where the field is NULL or the literal string
    'unknown'. Returns count and last_seen timestamp per family, ordered
    by count descending.
    """
    count_col = func.count(Analysis.id).label("count")
    last_seen_col = func.max(Analysis.completed_at).label("last_seen")

    stmt = (
        select(
            Analysis.malware_family_guess.label("family"),
            count_col,
            last_seen_col,
        )
        # Exclude rows with no attribution signal
        .where(Analysis.malware_family_guess.is_not(None))
        .where(Analysis.malware_family_guess != "unknown")
        .group_by(Analysis.malware_family_guess)
        .order_by(count_col.desc())
        .offset(offset)
        .limit(limit)
    )

    if q:
        stmt = stmt.where(Analysis.malware_family_guess.ilike(f"%{q}%"))

    rows = session.exec(stmt).all()

    return [
        {
            "family": row.family,
            "count": row.count,
            "last_seen": row.last_seen,
        }
        for row in rows
    ]
