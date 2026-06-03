# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# ATT&CK technique browser endpoint.
#
# technique_values holds one row per unique MITRE technique (e.g. T1055.003).
# analysis_techniques is the join table linking techniques to analyses.
# This endpoint surfaces frequency across all analyses so analysts can see
# which techniques appear most often in analyzed samples.

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlmodel import Session, select

from ..auth import AuthContext, require_auth
from ..database import get_session
from ..models.technique import AnalysisTechnique, TechniqueValue

router = APIRouter(prefix="/api/techniques", tags=["techniques"])


@router.get("")
async def list_techniques(
    q: str | None = Query(
        default=None,
        description="Search technique ID or name (substring match)",
    ),
    tactic: str | None = Query(
        default=None,
        description="Filter by tactic slug (e.g. defense-evasion, execution)",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> list[dict]:
    """
    Browse MITRE ATT&CK techniques with analysis frequency.

    Returns each technique with its ID, name, tactics array, and the number of
    distinct analyses in which it was observed (analysis_count). Ordered by
    analysis_count descending so the most common techniques appear first.
    """
    analysis_count_col = func.count(
        func.distinct(AnalysisTechnique.analysis_id)
    ).label("analysis_count")

    stmt = (
        select(
            TechniqueValue.id,
            TechniqueValue.technique_id,
            TechniqueValue.technique_name,
            TechniqueValue.tactics,
            TechniqueValue.first_seen,
            analysis_count_col,
        )
        .join(AnalysisTechnique, AnalysisTechnique.technique_id == TechniqueValue.id)
        .group_by(
            TechniqueValue.id,
            TechniqueValue.technique_id,
            TechniqueValue.technique_name,
            TechniqueValue.tactics,
            TechniqueValue.first_seen,
        )
        .order_by(analysis_count_col.desc())
        .offset(offset)
        .limit(limit)
    )

    if q:
        # Match against both technique_id (T1055) and technique_name
        stmt = stmt.where(
            TechniqueValue.technique_id.ilike(f"%{q}%")
            | TechniqueValue.technique_name.ilike(f"%{q}%")
        )

    if tactic:
        # Postgres ARRAY contains operator — checks if the tactic slug is in
        # the tactics varchar[] column.
        stmt = stmt.where(TechniqueValue.tactics.any(tactic))

    rows = session.exec(stmt).all()

    return [
        {
            "id": row.id,
            "technique_id": row.technique_id,
            "technique_name": row.technique_name,
            "tactics": row.tactics or [],
            "first_seen": row.first_seen,
            "analysis_count": row.analysis_count,
        }
        for row in rows
    ]
