# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# ATT&CK technique browser endpoint.
#
# technique_values holds one row per unique MITRE technique (e.g. T1055.003).
# analysis_techniques is the join table linking techniques to analyses.
# This endpoint surfaces frequency across all analyses so analysts can see
# which techniques appear most often in analyzed samples.

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlmodel import Session, select

from ..auth import AuthContext, require_auth
from ..database import get_session
from ..models.analysis import Analysis
from ..models.sample import Sample
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
    family: str | None = Query(
        default=None,
        description="Filter to techniques seen in analyses matching this malware family (substring, case-insensitive)",
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

    if family:
        family_analyses = (
            select(Analysis.id)
            .where(Analysis.malware_family_guess.ilike(f"%{family}%"))
        ).subquery()
        stmt = stmt.where(
            AnalysisTechnique.analysis_id.in_(select(family_analyses.c.id))
        )

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


@router.get("/{technique_id}/analyses")
async def technique_analyses(
    technique_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> list[dict]:
    """
    List all analyses that exhibit a specific MITRE ATT&CK technique.

    Lets analysts pivot from a technique to every pipeline run where it was
    observed — useful for hunting shared TTPs across samples.
    """
    technique = session.get(TechniqueValue, technique_id)
    if not technique:
        raise HTTPException(status_code=404, detail="Technique not found")

    stmt = (
        select(
            Analysis.id.label("analysis_id"),
            Sample.sha256,
            Analysis.malware_family_guess.label("family"),
            Analysis.created_at.label("submitted_at"),
            AnalysisTechnique.source_stage,
        )
        .join(AnalysisTechnique, AnalysisTechnique.analysis_id == Analysis.id)
        .join(Sample, Sample.id == Analysis.sample_id)
        .where(AnalysisTechnique.technique_id == technique_id)
        .order_by(Analysis.created_at.desc())
    )

    rows = session.exec(stmt).all()

    return [
        {
            "analysis_id": row.analysis_id,
            "sha256": row.sha256,
            "family": row.family,
            "submitted_at": row.submitted_at,
            "source_stage": row.source_stage,
        }
        for row in rows
    ]
