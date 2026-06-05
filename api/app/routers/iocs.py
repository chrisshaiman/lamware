# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# IOC browser endpoint — cross-sample IOC correlation.
#
# Each IOC value is stored once in ioc_values. The analysis_iocs join table
# links IOCs to analyses. This endpoint groups by IOC and counts how many
# distinct analyses share each indicator, so analysts can quickly identify
# infrastructure reused across multiple samples.

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlmodel import Session, select

from ..auth import AuthContext, require_auth
from ..database import get_session
from ..models.analysis import Analysis
from ..models.ioc import AnalysisIoc, IocValue
from ..models.sample import Sample

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


@router.get("")
async def list_iocs(
    q: str | None = Query(default=None, description="Search IOC value (substring match)"),
    type: str | None = Query(
        default=None,
        description="Filter by IOC type (e.g. ipv4-addr, domain-name, url)",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> list[dict]:
    """
    Browse all IOCs with cross-sample frequency counts.

    Returns IOC value, type, and the number of distinct analyses in which
    each IOC appeared (analysis_count). Ordered by analysis_count descending
    so the most widely observed indicators surface first.
    """
    # Count distinct analyses per IOC value — the key cross-correlation metric.
    # We join ioc_values -> analysis_iocs and group on the ioc_values PK.
    analysis_count_col = func.count(func.distinct(AnalysisIoc.analysis_id)).label(
        "analysis_count"
    )

    stmt = (
        select(
            IocValue.id,
            IocValue.type,
            IocValue.value,
            IocValue.first_seen,
            IocValue.last_seen,
            analysis_count_col,
        )
        .join(AnalysisIoc, AnalysisIoc.ioc_id == IocValue.id)
        .group_by(
            IocValue.id,
            IocValue.type,
            IocValue.value,
            IocValue.first_seen,
            IocValue.last_seen,
        )
        .order_by(analysis_count_col.desc())
        .offset(offset)
        .limit(limit)
    )

    if q:
        # Case-insensitive substring match on the IOC value string
        stmt = stmt.where(IocValue.value.ilike(f"%{q}%"))

    if type:
        stmt = stmt.where(IocValue.type == type)

    rows = session.exec(stmt).all()

    return [
        {
            "id": row.id,
            "type": row.type,
            "value": row.value,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "analysis_count": row.analysis_count,
        }
        for row in rows
    ]


@router.get("/{ioc_id}/analyses")
async def ioc_analyses(
    ioc_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> list[dict]:
    """
    List all analyses that contain a specific IOC.

    Lets analysts pivot from a single indicator to every pipeline run that
    observed it — the core cross-sample correlation query.
    """
    ioc = session.get(IocValue, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    stmt = (
        select(
            Analysis.id.label("analysis_id"),
            Sample.sha256,
            Analysis.malware_family_guess.label("family"),
            Analysis.created_at.label("submitted_at"),
            AnalysisIoc.source_stage,
            AnalysisIoc.confidence,
        )
        .join(AnalysisIoc, AnalysisIoc.analysis_id == Analysis.id)
        .join(Sample, Sample.id == Analysis.sample_id)
        .where(AnalysisIoc.ioc_id == ioc_id)
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
            "confidence": row.confidence,
        }
        for row in rows
    ]
