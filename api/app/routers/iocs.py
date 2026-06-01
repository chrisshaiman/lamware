# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# IOC browser endpoint — cross-sample IOC correlation.
#
# Each IOC value is stored once in ioc_values. The analysis_iocs join table
# links IOCs to analyses. This endpoint groups by IOC and counts how many
# distinct analyses share each indicator, so analysts can quickly identify
# infrastructure reused across multiple samples.

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlmodel import Session, select

from ..auth import AuthContext, require_auth
from ..database import get_session
from ..models.ioc import AnalysisIoc, IocValue

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


@router.get("")
async def list_iocs(
    q: str | None = Query(default=None, description="Search IOC value (substring match)"),
    type: str | None = Query(
        default=None,
        description="Filter by IOC type (e.g. ipv4-addr, domain-name, url)",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
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
