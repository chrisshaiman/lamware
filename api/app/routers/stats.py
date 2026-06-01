# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Aggregate statistics endpoint.
#
# All queries use raw SQL via text() rather than SQLModel ORM selects.
# Reasons:
#   1. PostgreSQL INTERVAL literals ('1 day', '7 days') are not supported
#      cleanly in SQLModel's select() builder.
#   2. COUNT(DISTINCT ...) across joined tables is awkward with SQLModel
#      but straightforward in SQL.
#   3. The queries are simple enough that raw SQL is clearer than ORM calls.
#
# Each query is wrapped in its own try/except so a single failure doesn't
# take down the entire stats response.

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlmodel import Session

from ..auth import AuthContext, require_auth
from ..database import get_session

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
async def get_stats(
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Return aggregate platform statistics.

    Covers total counts (analyses, samples, IOCs, techniques, families),
    cost breakdown (today / week / all time), and analysis frequency
    (today / week). All values default to 0 if the query fails.
    """
    return {
        "total_analyses": _scalar(session, "SELECT COUNT(*) FROM analyses"),
        "total_samples": _scalar(session, "SELECT COUNT(*) FROM samples"),
        "total_iocs": _scalar(session, "SELECT COUNT(*) FROM ioc_values"),
        "total_techniques": _scalar(session, "SELECT COUNT(*) FROM technique_values"),
        "families_detected": _scalar(
            session,
            """
            SELECT COUNT(DISTINCT malware_family_guess)
            FROM   analyses
            WHERE  malware_family_guess IS NOT NULL
              AND  malware_family_guess != 'unknown'
            """,
        ),
        "cost_today": _scalar(
            session,
            """
            SELECT COALESCE(SUM(llm_cost_usd), 0)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '1 day'
              AND  llm_cost_usd IS NOT NULL
            """,
            as_float=True,
        ),
        "cost_week": _scalar(
            session,
            """
            SELECT COALESCE(SUM(llm_cost_usd), 0)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '7 days'
              AND  llm_cost_usd IS NOT NULL
            """,
            as_float=True,
        ),
        "cost_total": _scalar(
            session,
            """
            SELECT COALESCE(SUM(llm_cost_usd), 0)
            FROM   analyses
            WHERE  llm_cost_usd IS NOT NULL
            """,
            as_float=True,
        ),
        "analyses_today": _scalar(
            session,
            """
            SELECT COUNT(*)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '1 day'
            """,
        ),
        "analyses_week": _scalar(
            session,
            """
            SELECT COUNT(*)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '7 days'
            """,
        ),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scalar(session: Session, sql: str, *, as_float: bool = False) -> int | float:
    """
    Execute a single-value SQL query and return the result.

    as_float=True casts to float (for cost columns stored as NUMERIC).
    Returns 0 (or 0.0) on any exception so the stats response stays complete.
    """
    try:
        result = session.exec(text(sql)).scalar()  # type: ignore[call-overload]
        if result is None:
            return 0.0 if as_float else 0
        return float(result) if as_float else int(result)
    except Exception:
        return 0.0 if as_float else 0
