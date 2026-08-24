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

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlmodel import Session

from ..auth import AuthContext, require_auth
from ..database import get_session

log = logging.getLogger(__name__)

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
    (today / week).

    A query that fails still yields 0, because the response has to keep its
    shape — but the name of every failed query is listed in `errors`. Without
    that, a database the API cannot reach rendered the dashboard as "0 analyses,
    $0.00 spend", which is what a quiet week looks like. Design principle 3 says
    a failed analyzer must never masquerade as a clean result, and the README
    states it as enforced; it was enforced in the pipeline
    (`correlation_warnings`, `PayloadAccessError`, Ghidra `analysis_warnings`)
    and not here. `spend.py:_zeroed` is the same fix on the neighbouring
    endpoint.
    """
    errors: list[str] = []
    stats = {
        "total_analyses": _scalar(errors, "total_analyses", session, "SELECT COUNT(*) FROM analyses"),
        "total_samples": _scalar(errors, "total_samples", session, "SELECT COUNT(*) FROM samples"),
        "total_iocs": _scalar(errors, "total_iocs", session, "SELECT COUNT(*) FROM ioc_values"),
        "total_techniques": _scalar(errors, "total_techniques", session, "SELECT COUNT(*) FROM technique_values"),
        "families_detected": _scalar(errors, "families_detected", session,
            """
            SELECT COUNT(DISTINCT malware_family_guess)
            FROM   analyses
            WHERE  malware_family_guess IS NOT NULL
              AND  malware_family_guess != 'unknown'
            """,
        ),
        "cost_today": _scalar(errors, "cost_today", session,
            """
            SELECT COALESCE(SUM(llm_cost_usd), 0)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '1 day'
              AND  llm_cost_usd IS NOT NULL
            """,
            as_float=True,
        ),
        "cost_week": _scalar(errors, "cost_week", session,
            """
            SELECT COALESCE(SUM(llm_cost_usd), 0)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '7 days'
              AND  llm_cost_usd IS NOT NULL
            """,
            as_float=True,
        ),
        "cost_total": _scalar(errors, "cost_total", session,
            """
            SELECT COALESCE(SUM(llm_cost_usd), 0)
            FROM   analyses
            WHERE  llm_cost_usd IS NOT NULL
            """,
            as_float=True,
        ),
        "analyses_today": _scalar(errors, "analyses_today", session,
            """
            SELECT COUNT(*)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '1 day'
            """,
        ),
        "analyses_week": _scalar(errors, "analyses_week", session,
            """
            SELECT COUNT(*)
            FROM   analyses
            WHERE  started_at >= NOW() - INTERVAL '7 days'
            """,
        ),
    }
    stats["errors"] = errors
    return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scalar(
    errors: list[str],
    name: str,
    session: Session,
    sql: str,
    *,
    as_float: bool = False,
) -> int | float:
    """
    Execute a single-value SQL query and return the result.

    as_float=True casts to float (for cost columns stored as NUMERIC).

    Still returns 0 on failure — the response keeps its shape either way — but
    appends `name` to `errors` first, and logs. The bare `except Exception:
    return 0` this replaces made a broken query and an empty table produce byte-
    identical output, so a database the API could not reach rendered as a quiet
    week rather than as an outage.
    """
    try:
        result = session.exec(text(sql)).scalar()  # type: ignore[call-overload]
        if result is None:
            return 0.0 if as_float else 0
        return float(result) if as_float else int(result)
    except Exception as exc:
        log.warning("stats query %s failed: %s", name, exc)
        errors.append(name)
        return 0.0 if as_float else 0
