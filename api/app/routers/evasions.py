# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Evasion technique aggregation endpoint.
#
# Extracts evasion_analysis findings from the report_json JSONB column
# and aggregates across all analyses. Used by the React evasion dashboard
# to show which sandbox evasion techniques are most common and which
# are fixable via Packer/CAPE/QEMU changes.

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlmodel import Session

from ..auth import AuthContext, require_auth
from ..database import get_session

router = APIRouter(prefix="/api/evasions", tags=["evasions"])


@router.get("")
async def list_evasions(
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Aggregate evasion hunter findings across all analyses.

    Returns techniques ranked by frequency, with MITRE IDs and evidence.
    """
    # Extract all evasion techniques from report_json JSONB
    sql = text("""
        SELECT
            t->>'technique' AS technique,
            t->>'mitre_id' AS mitre_id,
            t->>'evidence' AS evidence,
            COUNT(*) AS sample_count
        FROM analyses,
             jsonb_array_elements(
                 report_json->'evasion_analysis'->'analysis'->'evasion_techniques'
             ) AS t
        WHERE report_json->'evasion_analysis'->>'enabled' = 'true'
          AND report_json->'evasion_analysis'->'analysis'->'evasion_techniques' IS NOT NULL
        GROUP BY t->>'technique', t->>'mitre_id', t->>'evidence'
        ORDER BY sample_count DESC
    """)

    try:
        rows = session.exec(sql).all()  # type: ignore[call-overload]
    except Exception:
        rows = []

    techniques = [
        {
            "technique": row[0],
            "mitre_id": row[1],
            "evidence": row[2],
            "sample_count": row[3],
        }
        for row in rows
    ]

    # Get total analyses with evasion data
    total_sql = text("""
        SELECT COUNT(*)
        FROM analyses
        WHERE report_json->'evasion_analysis'->>'enabled' = 'true'
    """)
    try:
        total = session.exec(total_sql).scalar() or 0  # type: ignore[call-overload]
    except Exception:
        total = 0

    # Get recommendations aggregated
    rec_sql = text("""
        SELECT r, COUNT(*) AS freq
        FROM analyses,
             jsonb_array_elements_text(
                 report_json->'evasion_analysis'->'analysis'->'sandbox_recommendations'
             ) AS r
        WHERE report_json->'evasion_analysis'->>'enabled' = 'true'
          AND report_json->'evasion_analysis'->'analysis'->'sandbox_recommendations' IS NOT NULL
        GROUP BY r
        ORDER BY freq DESC
    """)

    try:
        rec_rows = session.exec(rec_sql).all()  # type: ignore[call-overload]
    except Exception:
        rec_rows = []

    recommendations = [
        {"recommendation": row[0], "frequency": row[1]}
        for row in rec_rows
    ]

    return {
        "total_analyses_with_evasion": int(total),
        "techniques": techniques,
        "recommendations": recommendations,
    }
