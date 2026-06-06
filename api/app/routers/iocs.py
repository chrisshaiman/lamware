# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# IOC browser endpoint — cross-sample IOC correlation.
#
# Each IOC value is stored once in ioc_values. The analysis_iocs join table
# links IOCs to analyses. This endpoint groups by IOC and counts how many
# distinct analyses share each indicator, so analysts can quickly identify
# infrastructure reused across multiple samples.

from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, text
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
    family: str | None = Query(
        default=None,
        description="Filter to IOCs seen in analyses matching this malware family (substring, case-insensitive)",
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

    if family:
        family_analyses = (
            select(Analysis.id)
            .where(Analysis.malware_family_guess.ilike(f"%{family}%"))
        ).subquery()
        stmt = stmt.where(
            AnalysisIoc.analysis_id.in_(select(family_analyses.c.id))
        )

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


@router.get("/clusters")
async def ioc_clusters(
    min_shared_iocs: int = Query(default=3, ge=1, le=50),
    min_analyses: int = Query(default=3, ge=2, le=100),
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> list[dict]:
    """
    Detect campaign clusters — groups of analyses sharing multiple IOCs.

    Uses union-find to merge analysis pairs that share at least
    *min_shared_iocs* indicators, then returns clusters with at least
    *min_analyses* members enriched with shared IOCs and techniques.
    """
    # Step 1: Find analysis pairs sharing >= min_shared_iocs IOCs.
    # Exclude noise IOCs (private IPs, localhost, INetSim) that create
    # false campaign links — these appear in nearly every analysis.
    pair_sql = text(
        """
        WITH meaningful_iocs AS (
            SELECT id FROM ioc_values
            WHERE NOT (
                (type = 'ipv4-addr' AND (
                    value LIKE '127.%'
                    OR value LIKE '10.%'
                    OR value LIKE '192.168.%'
                    OR value LIKE '172.16.%' OR value LIKE '172.17.%'
                    OR value LIKE '172.18.%' OR value LIKE '172.19.%'
                    OR value LIKE '172.2_.%' OR value LIKE '172.30.%'
                    OR value LIKE '172.31.%'
                    OR value = '0.0.0.0'
                    OR value = '255.255.255.255'
                ))
                OR (type = 'domain-name' AND value IN ('localhost', 'localhost.localdomain'))
            )
        )
        SELECT a1.analysis_id AS aid1, a2.analysis_id AS aid2,
               array_agg(DISTINCT a1.ioc_id) AS shared_ioc_ids
        FROM analysis_iocs a1
        JOIN meaningful_iocs m1 ON m1.id = a1.ioc_id
        JOIN analysis_iocs a2
            ON a1.ioc_id = a2.ioc_id AND a1.analysis_id < a2.analysis_id
        GROUP BY a1.analysis_id, a2.analysis_id
        HAVING COUNT(DISTINCT a1.ioc_id) >= :min_shared
        """
    )
    rows = session.exec(pair_sql, params={"min_shared": min_shared_iocs}).all()

    if not rows:
        return []

    # Step 2: Union-find to merge overlapping pairs into clusters
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Track which IOCs are shared between each pair for later enrichment
    pair_iocs: dict[tuple[int, int], list[int]] = {}
    for row in rows:
        union(row.aid1, row.aid2)
        pair_iocs[(row.aid1, row.aid2)] = list(row.shared_ioc_ids)

    # Group analyses by cluster root
    clusters_map: dict[int, set[int]] = defaultdict(set)
    for row in rows:
        root = find(row.aid1)
        clusters_map[root].add(row.aid1)
        clusters_map[root].add(row.aid2)

    # Step 3: Filter by min_analyses
    clusters_map = {
        root: aids for root, aids in clusters_map.items() if len(aids) >= min_analyses
    }
    if not clusters_map:
        return []

    # Step 4: Enrich each cluster
    result = []
    cluster_id = 0
    for _root, analysis_ids in clusters_map.items():
        cluster_id += 1
        aids_list = sorted(analysis_ids)

        # Analysis details (sha256, family)
        detail_sql = text(
            """
            SELECT a.id AS analysis_id, s.sha256,
                   a.malware_family_guess AS family
            FROM analyses a
            JOIN samples s ON s.id = a.sample_id
            WHERE a.id = ANY(:aids)
            ORDER BY a.id
            """
        )
        detail_rows = session.exec(
            detail_sql, params={"aids": aids_list}
        ).all()
        analyses_out = [
            {
                "analysis_id": r.analysis_id,
                "sha256": r.sha256,
                "family": r.family,
            }
            for r in detail_rows
        ]

        # Shared IOCs: IOCs appearing in 2+ analyses within this cluster
        shared_ioc_sql = text(
            """
            SELECT iv.id, iv.type, iv.value
            FROM ioc_values iv
            JOIN analysis_iocs ai ON ai.ioc_id = iv.id
            WHERE ai.analysis_id = ANY(:aids)
            GROUP BY iv.id, iv.type, iv.value
            HAVING COUNT(DISTINCT ai.analysis_id) >= 2
            ORDER BY iv.id
            """
        )
        shared_ioc_rows = session.exec(
            shared_ioc_sql, params={"aids": aids_list}
        ).all()
        shared_iocs_out = [
            {"id": r.id, "type": r.type, "value": r.value}
            for r in shared_ioc_rows
        ]

        # Shared techniques: techniques appearing in 2+ analyses
        shared_tech_sql = text(
            """
            SELECT tv.id, tv.technique_id, tv.technique_name
            FROM technique_values tv
            JOIN analysis_techniques at2 ON at2.technique_id = tv.id
            WHERE at2.analysis_id = ANY(:aids)
            GROUP BY tv.id, tv.technique_id, tv.technique_name
            HAVING COUNT(DISTINCT at2.analysis_id) >= 2
            ORDER BY tv.id
            """
        )
        shared_tech_rows = session.exec(
            shared_tech_sql, params={"aids": aids_list}
        ).all()
        shared_techniques_out = [
            {
                "id": r.id,
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
            }
            for r in shared_tech_rows
        ]

        result.append(
            {
                "cluster_id": cluster_id,
                "analyses": analyses_out,
                "shared_iocs": shared_iocs_out,
                "shared_techniques": shared_techniques_out,
            }
        )

    return result


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
