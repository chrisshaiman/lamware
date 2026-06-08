# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Evasion technique aggregation endpoint.
#
# Extracts evasion_analysis findings from the report_json JSONB column
# and aggregates across all analyses. Used by the React evasion dashboard
# to show which sandbox evasion techniques are most common and which
# are fixable via Packer/CAPE/QEMU changes.
#
# Techniques are categorized by fix type so analysts know where to act:
#   guest_image  — fix in Packer template (registry, filenames, hardware IDs)
#   qemu         — fix via QEMU patches (CPUID, ACPI, hypervisor artifacts)
#   cape_config  — fix in CAPE config (timeouts, sleep skipping, clock)
#   automation   — fix via agentic automation (mouse, keyboard, user interaction)
#   detection    — can't fix in sandbox; write detection rules instead

import re

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlmodel import Session

from ..auth import AuthContext, require_auth
from ..database import get_session

router = APIRouter(prefix="/api/evasions", tags=["evasions"])

# Ordered list of (category, compiled_regex) pairs. First match wins.
# Patterns are matched case-insensitively against the technique name.
_CATEGORY_RULES: list[tuple[str, re.Pattern[str]]] = [
    # QEMU / hypervisor artifacts
    ("qemu", re.compile(
        r"cpuid|acpi|smbios|hypervisor|qemu|virtual.*adapter|"
        r"virtual.*network|display device|"
        r"storage device|mount point|disk.*detect|anti-vm|"
        r"vm/sandbox|sandbox.*detect.*static|"
        r"vm.*detect.*(?:display|disk|storage|device)",
        re.IGNORECASE,
    )),
    # Guest image — things you fix in Packer
    ("guest_image", re.compile(
        r"registry.*(?:vm|environment|artifact)|hostname|computer name|"
        r"username|hardware.?id|volume serial|mac address|"
        r"memory.*check|available memory|disk size|"
        r"environment.*fingerprint|system fingerprint|"
        r"victim profil|environment.*enum|"
        r"large.*binary|large.*file|file.?size.*evasion|"
        r"inflated binary|oversized|bloat|"
        r"pdb path|"
        r"vm.*detect.*(?:username|registry|environment)",
        re.IGNORECASE,
    )),
    # CAPE config — timeouts, sleep, clock, network simulation
    ("cape_config", re.compile(
        r"timing|sleep|delay|deferred|date.*expir|kill.*date|"
        r"time.?bomb|temporal|uptime|clock|"
        r"recently.?booted|"
        r"dns.*connect|network.*connect|c2.*connect|"
        r"dead c2|connectivity.*check|connectivity.*verif|"
        r"kill.*switch.*domain|internet.*reach|"
        r"external.*ip|network.*environment|"
        r"inetsim|protocol.*not.*simul",
        re.IGNORECASE,
    )),
    # Automation — human interaction, process enumeration for tools
    ("automation", re.compile(
        r"human.*interact|user.*interact|mouse|cursor|keyboard|"
        r"screen.*resolution|user.*activ|"
        r"parent.*process|execution.*context|"
        r"process.*enum.*tool|analysis.*tool|"
        r"enable.*content|social.*engineer",
        re.IGNORECASE,
    )),
    # Everything else is detection engineering
]


def _categorize(technique: str) -> str:
    """Assign a fix-type category to a freeform evasion technique name."""
    for category, pattern in _CATEGORY_RULES:
        if pattern.search(technique):
            return category
    return "detection"


@router.get("")
async def list_evasions(
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Aggregate evasion hunter findings across all analyses.

    Returns techniques ranked by frequency with MITRE IDs, evidence,
    and a fix-type category for each technique.
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
            "category": _categorize(row[0] or ""),
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
