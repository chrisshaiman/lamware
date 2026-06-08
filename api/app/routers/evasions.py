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


# ---------------------------------------------------------------------------
# Mitigation status — based on deployed hardening (ADR-012, guest-domain.xml,
# kvm-qemu.sh DSDT patches, Packer scripts, INetSim routing).
#
# "mitigated"  — hardening defeats this technique
# "partial"    — partially addressed, residual risk remains
# "open"       — not yet addressed (fixable)
# "na"         — not applicable / detection engineering (can't fix in sandbox)
# ---------------------------------------------------------------------------

_MITIGATION_RULES: list[tuple[str, re.Pattern[str]]] = [
    # --- Mitigated (deployed hardening defeats these) ---
    # CPUID/hypervisor: host-passthrough + hypervisor bit disabled
    ("mitigated", re.compile(
        r"cpuid|hypervisor.*bit|hypervisor.*detect",
        re.IGNORECASE,
    )),
    # ACPI/DSDT/SMBIOS: kvm-qemu.sh patches brand names
    ("mitigated", re.compile(
        r"acpi|dsdt|smbios|bochs|seabios",
        re.IGNORECASE,
    )),
    # Hostname/username/computer name: Packer randomizes
    ("mitigated", re.compile(
        r"hostname|computer name|username",
        re.IGNORECASE,
    )),
    # Screen resolution: Packer sets 1920x1080
    ("mitigated", re.compile(
        r"screen.*resolution",
        re.IGNORECASE,
    )),
    # Disk/memory/CPU specs: 60GB/4GB/4cores
    ("mitigated", re.compile(
        r"disk size|memory.*check|available memory|memory size",
        re.IGNORECASE,
    )),
    # Hardware ID / volume serial: real hardware via passthrough
    ("mitigated", re.compile(
        r"hardware.?id|volume serial",
        re.IGNORECASE,
    )),
    # DNS/network connectivity: INetSim responds to all queries
    ("mitigated", re.compile(
        r"dns.*connect|dns.*reach|network.*connect.*verif|"
        r"connectivity.*verif|external.*ip.*verif",
        re.IGNORECASE,
    )),
    # Clock offset: localtime + native TSC
    ("mitigated", re.compile(
        r"sandbox.*clock.*manipul|clock.*offset|clock.*mismatch",
        re.IGNORECASE,
    )),
    # System fingerprinting / environment enumeration: decoy files + realistic profile
    ("mitigated", re.compile(
        r"system fingerprint|environment.*enum|victim profil|"
        r"environment.*fingerprint",
        re.IGNORECASE,
    )),

    # --- Partially mitigated ---
    # Storage device: DSDT patched but QEMU disk IDs may leak
    ("partial", re.compile(
        r"storage device|mount point|disk.*detect|vm.*disk",
        re.IGNORECASE,
    )),
    # Virtual network adapter: e1000 NIC but MAC OUI 52:54:00 still present
    ("partial", re.compile(
        r"virtual.*adapter|virtual.*network|mac address",
        re.IGNORECASE,
    )),
    # Timing/sleep: native TSC + catchup but no CAPE sleep skipping
    ("partial", re.compile(
        r"timing|sleep|delay|deferred|uptime|recently.?booted|"
        r"rdtsc|performance.*counter",
        re.IGNORECASE,
    )),
    # Date/time expiration: clock is realistic but sample may check real date
    ("partial", re.compile(
        r"date.*expir|kill.*date|time.?bomb|temporal",
        re.IGNORECASE,
    )),
    # Dead C2 / network: INetSim responds but may not match expected protocol
    ("partial", re.compile(
        r"dead c2|c2.*connect|kill.*switch|connectivity.*check|"
        r"network.*environment|inetsim|protocol.*not.*simul|"
        r"internet.*reach|external.*ip",
        re.IGNORECASE,
    )),
    # Registry VM detection: some keys cleaned but not exhaustive
    ("partial", re.compile(
        r"registry.*(?:vm|environment|artifact)",
        re.IGNORECASE,
    )),
    # Display device query: standard VGA but identifiable as emulated
    ("partial", re.compile(
        r"display device",
        re.IGNORECASE,
    )),

    # --- Open (not yet addressed, could be fixed) ---
    # Human interaction / mouse / keyboard: deferred per ADR-012
    ("open", re.compile(
        r"human.*interact|user.*interact|mouse|cursor|"
        r"keyboard.*layout|user.*activ",
        re.IGNORECASE,
    )),
    # Parent process / execution context: not spoofed
    ("open", re.compile(
        r"parent.*process|execution.*context",
        re.IGNORECASE,
    )),
    # Analysis tool detection: capemon hooks but tools visible in process list
    ("open", re.compile(
        r"process.*enum.*tool|analysis.*tool|"
        r"cross.*process.*memory.*tool",
        re.IGNORECASE,
    )),
    # Large binary / file size evasion: no sandbox-side fix needed (sample property)
    ("open", re.compile(
        r"large.*binary|large.*file|file.?size.*evasion|"
        r"inflated binary|oversized|bloat",
        re.IGNORECASE,
    )),
]


def _mitigation_status(technique: str, category: str) -> str:
    """Determine mitigation status based on deployed hardening."""
    # Detection engineering items are never "fixable" in the sandbox
    if category == "detection":
        return "na"

    for status, pattern in _MITIGATION_RULES:
        if pattern.search(technique):
            return status

    # Default: open for actionable categories, na for detection
    return "open"


@router.get("")
async def list_evasions(
    status: str | None = None,
    category: str | None = None,
    sort: str = "sample_count",
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Aggregate evasion hunter findings across all analyses.

    Returns techniques ranked by frequency with MITRE IDs, evidence,
    fix-type category, and mitigation status for each technique.

    Query params:
        status: filter by mitigation status (mitigated, partial, open, na)
        category: filter by fix-type category
        sort: sort field — sample_count (default), status, category
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

    techniques = []
    for row in rows:
        cat = _categorize(row[0] or "")
        mit = _mitigation_status(row[0] or "", cat)
        techniques.append({
            "technique": row[0],
            "mitre_id": row[1],
            "evidence": row[2],
            "sample_count": row[3],
            "category": cat,
            "status": mit,
        })

    # Filter
    if status:
        techniques = [t for t in techniques if t["status"] == status]
    if category:
        techniques = [t for t in techniques if t["category"] == category]

    # Sort
    _STATUS_ORDER = {"open": 0, "partial": 1, "mitigated": 2, "na": 3}
    if sort == "status":
        techniques.sort(key=lambda t: (_STATUS_ORDER.get(t["status"], 9), -t["sample_count"]))
    elif sort == "category":
        techniques.sort(key=lambda t: (t["category"], -t["sample_count"]))
    # default: already sorted by sample_count DESC from SQL

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
