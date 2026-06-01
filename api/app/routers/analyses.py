# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Analyses router -- /api/analyses endpoints.

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from sqlmodel import Session, col, func, select

from ..auth import AuthContext, require_auth, require_role
from ..audit import log_audit
from ..config import settings
from ..database import get_session
from ..models import (
    Analysis,
    AnalysisIoc,
    AnalysisTechnique,
    Capability,
    IocValue,
    NetworkEvent,
    Sample,
    Signature,
    TechniqueValue,
)

router = APIRouter(prefix="/api/analyses", tags=["analyses"])


# ---------------------------------------------------------------------------
# Helper -- fetch analysis or raise 404
# ---------------------------------------------------------------------------


def _get_analysis_or_404(analysis_id: int, session: Session) -> Analysis:
    analysis = session.get(Analysis, analysis_id)
    if analysis is None:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")
    return analysis


# ---------------------------------------------------------------------------
# GET /api/analyses -- paginated list
# ---------------------------------------------------------------------------


@router.get("")
def list_analyses(
    q: str | None = Query(default=None, description="Search SHA256, filename, or family"),
    severity: str | None = Query(default=None, description="Filter by severity"),
    family: str | None = Query(default=None, description="Filter by malware family"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    List analyses with optional search and filters.

    Returns total count and a page of results. Each item includes sample
    details (sha256, filename) plus IOC, technique, and signature counts.
    """
    # Base query: join Analysis to Sample
    stmt = select(Analysis, Sample).join(Sample, Analysis.sample_id == Sample.id)

    # Filters
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            col(Sample.sha256).ilike(pattern)
            | col(Sample.filename).ilike(pattern)
            | col(Analysis.malware_family_guess).ilike(pattern)
        )
    if severity:
        stmt = stmt.where(Analysis.severity == severity)
    if family:
        stmt = stmt.where(col(Analysis.malware_family_guess).ilike(f"%{family}%"))

    # Total count before pagination
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = session.exec(count_stmt).one()

    # Paginate, sort newest first
    stmt = stmt.order_by(col(Analysis.started_at).desc()).offset(offset).limit(limit)
    rows = session.exec(stmt).all()

    # Batch-fetch per-analysis counts to avoid N+1 queries
    if rows:
        analysis_ids = [a.id for a, _ in rows]

        ioc_counts: dict[int, int] = {}
        for row in session.exec(
            select(AnalysisIoc.analysis_id, func.count(AnalysisIoc.id).label("cnt"))
            .where(col(AnalysisIoc.analysis_id).in_(analysis_ids))
            .group_by(AnalysisIoc.analysis_id)
        ).all():
            ioc_counts[row[0]] = row[1]

        tech_counts: dict[int, int] = {}
        for row in session.exec(
            select(AnalysisTechnique.analysis_id, func.count(AnalysisTechnique.id).label("cnt"))
            .where(col(AnalysisTechnique.analysis_id).in_(analysis_ids))
            .group_by(AnalysisTechnique.analysis_id)
        ).all():
            tech_counts[row[0]] = row[1]

        sig_counts: dict[int, int] = {}
        for row in session.exec(
            select(Signature.analysis_id, func.count(Signature.id).label("cnt"))
            .where(col(Signature.analysis_id).in_(analysis_ids))
            .group_by(Signature.analysis_id)
        ).all():
            sig_counts[row[0]] = row[1]
    else:
        ioc_counts = {}
        tech_counts = {}
        sig_counts = {}

    items = []
    for analysis, sample in rows:
        items.append(
            {
                "id": analysis.id,
                "task_id": analysis.task_id,
                "started_at": analysis.started_at,
                "completed_at": analysis.completed_at,
                "severity": analysis.severity,
                "malscore": float(analysis.malscore) if analysis.malscore is not None else None,
                "malware_family_guess": analysis.malware_family_guess,
                "pipeline_status": analysis.pipeline_status,
                "current_stage": analysis.current_stage,
                "sample": {
                    "id": sample.id,
                    "sha256": sample.sha256,
                    "filename": sample.filename,
                    "file_type": sample.file_type,
                    "file_mime": sample.file_mime,
                    "file_size": sample.file_size,
                },
                "ioc_count": ioc_counts.get(analysis.id, 0),
                "technique_count": tech_counts.get(analysis.id, 0),
                "signature_count": sig_counts.get(analysis.id, 0),
            }
        )

    return {"total": total, "offset": offset, "limit": limit, "analyses": items}


# ---------------------------------------------------------------------------
# GET /api/analyses/{id} -- full detail
# ---------------------------------------------------------------------------


@router.get("/{analysis_id}")
def get_analysis(
    analysis_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> dict:
    """
    Full analysis detail with nested IOCs, techniques, capabilities,
    signatures, and network events.
    """
    analysis = _get_analysis_or_404(analysis_id, session)
    sample = session.get(Sample, analysis.sample_id)

    # IOCs: join AnalysisIoc -> IocValue
    ioc_rows = session.exec(
        select(AnalysisIoc, IocValue)
        .join(IocValue, AnalysisIoc.ioc_id == IocValue.id)
        .where(AnalysisIoc.analysis_id == analysis_id)
        .order_by(IocValue.type, IocValue.value)
    ).all()

    iocs = [
        {
            "id": ai.id,
            "ioc_id": ioc.id,
            "type": ioc.type,
            "value": ioc.value,
            "source_stage": ai.source_stage,
            "confidence": ai.confidence,
            "context": ai.context,
        }
        for ai, ioc in ioc_rows
    ]

    # Techniques: join AnalysisTechnique -> TechniqueValue
    tech_rows = session.exec(
        select(AnalysisTechnique, TechniqueValue)
        .join(TechniqueValue, AnalysisTechnique.technique_id == TechniqueValue.id)
        .where(AnalysisTechnique.analysis_id == analysis_id)
        .order_by(TechniqueValue.technique_id)
    ).all()

    techniques = [
        {
            "id": at.id,
            "technique_id": tv.technique_id,
            "technique_name": tv.technique_name,
            "tactics": tv.tactics or [],
            "source_stage": at.source_stage,
            "source_detail": at.source_detail,
        }
        for at, tv in tech_rows
    ]

    # Capabilities
    capabilities = [
        {
            "id": cap.id,
            "description": cap.description,
            "source_stage": cap.source_stage,
        }
        for cap in session.exec(
            select(Capability)
            .where(Capability.analysis_id == analysis_id)
            .order_by(Capability.id)
        ).all()
    ]

    # Signatures sorted by severity desc, then name
    signatures = [
        {
            "id": sig.id,
            "name": sig.name,
            "severity": sig.severity,
            "description": sig.description,
            "source_stage": sig.source_stage,
        }
        for sig in session.exec(
            select(Signature)
            .where(Signature.analysis_id == analysis_id)
            .order_by(col(Signature.severity).desc(), Signature.name)
        ).all()
    ]

    # Network events
    network_events = [
        {
            "id": ne.id,
            "event_type": ne.event_type,
            "dns_query": ne.dns_query,
            "dns_type": ne.dns_type,
            "dns_answers": ne.dns_answers,
            "http_method": ne.http_method,
            "http_url": ne.http_url,
            "http_host": ne.http_host,
            "http_status": ne.http_status,
            "http_user_agent": ne.http_user_agent,
            "src_ip": ne.src_ip,
            "src_port": ne.src_port,
            "dst_ip": ne.dst_ip,
            "dst_port": ne.dst_port,
            "timestamp": ne.timestamp,
        }
        for ne in session.exec(
            select(NetworkEvent)
            .where(NetworkEvent.analysis_id == analysis_id)
            .order_by(NetworkEvent.timestamp, NetworkEvent.id)
        ).all()
    ]

    return {
        "id": analysis.id,
        "task_id": analysis.task_id,
        "started_at": analysis.started_at,
        "completed_at": analysis.completed_at,
        "severity": analysis.severity,
        "malscore": float(analysis.malscore) if analysis.malscore is not None else None,
        "malware_family_guess": analysis.malware_family_guess,
        "pipeline_status": analysis.pipeline_status,
        "current_stage": analysis.current_stage,
        # Stage completion flags
        "triage_completed": analysis.triage_completed,
        "cape_completed": analysis.cape_completed,
        "cape_task_id": analysis.cape_task_id,
        "volatility_completed": analysis.volatility_completed,
        "volatility_triggered": analysis.volatility_triggered,
        "ghidra_completed": analysis.ghidra_completed,
        "ghidra_triggered": analysis.ghidra_triggered,
        "interpret_completed": analysis.interpret_completed,
        "summary_completed": analysis.summary_completed,
        "pdf_generated": analysis.pdf_generated,
        # AI RE metadata
        "interpret_model": analysis.interpret_model,
        "interpret_tool_calls": analysis.interpret_tool_calls,
        "interpret_duration_secs": analysis.interpret_duration_secs,
        "interpret_escalated": analysis.interpret_escalated,
        "possible_prompt_influence": analysis.possible_prompt_influence,
        # Narrative fields
        "narrative": analysis.narrative,
        "working_notes": analysis.working_notes,
        "executive_summary": analysis.executive_summary,
        "plain_english_summary": analysis.plain_english_summary,
        # Cost / timing
        "llm_cost_usd": float(analysis.llm_cost_usd) if analysis.llm_cost_usd is not None else None,
        "stage_timings": analysis.stage_timings,
        "created_at": analysis.created_at,
        # Nested related objects
        "sample": {
            "id": sample.id,
            "sha256": sample.sha256,
            "sha1": sample.sha1,
            "md5": sample.md5,
            "ssdeep": sample.ssdeep,
            "filename": sample.filename,
            "file_type": sample.file_type,
            "file_mime": sample.file_mime,
            "file_size": sample.file_size,
            "entropy": sample.entropy,
        }
        if sample
        else None,
        "iocs": iocs,
        "techniques": techniques,
        "capabilities": capabilities,
        "signatures": signatures,
        "network_events": network_events,
    }


# ---------------------------------------------------------------------------
# DELETE /api/analyses/{id} -- delete analysis and report files
# ---------------------------------------------------------------------------


@router.delete("/{analysis_id}", status_code=200)
def delete_analysis(
    analysis_id: int,
    auth: AuthContext = Depends(require_role("admin")),
    session: Session = Depends(get_session),
) -> dict:
    """
    Delete an analysis and all associated child rows.
    Also removes the report directory from disk (best-effort).

    Child rows are deleted explicitly in FK-safe order regardless of
    whether ON DELETE CASCADE is defined in the schema.
    """
    analysis = _get_analysis_or_404(analysis_id, session)
    task_id = analysis.task_id

    # Delete child rows in FK-safe order
    for model in (AnalysisIoc, AnalysisTechnique, Capability, Signature, NetworkEvent):
        rows = session.exec(
            select(model).where(model.analysis_id == analysis_id)  # type: ignore[attr-defined]
        ).all()
        for row in rows:
            session.delete(row)

    session.delete(analysis)
    session.commit()

    log_audit(
        session, auth,
        action="analysis_delete",
        resource_type="analysis",
        resource_id=str(analysis_id),
        details={"task_id": task_id},
    )

    # Remove report files from disk -- best-effort, no exception on failure
    report_dir = Path(settings.reports_dir) / task_id
    deleted_files: list[str] = []
    if report_dir.exists():
        for f in report_dir.iterdir():
            try:
                f.unlink()
                deleted_files.append(f.name)
            except OSError:
                pass
        try:
            report_dir.rmdir()
        except OSError:
            pass

    return {
        "deleted": True,
        "analysis_id": analysis_id,
        "task_id": task_id,
        "files_removed": deleted_files,
    }


# ---------------------------------------------------------------------------
# GET /api/analyses/{id}/pdf -- PDF report download
# ---------------------------------------------------------------------------


@router.get("/{analysis_id}/pdf")
def get_pdf(
    analysis_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> FileResponse:
    """Download the PDF report for this analysis."""
    analysis = _get_analysis_or_404(analysis_id, session)

    pdf_path = Path(settings.reports_dir) / analysis.task_id / "report.pdf"
    if not pdf_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"PDF report not found for task {analysis.task_id}",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"lamware_{analysis.task_id}.pdf",
    )


# ---------------------------------------------------------------------------
# GET /api/analyses/{id}/logs -- pipeline log download
# ---------------------------------------------------------------------------


@router.get("/{analysis_id}/logs")
def get_logs(
    analysis_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> FileResponse:
    """Download the pipeline log for this analysis."""
    analysis = _get_analysis_or_404(analysis_id, session)

    # Check multiple naming conventions used by the pipeline
    task_dir = Path(settings.reports_dir) / analysis.task_id
    candidates = [
        task_dir / "pipeline.log",
        task_dir / f"pipeline_{analysis.task_id}.log",
        Path("/opt/pipeline/logs") / f"{analysis.task_id}.log",
    ]

    log_path: Path | None = None
    for candidate in candidates:
        if candidate.exists():
            log_path = candidate
            break

    if log_path is None:
        raise HTTPException(
            status_code=404,
            detail=f"Pipeline log not found for task {analysis.task_id}",
        )

    return FileResponse(
        path=str(log_path),
        media_type="text/plain",
        filename=f"lamware_{analysis.task_id}.log",
    )


# ---------------------------------------------------------------------------
# GET /api/analyses/{id}/iocs/csv -- CSV export
# ---------------------------------------------------------------------------


@router.get("/{analysis_id}/iocs/csv")
def export_iocs_csv(
    analysis_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> StreamingResponse:
    """Export all IOCs for this analysis as CSV."""
    _get_analysis_or_404(analysis_id, session)

    ioc_rows = session.exec(
        select(AnalysisIoc, IocValue)
        .join(IocValue, AnalysisIoc.ioc_id == IocValue.id)
        .where(AnalysisIoc.analysis_id == analysis_id)
        .order_by(IocValue.type, IocValue.value)
    ).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "confidence", "source_stage", "context"])
    for ai, ioc in ioc_rows:
        writer.writerow([
            ioc.type,
            ioc.value,
            ai.confidence or "",
            ai.source_stage or "",
            ai.context or "",
        ])

    buf.seek(0)
    filename = f"iocs_analysis_{analysis_id}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={chr(34)}{filename}{chr(34)}"},
    )


# ---------------------------------------------------------------------------
# GET /api/analyses/{id}/iocs/stix -- STIX 2.1 bundle export
# ---------------------------------------------------------------------------

# Maps internal IOC type strings to STIX 2.1 Observable type names.
# Types absent from this map use the x-lamware-observable custom extension.
_STIX_TYPE_MAP: dict[str, str] = {
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "domain-name": "domain-name",
    "url": "url",
    "email-addr": "email-addr",
    "file:hashes.SHA-256": "file",
    "file:hashes.MD5": "file",
    "file:name": "file",
    "windows-registry-key": "windows-registry-key",
    "mutex": "mutex",
    "network-traffic": "network-traffic",
}

# Fixed UUID namespace for deterministic STIX IDs (URL namespace, RFC 4122)
_STIX_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


def _ioc_to_stix_object(ioc: IocValue, ai: AnalysisIoc) -> dict:
    """
    Convert one IOC into a STIX 2.1 Observable dict.

    IDs are deterministic via uuid5 so repeated exports yield stable bundles.
    Custom x_lamware_* properties carry pipeline metadata not expressible in
    standard STIX fields.
    """
    stix_type = _STIX_TYPE_MAP.get(ioc.type, "x-lamware-observable")
    det_id = uuid.uuid5(_STIX_NS, f"{stix_type}--{ioc.type}:{ioc.value}")
    stix_id = f"{stix_type}--{det_id}"

    obj: dict = {
        "type": stix_type,
        "id": stix_id,
        "spec_version": "2.1",
    }

    # Populate standard type-specific fields
    if stix_type in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr"):
        obj["value"] = ioc.value
    elif stix_type == "file":
        if ioc.type == "file:hashes.SHA-256":
            obj["hashes"] = {"SHA-256": ioc.value}
        elif ioc.type == "file:hashes.MD5":
            obj["hashes"] = {"MD5": ioc.value}
        else:
            obj["name"] = ioc.value
    elif stix_type == "windows-registry-key":
        obj["key"] = ioc.value
    elif stix_type == "mutex":
        obj["name"] = ioc.value
    elif stix_type == "network-traffic":
        # network-traffic requires src/dst refs we may not have; store raw value
        obj["x_lamware_raw"] = ioc.value
    else:
        # Custom extension for unrecognised types
        obj["x_lamware_type"] = ioc.type
        obj["x_lamware_value"] = ioc.value

    # Pipeline metadata as custom properties
    if ai.source_stage:
        obj["x_lamware_source_stage"] = ai.source_stage
    if ai.context:
        obj["x_lamware_context"] = ai.context
    if ai.confidence:
        obj["x_lamware_confidence"] = ai.confidence

    return obj


@router.get("/{analysis_id}/iocs/stix")
def export_iocs_stix(
    analysis_id: int,
    auth: AuthContext = Depends(require_auth),
    session: Session = Depends(get_session),
) -> StreamingResponse:
    """
    Export all IOCs for this analysis as a STIX 2.1 bundle (JSON).

    Each IOC becomes a STIX Observable. The bundle also includes an
    x-lamware-analysis object with analysis metadata. IDs are deterministic
    (uuid5) so the same IOC always maps to the same STIX ID across exports.
    """
    analysis = _get_analysis_or_404(analysis_id, session)

    ioc_rows = session.exec(
        select(AnalysisIoc, IocValue)
        .join(IocValue, AnalysisIoc.ioc_id == IocValue.id)
        .where(AnalysisIoc.analysis_id == analysis_id)
        .order_by(IocValue.type, IocValue.value)
    ).all()

    objects: list[dict] = []

    # Custom analysis metadata object
    analysis_stix_id = "x-lamware-analysis--" + str(uuid.uuid5(_STIX_NS, f"analysis:{analysis_id}"))
    objects.append(
        {
            "type": "x-lamware-analysis",
            "id": analysis_stix_id,
            "spec_version": "2.1",
            "analysis_id": analysis_id,
            "task_id": analysis.task_id,
            "severity": analysis.severity,
            "malscore": float(analysis.malscore) if analysis.malscore is not None else None,
            "malware_family_guess": analysis.malware_family_guess,
            "created": (
                analysis.started_at.isoformat()
                if analysis.started_at
                else datetime.now(timezone.utc).isoformat()
            ),
        }
    )

    # One Observable per IOC; deduplicate by STIX ID
    seen_ids: set[str] = set()
    for ai, ioc in ioc_rows:
        stix_obj = _ioc_to_stix_object(ioc, ai)
        if stix_obj["id"] not in seen_ids:
            objects.append(stix_obj)
            seen_ids.add(stix_obj["id"])

    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid5(_STIX_NS, f"bundle:analysis:{analysis_id}")),
        "spec_version": "2.1",
        "objects": objects,
    }

    filename = f"iocs_analysis_{analysis_id}.stix.json"
    return StreamingResponse(
        iter([json.dumps(bundle, indent=2, default=str)]),
        media_type="application/stix+json",
        headers={"Content-Disposition": f"attachment; filename={chr(34)}{filename}{chr(34)}"},
    )
