# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Investigation agent router — conversational deep-dive sessions for malware analysis.
#
# Provides endpoints for creating/managing investigation sessions, sending messages
# (SSE streaming), managing analyst-pinned findings, promoting pins to the analysis
# record, switching models, and exporting markdown transcripts.

import json
import logging
from datetime import datetime, timezone
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlmodel import Session, col, select

from ..auth import AuthContext, require_auth, require_role
from ..audit import log_audit
from ..config import settings
from ..database import get_session
from ..investigate.orchestrator import run_conversation_turn
from ..investigate.system_prompt import build_system_prompt
from ..models.investigation import InvestigationMessage, InvestigationPin, InvestigationSession

log = logging.getLogger(__name__)

# Allowlist of models the investigation agent may use.
# These correspond to model IDs recognised by the LiteLLM proxy.
VALID_MODELS = ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5"]

AUTH_RESPONSES = {
    401: {"description": "Authentication required"},
    403: {"description": "Insufficient role"},
}

router = APIRouter(
    prefix="/api/investigate",
    tags=["investigate"],
    responses=AUTH_RESPONSES,
)


# ---------------------------------------------------------------------------
# Pure helpers — unit-testable without DB or HTTP
# ---------------------------------------------------------------------------


def _validate_pin_body(body: dict) -> str | None:
    """Validate POST /pin request body. Returns error message string or None."""
    pin_type = body.get("type")
    if pin_type not in {"ioc", "technique", "note"}:
        return f"pin type must be one of: ioc, technique, note (got {pin_type!r})"
    if pin_type == "ioc" and not body.get("ioc_type"):
        return "ioc_type is required when type is 'ioc'"
    return None


def _build_report_markdown(session_dict: dict, messages: list[dict], pins: list[dict]) -> str:
    """Build a markdown transcript/report from plain data dicts.

    Accepts plain dicts so this function is testable without DB objects.
    session_dict keys: id, analysis_id, model, total_cost_usd, created_at (isoformat str)
    messages: list of dicts with keys: id, role, content, tool_name, created_at
    pins: list of dicts with keys: id, pin_type, value, ioc_type, context, promoted, created_at
    """
    lines: list[str] = []

    # --- Header ---
    lines.append(f"# Investigation Report — Session {session_dict['id']}")
    lines.append("")
    lines.append(f"- **Analysis ID:** {session_dict['analysis_id']}")
    lines.append(f"- **Model:** {session_dict['model']}")
    cost = session_dict.get("total_cost_usd", 0)
    lines.append(f"- **Total cost:** ${float(cost):.4f}")
    lines.append(f"- **Date:** {session_dict.get('created_at', '')}")
    lines.append("")

    # --- Findings ---
    lines.append("## Findings")
    lines.append("")
    if pins:
        for pin in pins:
            label = pin["pin_type"].upper()
            ioc_suffix = f" ({pin['ioc_type']})" if pin.get("ioc_type") else ""
            promoted_suffix = " *(promoted to analysis)*" if pin.get("promoted") else ""
            ctx = f" — {pin['context']}" if pin.get("context") else ""
            lines.append(f"- **[{label}{ioc_suffix}]** `{pin['value']}`{ctx}{promoted_suffix}")
    else:
        lines.append("*(no findings pinned)*")
    lines.append("")

    # --- Conversation Transcript ---
    lines.append("## Conversation Transcript")
    lines.append("")
    for msg in messages:
        role = msg["role"]
        content = msg.get("content") or ""
        tool_name = msg.get("tool_name") or ""

        if role == "user":
            lines.append("### Analyst")
            lines.append("")
            lines.append(content)
            lines.append("")
        elif role == "assistant":
            lines.append("### Agent")
            lines.append("")
            lines.append(content)
            lines.append("")
        elif role == "tool_call":
            # Show tool name and args as a blockquote
            try:
                data = json.loads(content) if content else {}
            except (json.JSONDecodeError, TypeError):
                data = {"raw": content}
            args_str = json.dumps(data.get("args", data), indent=2)
            lines.append(f"> **Tool:** `{tool_name}` — args")
            lines.append(f"> ```json")
            for arg_line in args_str.splitlines():
                lines.append(f"> {arg_line}")
            lines.append(f"> ```")
            lines.append("")
        elif role == "tool_result":
            # Show result as a truncated JSON code block in a blockquote
            try:
                data = json.loads(content) if content else {}
            except (json.JSONDecodeError, TypeError):
                data = {"raw": content}
            result_str = json.dumps(data, indent=2, default=str)
            if len(result_str) > 2000:
                result_str = result_str[:2000] + "\n... [truncated]"
            lines.append(f"> **Result:** `{tool_name}`")
            lines.append(f"> ```json")
            for res_line in result_str.splitlines():
                lines.append(f"> {res_line}")
            lines.append(f"> ```")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Endpoint 1: POST /{analysis_id}/sessions — create session
# ---------------------------------------------------------------------------


@router.post("/{analysis_id}/sessions", status_code=201)
def create_session(
    analysis_id: int,
    auth: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_session),
) -> dict:
    """Create a new investigation session for an analysis. Requires analyst role."""
    # Verify analysis exists
    row = db.exec(text("SELECT id FROM analyses WHERE id = :aid"), params={"aid": analysis_id}).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Analysis {analysis_id} not found")

    session = InvestigationSession(
        analysis_id=analysis_id,
        user_sub=auth.user_id,
        max_turns=settings.investigation_max_turns,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    log_audit(
        db, auth,
        action="investigation_start",
        resource_type="investigation_session",
        resource_id=str(session.id),
        details={"analysis_id": analysis_id},
    )

    return {
        "id": session.id,
        "analysis_id": session.analysis_id,
        "model": session.model,
        "status": session.status,
        "created_at": session.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Endpoint 2: GET /{analysis_id}/sessions — list sessions
# ---------------------------------------------------------------------------


@router.get("/{analysis_id}/sessions")
def list_sessions(
    analysis_id: int,
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_session),
) -> dict:
    """List all investigation sessions for an analysis, newest first."""
    sessions = db.exec(
        select(InvestigationSession)
        .where(InvestigationSession.analysis_id == analysis_id)
        .order_by(col(InvestigationSession.created_at).desc())
    ).all()

    return {
        "sessions": [
            {
                "id": s.id,
                "status": s.status,
                "model": s.model,
                "total_cost_usd": float(s.total_cost_usd),
                "created_at": s.created_at.isoformat(),
                "updated_at": s.updated_at.isoformat(),
            }
            for s in sessions
        ]
    }


# ---------------------------------------------------------------------------
# Endpoint 3: GET /sessions/{session_id} — full session detail
# ---------------------------------------------------------------------------


@router.get("/sessions/{session_id}")
def get_session(
    session_id: int,
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_session),
) -> dict:
    """Full session detail with messages and pins."""
    session = db.get(InvestigationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    messages = db.exec(
        select(InvestigationMessage)
        .where(InvestigationMessage.session_id == session_id)
        .order_by(InvestigationMessage.created_at, InvestigationMessage.id)
    ).all()

    pins = db.exec(
        select(InvestigationPin)
        .where(InvestigationPin.session_id == session_id)
        .order_by(InvestigationPin.created_at)
    ).all()

    return {
        "id": session.id,
        "analysis_id": session.analysis_id,
        "user_sub": session.user_sub,
        "model": session.model,
        "status": session.status,
        "total_input_tokens": session.total_input_tokens,
        "total_output_tokens": session.total_output_tokens,
        "total_cost_usd": float(session.total_cost_usd),
        "max_turns": session.max_turns,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat(),
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "tool_name": m.tool_name,
                "created_at": m.created_at.isoformat(),
            }
            for m in messages
        ],
        "pins": [
            {
                "id": p.id,
                "pin_type": p.pin_type,
                "value": p.value,
                "ioc_type": p.ioc_type,
                "context": p.context,
                "promoted": p.promoted,
                "created_at": p.created_at.isoformat(),
            }
            for p in pins
        ],
    }


# ---------------------------------------------------------------------------
# Endpoint 4: POST /{analysis_id}/message — SSE streaming endpoint
# ---------------------------------------------------------------------------


@router.post("/{analysis_id}/message")
async def send_message(
    analysis_id: int,
    body: dict,
    auth: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_session),
) -> StreamingResponse:
    """
    Send a user message to the investigation agent and stream the response via SSE.

    Each SSE event has the form:
        event: <type>\\ndata: <json>\\n\\n

    Event types: token, tool_call, tool_result, pin_proposal, done, error
    """
    session_id = body.get("session_id")
    content = body.get("content", "").strip() if body.get("content") else ""

    if not session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    if not content:
        raise HTTPException(status_code=400, detail="content is required and must not be blank")

    session = db.get(InvestigationSession, session_id)
    if session is None or session.analysis_id != analysis_id:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found for analysis {analysis_id}")

    if session.status != "active":
        raise HTTPException(status_code=400, detail=f"Session is not active (status: {session.status})")

    # Check turn limit: count existing user-role messages
    user_turn_count = db.exec(
        select(InvestigationMessage)
        .where(
            InvestigationMessage.session_id == session_id,
            InvestigationMessage.role == "user",
        )
    ).all()
    if len(user_turn_count) >= session.max_turns:
        raise HTTPException(status_code=400, detail="Turn limit reached")

    # Persist the user message immediately so it's in the DB before streaming starts
    user_msg = InvestigationMessage(
        session_id=session_id,
        role="user",
        content=content,
    )
    db.add(user_msg)
    db.commit()

    # Rebuild conversation history for the LLM: only user and assistant rows.
    # Tool_call and tool_result rows are stored for transcript/audit/UI display
    # but are NOT replayed to the LLM. The assistant's final text already
    # synthesizes what tools found; replaying raw tool exchanges would require
    # fragile OpenAI-format reconstruction and would balloon prompt token costs.
    history_rows = db.exec(
        select(InvestigationMessage)
        .where(
            InvestigationMessage.session_id == session_id,
            col(InvestigationMessage.role).in_(["user", "assistant"]),
        )
        .order_by(InvestigationMessage.created_at, InvestigationMessage.id)
    ).all()
    messages = [{"role": m.role, "content": m.content} for m in history_rows]

    # Load analysis report JSON (may be None → empty dict)
    report_row = db.exec(
        text("SELECT report_json FROM analyses WHERE id = :aid"),
        params={"aid": analysis_id},
    ).first()
    report: dict = {}
    if report_row and report_row[0]:
        raw = report_row[0]
        if isinstance(raw, dict):
            report = raw
        else:
            try:
                report = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                report = {}

    system_prompt = build_system_prompt(analysis_id, db)
    model = session.model

    async def event_stream():
        assistant_content = ""

        try:
            async for event in run_conversation_turn(messages, system_prompt, model, db, report, analysis_id):
                etype = event["event"]
                edata = event["data"]

                if etype == "token":
                    # Accumulate assistant text; do NOT write to DB per-token
                    assistant_content += edata.get("content", "")

                elif etype == "tool_call":
                    tool_msg = InvestigationMessage(
                        session_id=session_id,
                        role="tool_call",
                        content=json.dumps(edata, default=str),
                        tool_name=edata.get("tool"),
                    )
                    db.add(tool_msg)
                    db.commit()

                elif etype == "tool_result":
                    result_msg = InvestigationMessage(
                        session_id=session_id,
                        role="tool_result",
                        content=json.dumps(edata, default=str),
                        tool_name=edata.get("tool"),
                    )
                    db.add(result_msg)
                    db.commit()

                elif etype == "pin_proposal":
                    # No DB write — UI handles confirmation via POST /pin
                    pass

                elif etype == "error":
                    # No DB write — just forward to the client
                    pass

                elif etype == "done":
                    # Save the accumulated assistant response
                    input_tokens = edata.get("input_tokens", 0)
                    output_tokens = edata.get("output_tokens", 0)
                    cost = edata.get("cost", 0.0)

                    asst_msg = InvestigationMessage(
                        session_id=session_id,
                        role="assistant",
                        content=assistant_content,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                    )
                    db.add(asst_msg)

                    # Update session token totals and cost
                    session.total_input_tokens += input_tokens
                    session.total_output_tokens += output_tokens
                    session.total_cost_usd += Decimal(str(cost))
                    session.updated_at = datetime.now(timezone.utc)
                    db.add(session)
                    db.commit()

                    # Attach cost alert flag before forwarding to client
                    cost_alert = session.total_cost_usd >= Decimal(
                        str(settings.investigation_cost_alert_usd)
                    )
                    edata = {**edata, "cost_alert": cost_alert}

                yield f"event: {etype}\ndata: {json.dumps(edata, default=str)}\n\n"

        except Exception:
            log.exception(
                "Unexpected error in investigation event_stream session=%s analysis=%s",
                session_id,
                analysis_id,
            )
            error_payload = json.dumps({"message": "Internal server error in agent stream"})
            yield f"event: error\ndata: {error_payload}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Endpoint 5: POST /sessions/{session_id}/pin — confirm a pin
# ---------------------------------------------------------------------------


@router.post("/sessions/{session_id}/pin", status_code=201)
def confirm_pin(
    session_id: int,
    body: dict,
    auth: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_session),
) -> dict:
    """Confirm and save an analyst-pinned finding from a session."""
    session = db.get(InvestigationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    error = _validate_pin_body(body)
    if error:
        raise HTTPException(status_code=400, detail=error)

    pin = InvestigationPin(
        session_id=session_id,
        analysis_id=session.analysis_id,
        pin_type=body["type"],
        value=body["value"],
        ioc_type=body.get("ioc_type"),
        context=body.get("context") or "",
    )
    db.add(pin)
    db.commit()
    db.refresh(pin)

    return {"id": pin.id, "status": "confirmed"}


# ---------------------------------------------------------------------------
# Endpoint 6: POST /sessions/{session_id}/pin/{pin_id}/promote
# ---------------------------------------------------------------------------


@router.post("/sessions/{session_id}/pin/{pin_id}/promote")
def promote_pin(
    session_id: int,
    pin_id: int,
    auth: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_session),
) -> dict:
    """
    Promote a pinned finding to the analysis record.

    IOC pins are upserted into ioc_values and linked via analysis_iocs.
    Technique pins: technique_values has a NOT NULL tactics column with no
    default, so promotion requires knowing the tactics array. Since pin data
    only carries technique ID/value (not tactics), we skip DB upsert for
    technique pins but still mark them promoted — the pin record captures the
    finding, and an analyst can manually add to analysis_techniques if needed.
    Note pins have no corresponding normalised table; they are marked promoted
    to indicate the analyst has reviewed and acknowledged them.
    """
    pin = db.get(InvestigationPin, pin_id)
    if pin is None or pin.session_id != session_id:
        raise HTTPException(status_code=404, detail=f"Pin {pin_id} not found for session {session_id}")

    if pin.promoted:
        return {"status": "already_promoted"}

    if pin.pin_type == "ioc" and pin.ioc_type:
        # Upsert the IOC value — (type, value) is UNIQUE in ioc_values
        db.exec(
            text(
                "INSERT INTO ioc_values (type, value) "
                "VALUES (:type, :value) "
                "ON CONFLICT (type, value) DO NOTHING"
            ),
            params={"type": pin.ioc_type, "value": pin.value},
        )
        # Fetch the canonical ioc_values.id (whether just inserted or pre-existing)
        ioc_row = db.exec(
            text("SELECT id FROM ioc_values WHERE type = :type AND value = :value"),
            params={"type": pin.ioc_type, "value": pin.value},
        ).first()
        ioc_id = ioc_row[0]

        # Link to the analysis — analysis_iocs UNIQUE(analysis_id, ioc_id, source_stage)
        # context column allows NULL per schema; confidence has DEFAULT 'high'.
        db.exec(
            text(
                "INSERT INTO analysis_iocs (analysis_id, ioc_id, source_stage, confidence) "
                "VALUES (:analysis_id, :ioc_id, :source_stage, :confidence) "
                "ON CONFLICT (analysis_id, ioc_id, source_stage) DO NOTHING"
            ),
            params={
                "analysis_id": pin.analysis_id,
                "ioc_id": ioc_id,
                "source_stage": "Investigation",
                "confidence": "high",
            },
        )

    elif pin.pin_type == "technique":
        # technique_values.tactics is VARCHAR[] NOT NULL with no DEFAULT.
        # Promotion would require us to supply a tactics array we don't have in
        # the pin record, and guessing '{}'::varchar[] would produce misleading
        # data. We mark the pin promoted (it's captured in investigation_pins)
        # but skip the technique_values / analysis_techniques upsert.
        # Analysts who want this in analysis_techniques should add it manually.
        log.info(
            "Technique pin %d promoted (recorded in pins only — "
            "technique_values upsert skipped: tactics column is NOT NULL with no default)",
            pin_id,
        )

    # pin_type == "note": nothing to promote into normalised tables; mark promoted.

    pin.promoted = True
    db.add(pin)
    db.commit()

    log_audit(
        db, auth,
        action="pin_promoted",
        resource_type="investigation_pin",
        resource_id=str(pin_id),
        details={
            "session_id": session_id,
            "analysis_id": pin.analysis_id,
            "pin_type": pin.pin_type,
            "value": pin.value,
        },
    )

    return {"status": "promoted"}


# ---------------------------------------------------------------------------
# Endpoint 7: POST /sessions/{session_id}/model — update model
# ---------------------------------------------------------------------------


@router.post("/sessions/{session_id}/model")
def update_model(
    session_id: int,
    body: dict,
    auth: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_session),
) -> dict:
    """Switch the LLM model for a session. Must be one of VALID_MODELS."""
    session = db.get(InvestigationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    model = body.get("model")
    if model not in VALID_MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid model {model!r}. Must be one of: {VALID_MODELS}",
        )

    session.model = model
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)
    db.commit()

    return {"model": model}


# ---------------------------------------------------------------------------
# Endpoint 8: POST /sessions/{session_id}/complete — mark session complete
# ---------------------------------------------------------------------------


@router.post("/sessions/{session_id}/complete")
def complete_session(
    session_id: int,
    auth: AuthContext = Depends(require_role("analyst")),
    db: Session = Depends(get_session),
) -> dict:
    """Mark an investigation session as completed."""
    session = db.get(InvestigationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    session.status = "completed"
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)
    db.commit()

    return {"status": "completed"}


# ---------------------------------------------------------------------------
# Endpoint 9: GET /sessions/{session_id}/report — markdown export
# ---------------------------------------------------------------------------


@router.get("/sessions/{session_id}/report")
def get_session_report(
    session_id: int,
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_session),
) -> dict:
    """Export session as a markdown document with findings and transcript."""
    session = db.get(InvestigationSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    messages = db.exec(
        select(InvestigationMessage)
        .where(InvestigationMessage.session_id == session_id)
        .order_by(InvestigationMessage.created_at, InvestigationMessage.id)
    ).all()

    pins = db.exec(
        select(InvestigationPin)
        .where(InvestigationPin.session_id == session_id)
        .order_by(InvestigationPin.created_at)
    ).all()

    session_dict = {
        "id": session.id,
        "analysis_id": session.analysis_id,
        "model": session.model,
        "total_cost_usd": float(session.total_cost_usd),
        "created_at": session.created_at.isoformat(),
    }
    messages_dicts = [
        {
            "id": m.id,
            "role": m.role,
            "content": m.content,
            "tool_name": m.tool_name,
            "created_at": m.created_at.isoformat(),
        }
        for m in messages
    ]
    pins_dicts = [
        {
            "id": p.id,
            "pin_type": p.pin_type,
            "value": p.value,
            "ioc_type": p.ioc_type,
            "context": p.context,
            "promoted": p.promoted,
            "created_at": p.created_at.isoformat(),
        }
        for p in pins
    ]

    markdown = _build_report_markdown(session_dict, messages_dicts, pins_dicts)
    return {"markdown": markdown}
