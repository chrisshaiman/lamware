# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Sample submission endpoint.
#
# Accepts a multipart file upload, saves it to a spool directory. A systemd
# path unit watches the spool and triggers the pipeline as the `pipeline` user.
# Returns immediately — clients poll /api/pipeline/status for progress.
#
# This design maintains the security boundary: the API (lamware-api) writes
# files, the pipeline (pipeline user) processes them. No sudo, no privilege
# escalation.

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from sqlmodel import Session

from ..auth import AuthContext, require_role
from ..audit import log_audit
from ..database import get_session

router = APIRouter(prefix="/api/samples", tags=["samples"])

# Max upload size: 100 MB.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024

# Spool directory for uploaded samples. Owned by lamware-api:lamware.
# Pipeline user reads via lamware group membership.
SPOOL_DIR = Path("/opt/pipeline/spool")


@router.post("/submit")
async def submit_sample(
    file: UploadFile,
    auth: AuthContext = Depends(require_role("analyst")),
    session: Session = Depends(get_session),
) -> dict:
    """
    Submit a sample file for analysis.

    Saves the upload to a spool directory. A systemd path unit detects the
    new file and launches the pipeline as the pipeline user. Returns
    immediately — poll /api/pipeline/status for progress.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename is required")

    safe_name = Path(file.filename).name[:200]
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid filename")

    submission_id = str(uuid.uuid4())
    tmp_path = SPOOL_DIR / f"{submission_id}_{safe_name}"

    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read upload: {exc}") from exc

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds maximum size of {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
        )

    try:
        SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        tmp_path.write_bytes(content)
        tmp_path.chmod(0o640)
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to save upload: {exc}"
        ) from exc

    log_audit(
        session, auth,
        action="sample_submit",
        resource_type="sample",
        resource_id=submission_id,
        details={"filename": safe_name, "size_bytes": len(content)},
    )

    return {
        "status": "submitted",
        "submission_id": submission_id,
        "filename": safe_name,
        "size_bytes": len(content),
        "submitted_by": auth.email,
        "message": "Sample queued. Poll /api/pipeline/status for progress.",
    }
