# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Sample submission endpoint.
#
# Accepts a multipart file upload, saves it to a temp directory, then
# launches the pipeline command in a background subprocess. Returns
# immediately with a submitted status — clients poll /api/pipeline/status
# for progress.
#
# The pipeline command (settings.pipeline_cmd) is expected to accept a file
# path as its first positional argument:
#
#   /usr/local/bin/run-pipeline /tmp/uploads/<filename>
#
# subprocess.Popen is used (not subprocess.run) so the call is non-blocking.
# The child process is detached from this process's stdin/stdout.

import subprocess
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile

from ..auth import require_api_key
from ..config import settings

router = APIRouter(prefix="/api/samples", tags=["samples"])

# Max upload size: 100 MB. FastAPI doesn't enforce this at the middleware
# level by default, so we check after reading into the temp file.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


@router.post("/submit")
async def submit_sample(
    file: UploadFile,
    _auth: dict = Depends(require_api_key),
) -> dict:
    """
    Submit a sample file for analysis.

    Saves the upload to a temp file and launches the pipeline in a background
    subprocess. Returns immediately — poll /api/pipeline/status for progress.

    The response includes a submission_id (random UUID) for tracking this
    specific API call. It is NOT the pipeline task_id — that is assigned by
    the pipeline and visible in /api/pipeline/status once the run starts.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="filename is required")

    # Sanitise the original filename — strip directory components and limit
    # length so we can safely use it as part of a filesystem path.
    safe_name = Path(file.filename).name[:200]
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Write upload to a unique temp file. Using NamedTemporaryFile with
    # delete=False so the pipeline process can open it after we close it.
    submission_id = str(uuid.uuid4())
    tmp_dir = tempfile.gettempdir()
    tmp_path = Path(tmp_dir) / f"{submission_id}_{safe_name}"

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
        tmp_path.write_bytes(content)
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to save upload: {exc}"
        ) from exc

    # Launch the pipeline in the background. Popen returns immediately;
    # the child runs independently. We capture no output — the pipeline
    # writes its own logs.
    try:
        proc = subprocess.Popen(  # noqa: S603 — cmd and path are not user-controlled
            [settings.pipeline_cmd, str(tmp_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline command not found: {settings.pipeline_cmd}",
        ) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=500, detail=f"Failed to launch pipeline: {exc}"
        ) from exc

    return {
        "status": "submitted",
        "submission_id": submission_id,
        "filename": safe_name,
        "size_bytes": len(content),
        "pipeline_pid": proc.pid,
        "message": "Sample queued. Poll /api/pipeline/status for progress.",
    }
