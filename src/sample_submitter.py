"""
sample_submitter — Lambda handler
Called by API Gateway v2 (POST /submit) and by S3 ObjectCreated events.

Two-phase flow (eliminates the race where the agent could dequeue a job
before the client finishes uploading the sample):

  Phase 1 — API GW POST /submit {"filename": "...", "sha256": "...", "tags": [...]}
    → validate + sanitize request body
    → generate task_id (UUID4)
    → construct S3 key: samples/{sha256}/{task_id}/{filename}
    → issue pre-signed S3 PUT URL with job metadata embedded in the signature
      (task_id, sha256, tags — client MUST send x-amz-meta-* headers)
    → return {task_id, upload_url, expires_in, s3_key}

  Phase 2 — S3 ObjectCreated on samples/{sha256}/{task_id}/{filename}
    → read job metadata from the uploaded object (task_id, sha256, tags)
    → publish SQS job {task_id, s3_key, sha256, tags, submitted_at}

The SQS job is only enqueued after S3 confirms the object exists, so the bare
metal agent can never receive a job for a sample that has not yet been uploaded.

Environment variables (set by Terraform):
  SAMPLES_BUCKET      — S3 bucket name for sample uploads
  SQS_QUEUE_URL       — SQS job queue URL
  AWS_REGION_NAME     — AWS region

Author: Christopher Shaiman
License: Apache 2.0
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import uuid

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PRESIGNED_URL_TTL_SECONDS = 900  # 15 minutes — enough time for client to upload
MAX_TAGS = 10
MAX_TAG_LENGTH = 64
MAX_FILENAME_LENGTH = 255

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Initialise clients at module level — reused across warm Lambda invocations
_s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION_NAME", "us-east-1"))
_sqs = boto3.client("sqs", region_name=os.environ.get("AWS_REGION_NAME", "us-east-1"))


def handler(event: dict, context: object) -> dict | None:
    """
    Entry point. Routes between the two event sources:
      - API Gateway v2 (POST /submit): validate and return pre-signed upload URL
      - S3 ObjectCreated (samples/ prefix): enqueue the analysis job on SQS
    """
    if _is_s3_event(event):
        _handle_s3_event(event, context)
        return None  # S3 event triggers don't expect a return value
    return _handle_api_request(event, context)


# -----------------------------------------------------------------------------
# Phase 1 — API Gateway handler
# -----------------------------------------------------------------------------

def _handle_api_request(event: dict, context: object) -> dict:
    """
    API Gateway path. Validates the request, issues a pre-signed S3 PUT URL
    with job metadata embedded in the signature, and returns immediately.
    The SQS job is enqueued by Phase 2 when the upload completes.
    """
    logger.info("sample_submitter: API request", extra={"request_id": context.aws_request_id})

    try:
        body = _parse_body(event)
    except ValueError as exc:
        return _error(400, str(exc))

    try:
        filename, sha256, tags = _validate(body)
    except ValueError as exc:
        return _error(400, str(exc))

    task_id = str(uuid.uuid4())
    # task_id in path prevents collision if the same sha256+filename is submitted twice
    s3_key = f"samples/{sha256}/{task_id}/{filename}"

    try:
        upload_url = _presigned_put_url(
            os.environ["SAMPLES_BUCKET"], s3_key, task_id, sha256, tags
        )
    except ClientError:
        logger.exception("Failed to generate pre-signed URL", extra={"s3_key": s3_key})
        return _error(500, "Failed to generate upload URL")

    logger.info(
        "Sample submission accepted — awaiting upload",
        extra={"task_id": task_id, "sha256": sha256, "s3_key": s3_key, "tags": tags},
    )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "task_id": task_id,
            "upload_url": upload_url,
            "expires_in": PRESIGNED_URL_TTL_SECONDS,
            "s3_key": s3_key,
        }),
    }


# -----------------------------------------------------------------------------
# Phase 2 — S3 event handler
# -----------------------------------------------------------------------------

def _handle_s3_event(event: dict, context: object) -> None:
    """
    S3 ObjectCreated path. Fired when a sample lands in the samples/ prefix.
    Reads job metadata from the S3 object (embedded by the presigned URL), then
    enqueues the SQS analysis job. Guaranteed to run only after upload completes.
    """
    logger.info("sample_submitter: S3 event", extra={"request_id": context.aws_request_id})

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        s3_key = record["s3"]["object"]["key"]

        if not s3_key.startswith("samples/"):
            logger.warning("Ignoring S3 event for unexpected key prefix: %s", s3_key)
            continue

        logger.info("Sample uploaded — enqueuing job: s3://%s/%s", bucket, s3_key)

        try:
            head = _s3.head_object(Bucket=bucket, Key=s3_key)
            metadata = head.get("Metadata", {})

            task_id = metadata.get("task-id")
            sha256 = metadata.get("sha256")
            tags_raw = metadata.get("tags", "[]")

            if not task_id or not sha256:
                logger.error(
                    "Sample uploaded without required metadata (task-id, sha256) "
                    "— cannot enqueue job. s3_key=%s",
                    s3_key,
                )
                continue

            try:
                tags = json.loads(tags_raw)
            except json.JSONDecodeError:
                logger.warning("Could not parse tags metadata — defaulting to []: %s", tags_raw)
                tags = []

            _enqueue_job(task_id, s3_key, sha256, tags)
            logger.info("Enqueued analysis job: task_id=%s sha256=%s", task_id, sha256)

        except ClientError:
            logger.exception("Failed to process S3 event for key %s", s3_key)


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------

def _is_s3_event(event: dict) -> bool:
    """Return True if the event originated from S3."""
    records = event.get("Records", [])
    return bool(records) and records[0].get("eventSource") == "aws:s3"


def _parse_body(event: dict) -> dict:
    """Extract and parse the JSON request body from an API Gateway v2 event."""
    raw = event.get("body")
    if not raw:
        raise ValueError("Request body is required")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("Request body must be valid JSON")


def _validate(body: dict) -> tuple[str, str, list[str]]:
    """
    Validate and sanitize submission fields.

    Returns:
        Tuple of (filename, sha256, tags).

    Raises:
        ValueError: if any field is missing, malformed, or out of range.
    """
    # filename — required; strip path components to prevent traversal
    filename = body.get("filename")
    if not filename or not isinstance(filename, str):
        raise ValueError("'filename' is required and must be a string")
    filename = os.path.basename(filename.strip())
    if not filename:
        raise ValueError("'filename' must not be empty after path sanitization")
    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValueError(f"'filename' must be {MAX_FILENAME_LENGTH} characters or fewer")

    # sha256 — required; must be exactly 64 lowercase hex characters
    sha256 = body.get("sha256")
    if not sha256 or not isinstance(sha256, str):
        raise ValueError("'sha256' is required and must be a string")
    sha256 = sha256.lower().strip()
    if not _SHA256_RE.match(sha256):
        raise ValueError("'sha256' must be a 64-character hex string")

    # tags — optional list of short strings
    tags = body.get("tags", [])
    if not isinstance(tags, list):
        raise ValueError("'tags' must be a list of strings")
    if len(tags) > MAX_TAGS:
        raise ValueError(f"'tags' must contain {MAX_TAGS} items or fewer")
    for tag in tags:
        if not isinstance(tag, str):
            raise ValueError("Each tag must be a string")
        if len(tag) > MAX_TAG_LENGTH:
            raise ValueError(f"Each tag must be {MAX_TAG_LENGTH} characters or fewer")

    return filename, sha256, tags


def _presigned_put_url(
    bucket: str, key: str, task_id: str, sha256: str, tags: list[str]
) -> str:
    """
    Generate a pre-signed S3 PUT URL with job metadata embedded in the signature.

    The Metadata dict is included in the signature — the client MUST send the
    corresponding x-amz-meta-* headers or S3 will reject the PUT with a 403.
    This guarantees the metadata is always present when the S3 event fires.
    """
    return _s3.generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket,
            "Key": key,
            "Metadata": {
                "task-id": task_id,
                "sha256": sha256,
                "tags": json.dumps(tags),
            },
        },
        ExpiresIn=PRESIGNED_URL_TTL_SECONDS,
    )


def _enqueue_job(task_id: str, s3_key: str, sha256: str, tags: list[str]) -> None:
    """Publish an analysis job to the SQS job queue."""
    _sqs.send_message(
        QueueUrl=os.environ["SQS_QUEUE_URL"],
        MessageBody=json.dumps({
            "task_id": task_id,
            "s3_key": s3_key,
            "sha256": sha256,
            "tags": tags,
            # submitted_at lets the sqs-agent and report_processor correlate job age
            "submitted_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }),
    )


def _error(status_code: int, message: str) -> dict:
    """Return an API Gateway-compatible error response."""
    logger.warning("Returning error response", extra={"status_code": status_code, "error_message": message})
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": message}),
    }
