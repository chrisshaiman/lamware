"""
sample_submitter — Lambda handler
Called by API Gateway (POST /submit). Accepts a sample submission request,
issues a pre-signed S3 URL for direct upload, and enqueues an analysis job.

Flow:
  API GW POST /submit  {filename, sha256, tags}
    → validate request
    → generate pre-signed S3 PUT URL (client uploads directly to S3)
    → publish SQS job {task_id, s3_key, sha256, tags}
    → return {task_id, upload_url}

Environment variables (set by Terraform):
  SAMPLES_BUCKET      — S3 bucket name for sample uploads
  SQS_QUEUE_URL       — SQS job queue URL
  CAPE_API_SECRET_ARN — Secrets Manager ARN for Cape API key (reserved for future use)
  AWS_REGION_NAME     — AWS region

Author: Christopher Shaiman
License: Apache 2.0
"""

from __future__ import annotations

import json
import logging
import os
import uuid

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PRESIGNED_URL_TTL_SECONDS = 900  # 15 minutes — enough time for client to upload


def handler(event: dict, context: object) -> dict:
    """
    Entry point. Validates the submission request, issues a pre-signed upload URL,
    and enqueues an analysis job on SQS.

    Args:
        event:   API Gateway HTTP event (v2 payload format)
        context: Lambda context object

    Returns:
        API Gateway-compatible response dict with statusCode and body.
    """
    logger.info("sample_submitter invoked")

    # TODO: parse and validate request body {filename, sha256, tags}
    # TODO: generate a task_id (UUID)
    # TODO: construct S3 key: samples/{sha256}/{filename}
    # TODO: generate pre-signed PUT URL via boto3 S3 client
    # TODO: publish SQS message {task_id, s3_key, sha256, tags}
    # TODO: return {task_id, upload_url, expires_in}

    logger.warning("sample_submitter is a stub — no submission processed")

    task_id = str(uuid.uuid4())

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "task_id": task_id,
            "message": "stub — not yet implemented",
        }),
    }


def _generate_presigned_upload_url(bucket: str, key: str, ttl: int = PRESIGNED_URL_TTL_SECONDS) -> str:
    """Generate a pre-signed S3 PUT URL for direct client upload."""
    s3 = boto3.client("s3", region_name=os.environ["AWS_REGION_NAME"])
    return s3.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=ttl,
    )


def _enqueue_job(task_id: str, s3_key: str, sha256: str, tags: list[str]) -> None:
    """Publish an analysis job to the SQS job queue."""
    sqs = boto3.client("sqs", region_name=os.environ["AWS_REGION_NAME"])
    sqs.send_message(
        QueueUrl=os.environ["SQS_QUEUE_URL"],
        MessageBody=json.dumps({
            "task_id": task_id,
            "s3_key": s3_key,
            "sha256": sha256,
            "tags": tags,
        }),
    )
