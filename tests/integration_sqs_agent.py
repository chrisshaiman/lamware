"""
Integration test for the SQS agent's poll -> download flow.

Submits a test job via the API, then polls SQS and downloads the sample
from S3 — verifying the bare metal agent's receive path without Cape.

Usage:
    API_ENDPOINT=https://xxx.execute-api.us-east-1.amazonaws.com \
    SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/xxx/queue-name \
    SAMPLES_BUCKET=malware-sandbox-samples-xxx \
    python integration_sqs_agent.py

Requires AWS credentials with execute-api:Invoke, sqs:*, s3:GetObject.

Author: Christopher Shaiman
License: Apache 2.0
"""
import hashlib
import json
import os
import sys
import tempfile
import time

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def submit_sample(api_endpoint, region, creds):
    """Phase 1: POST /submit to get upload credentials."""
    submit_url = f"{api_endpoint.rstrip('/')}/submit"
    body = json.dumps({
        "filename": "eicar-test.com",
        "sha256": EICAR_SHA256,
        "tags": ["test", "eicar", "sqs-agent-test"],
    })

    aws_req = AWSRequest(
        method="POST", url=submit_url, data=body,
        headers={"Content-Type": "application/json"},
    )
    SigV4Auth(creds, "execute-api", region).add_auth(aws_req)

    r = requests.post(submit_url, data=body, headers=dict(aws_req.headers))
    assert r.status_code == 200, f"POST /submit failed: {r.status_code} {r.text}"
    return r.json()


def upload_sample(resp):
    """Phase 2: Upload via presigned POST."""
    r = requests.post(
        resp["upload_url"],
        data=resp["upload_fields"],
        files={"file": ("eicar-test.com", EICAR_BYTES)},
    )
    assert r.status_code == 204, f"Upload failed: {r.status_code} {r.text[:200]}"


def poll_and_download(sqs_queue_url, samples_bucket, region, expected_task_id):
    """Simulate the SQS agent: poll for the job, download sample from S3."""
    sqs = boto3.client("sqs", region_name=region)
    s3 = boto3.client("s3", region_name=region)

    print("\n=== SQS Agent Simulation ===")
    print(f"Polling queue...")

    # Poll for up to 30s
    message = None
    for _ in range(3):
        resp = sqs.receive_message(
            QueueUrl=sqs_queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
        )
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            if body.get("task_id") == expected_task_id:
                message = m
                break
        if message:
            break

    if not message:
        print("  FAIL: No SQS message found for this task_id")
        return False

    body = json.loads(message["Body"])
    print(f"  Received job:")
    print(f"    task_id:      {body['task_id']}")
    print(f"    sha256:       {body['sha256']}")
    print(f"    s3_key:       {body['s3_key']}")
    print(f"    tags:         {body.get('tags', [])}")
    print(f"    submitted_at: {body['submitted_at']}")

    # Download sample from S3
    s3_key = body["s3_key"]
    print(f"\n  Downloading s3://{samples_bucket}/{s3_key} ...")
    with tempfile.NamedTemporaryFile(delete=False, suffix="_eicar-test.com") as tmp:
        s3.download_fileobj(samples_bucket, s3_key, tmp)
        tmp_path = tmp.name

    with open(tmp_path, "rb") as f:
        content = f.read()

    actual_sha256 = hashlib.sha256(content).hexdigest()
    print(f"  Downloaded {len(content)} bytes")
    print(f"  SHA256 verify: {actual_sha256}")
    print(f"  SHA256 match:  {'PASS' if actual_sha256 == body['sha256'] else 'FAIL'}")

    os.unlink(tmp_path)

    # At this point the real agent would submit to Cape.
    print("\n  [Skipping Cape submission — no Cape running]")

    sqs.delete_message(
        QueueUrl=sqs_queue_url,
        ReceiptHandle=message["ReceiptHandle"],
    )
    print("  SQS message deleted")

    return actual_sha256 == body["sha256"]


def main():
    api_endpoint = os.environ.get("API_ENDPOINT")
    sqs_queue_url = os.environ.get("SQS_QUEUE_URL")
    samples_bucket = os.environ.get("SAMPLES_BUCKET")
    region = os.environ.get("AWS_REGION", "us-east-1")

    missing = []
    if not api_endpoint:
        missing.append("API_ENDPOINT")
    if not sqs_queue_url:
        missing.append("SQS_QUEUE_URL")
    if not samples_bucket:
        missing.append("SAMPLES_BUCKET")
    if missing:
        print(f"ERROR: Set environment variables: {', '.join(missing)}")
        sys.exit(1)

    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()

    # Step 1: Submit sample via API
    print("=== Step 1: Submit sample ===")
    resp = submit_sample(api_endpoint, region, creds)
    task_id = resp["task_id"]
    print(f"  task_id: {task_id}")
    print(f"  s3_key:  {resp['s3_key']}")

    # Step 2: Upload sample
    print("\n=== Step 2: Upload sample ===")
    upload_sample(resp)
    print("  Upload OK")

    # Step 3: Wait for Lambda to process S3 event
    print("\n=== Step 3: Waiting for S3 event processing ===")
    time.sleep(3)

    # Step 4: Poll SQS and download (simulating the bare metal agent)
    success = poll_and_download(sqs_queue_url, samples_bucket, region, task_id)

    # Summary
    print("\n=== Results ===")
    print("  API submit + S3 upload:  PASS")
    print(f"  SQS receive + S3 download + SHA256 verify: {'PASS' if success else 'FAIL'}")


if __name__ == "__main__":
    main()
