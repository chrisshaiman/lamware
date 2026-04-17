"""
End-to-end pipeline test: POST /submit -> S3 upload -> SQS message.

Usage:
    python test_pipeline_e2e.py

Reads configuration from environment variables (set in .env or shell):
    API_ENDPOINT   — API Gateway base URL (e.g. https://xxx.execute-api.us-east-1.amazonaws.com)
    SQS_QUEUE_URL  — SQS job queue URL
    AWS_REGION     — AWS region (default: us-east-1)

Requires AWS credentials with execute-api:Invoke and sqs:ReceiveMessage.

Author: Christopher Shaiman
License: Apache 2.0
"""
import json
import os
import sys
import time

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def main():
    api_endpoint = os.environ.get("API_ENDPOINT")
    sqs_queue_url = os.environ.get("SQS_QUEUE_URL")
    region = os.environ.get("AWS_REGION", "us-east-1")

    if not api_endpoint or not sqs_queue_url:
        print("ERROR: Set API_ENDPOINT and SQS_QUEUE_URL environment variables")
        sys.exit(1)

    submit_url = f"{api_endpoint.rstrip('/')}/submit"

    session = boto3.Session()
    creds = session.get_credentials().get_frozen_credentials()

    # --- Phase 1: POST /submit ---
    body = json.dumps({
        "filename": "eicar-test.com",
        "sha256": EICAR_SHA256,
        "tags": ["test", "eicar"],
    })

    aws_req = AWSRequest(
        method="POST", url=submit_url, data=body,
        headers={"Content-Type": "application/json"},
    )
    SigV4Auth(creds, "execute-api", region).add_auth(aws_req)

    r = requests.post(submit_url, data=body, headers=dict(aws_req.headers))
    print(f"Phase 1 — POST /submit: {r.status_code}")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    resp = r.json()
    task_id = resp["task_id"]
    s3_key = resp["s3_key"]
    print(f"  task_id:  {task_id}")
    print(f"  s3_key:   {s3_key}")
    print(f"  expires:  {resp['expires_in']}s")

    # --- Phase 2: POST upload via pre-signed form ---
    upload_url = resp["upload_url"]
    upload_fields = resp["upload_fields"]

    # multipart/form-data: fields first, then 'file' last
    r2 = requests.post(
        upload_url,
        data=upload_fields,
        files={"file": ("eicar-test.com", EICAR_BYTES)},
    )
    print(f"\nPhase 2 — S3 upload: {r2.status_code}")
    assert r2.status_code == 204, f"Upload failed: {r2.status_code} {r2.text[:300]}"
    print("  EICAR uploaded successfully")

    # --- Phase 3: Check SQS for the analysis job ---
    print("\nPhase 3 — Checking SQS (waiting up to 15s)...")
    sqs = boto3.client("sqs", region_name=region)

    found = False
    for attempt in range(3):
        time.sleep(5)
        msgs = sqs.receive_message(
            QueueUrl=sqs_queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
        )
        for m in msgs.get("Messages", []):
            msg_body = json.loads(m["Body"])
            if msg_body.get("task_id") == task_id:
                print("  SQS message found!")
                print(f"  {json.dumps(msg_body, indent=2)}")
                # Delete the test message so it doesn't get picked up by a real agent
                sqs.delete_message(
                    QueueUrl=sqs_queue_url,
                    ReceiptHandle=m["ReceiptHandle"],
                )
                print("  Test message deleted from queue")
                found = True
                break
        if found:
            break

    if not found:
        print("  WARNING: No SQS message found for this task_id")
        print("  Check Lambda logs for errors")

    # --- Summary ---
    print("\n=== Results ===")
    print("  API Gateway POST /submit:  PASS")
    print("  S3 pre-signed upload:      PASS")
    print(f"  SQS job enqueue:           {'PASS' if found else 'FAIL'}")


if __name__ == "__main__":
    main()
