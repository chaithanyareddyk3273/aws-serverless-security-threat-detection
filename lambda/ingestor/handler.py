"""
AWS Lambda — Log Ingestor
Receives raw network log events via API Gateway (POST /ingest),
archives to S3, and forwards to the classifier Lambda asynchronously.
"""
import json
import os
import uuid
import boto3
from datetime import datetime, timezone

s3              = boto3.client("s3")
lambda_client   = boto3.client("lambda")

LOG_BUCKET           = os.environ["LOG_BUCKET"]
CLASSIFIER_FUNC_NAME = os.environ["CLASSIFIER_FUNCTION_NAME"]


def handler(event, context):
    try:
        # Parse body — API Gateway wraps it as a string
        body = event.get("body", "{}")
        if isinstance(body, str):
            body = json.loads(body)

        # Assign event ID + timestamp if missing
        event_id  = body.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}"
        timestamp = body.get("timestamp") or datetime.now(timezone.utc).isoformat()

        enriched = {
            "event_id":  event_id,
            "source_ip": body.get("src_ip", "unknown"),
            "timestamp": timestamp,
            "raw_event": body,
        }

        # Archive to S3 (partitioned by date)
        date_prefix = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        s3_key = f"logs/{date_prefix}/{event_id}.json"

        s3.put_object(
            Bucket=LOG_BUCKET,
            Key=s3_key,
            Body=json.dumps(enriched),
            ContentType="application/json",
        )

        # Invoke classifier Lambda asynchronously (fire and forget)
        lambda_client.invoke(
            FunctionName=CLASSIFIER_FUNC_NAME,
            InvocationType="Event",   # async
            Payload=json.dumps(enriched),
        )

        return {
            "statusCode": 202,
            "body": json.dumps({
                "message":  "Event accepted",
                "event_id": event_id,
            }),
        }

    except Exception as e:
        print(f"[Ingestor] Error: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }
