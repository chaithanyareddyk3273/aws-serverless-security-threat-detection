"""
AWS Lambda — Threat Classifier
Triggered by the ingestor Lambda (or directly via EventBridge).

Event payload:
{
    "event_id":   "evt-abc123",
    "source_ip":  "1.2.3.4",
    "timestamp":  "2024-01-15T10:30:00Z",
    "raw_event":  { ...network log fields... }
}
"""
import json
import os
import boto3
from classifier.features     import extract_features, validate_event
from classifier.model        import ThreatClassifier
from classifier.threat_types import get_remediation

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ALERT_THRESHOLD_SEVERITY = {"Medium", "High", "Critical"}

sns = boto3.client("sns")
cw  = boto3.client("cloudwatch")

classifier = ThreatClassifier()   # loaded once on cold start


def handler(event, context):
    results = []

    # Supports both single event and batch
    records = event if isinstance(event, list) else [event]

    for record in records:
        raw = record.get("raw_event", record)

        # Validate
        valid, err = validate_event(raw)
        if not valid:
            print(f"[Classifier] Invalid event: {err}")
            continue

        # Extract features & classify
        features   = extract_features(raw)
        prediction = classifier.predict(features)
        threat     = prediction["threat"]
        severity   = prediction["severity"]
        confidence = prediction["confidence"]

        print(f"[Classifier] {record.get('source_ip','?')} → {threat} ({severity}, {confidence:.2%})")

        # Publish CloudWatch metric (normal traffic would otherwise trip the volume alarm)
        if threat != "normal":
            _put_metric(threat, severity)

        # Alert if above threshold
        if severity in ALERT_THRESHOLD_SEVERITY:
            _send_alert(record, prediction, raw)

        results.append({
            "event_id":  record.get("event_id"),
            "threat":    threat,
            "severity":  severity,
            "confidence": confidence,
        })

    return {"statusCode": 200, "body": json.dumps(results)}


def _put_metric(threat, severity):
    # CloudWatch stores each dimension combination as a separate metric, so publish
    # all three views: per type+severity (dashboard), per severity (critical alarm),
    # and the total (volume alarm + "Total Threats" widget).
    dimension_sets = [
        [{"Name": "ThreatType", "Value": threat}, {"Name": "Severity", "Value": severity}],
        [{"Name": "Severity", "Value": severity}],
        [],
    ]
    cw.put_metric_data(
        Namespace="SecurityThreatDetection",
        MetricData=[
            {
                "MetricName": "ThreatDetected",
                "Dimensions": dims,
                "Value": 1,
                "Unit":  "Count",
            }
            for dims in dimension_sets
        ],
    )


def _send_alert(record, prediction, raw_event):
    threat    = prediction["threat"]
    severity  = prediction["severity"]
    confidence = prediction["confidence"]
    playbook  = get_remediation(threat)

    steps_text = "\n".join(playbook["steps"])

    message = f"""
🚨 SECURITY ALERT — {severity.upper()}
{'='*50}

Threat Type  : {playbook['title']}
Severity     : {severity}
Confidence   : {confidence:.1%}
Source IP    : {record.get('source_ip', 'Unknown')}
Timestamp    : {record.get('timestamp', 'Unknown')}
Event ID     : {record.get('event_id', 'Unknown')}

Description:
{playbook['description']}

{'='*50}
🛠️  RECOMMENDED ACTIONS (follow in order):

{steps_text}

{'='*50}
Confidence Breakdown:
{json.dumps(prediction['probabilities'], indent=2)}

This alert was generated automatically by the Security Threat Detection Platform.
"""

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[{severity}] Security Alert: {playbook['title']}",
        Message=message,
    )
    print(f"[Classifier] Alert sent to SNS for {threat} ({severity})")
