# ── SNS — Alert Topics ────────────────────────────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"
  tags = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── CloudWatch — Dashboard ────────────────────────────────────────────────────
resource "aws_cloudwatch_dashboard" "threats" {
  dashboard_name = "${var.project_name}-threats"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          title  = "Threats Detected by Type (last 24h)"
          period = 300
          stat   = "Sum"
          metrics = [
            ["SecurityThreatDetection", "ThreatDetected", "ThreatType", "dos",               "Severity", "Critical"],
            ["SecurityThreatDetection", "ThreatDetected", "ThreatType", "ddos",              "Severity", "Critical"],
            ["SecurityThreatDetection", "ThreatDetected", "ThreatType", "brute_force",       "Severity", "High"],
            ["SecurityThreatDetection", "ThreatDetected", "ThreatType", "data_exfiltration", "Severity", "Critical"],
            ["SecurityThreatDetection", "ThreatDetected", "ThreatType", "port_scan",         "Severity", "Medium"],
            ["SecurityThreatDetection", "ThreatDetected", "ThreatType", "phishing",          "Severity", "High"],
          ]
          view   = "timeSeries"
          region = var.aws_region
        }
      },
      {
        type = "metric"
        properties = {
          title  = "Total Threats (1h)"
          period = 3600
          stat   = "Sum"
          metrics = [
            ["SecurityThreatDetection", "ThreatDetected"]
          ]
          view   = "singleValue"
          region = var.aws_region
        }
      },
    ]
  })
}

# ── CloudWatch — Alarms ───────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "critical_threat" {
  alarm_name          = "${var.project_name}-critical-threat"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ThreatDetected"
  namespace           = "SecurityThreatDetection"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "A Critical severity threat has been detected"
  treat_missing_data  = "notBreaching"

  dimensions = { Severity = "Critical" }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "high_volume" {
  alarm_name          = "${var.project_name}-high-threat-volume"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ThreatDetected"
  namespace           = "SecurityThreatDetection"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "More than 10 threats detected in 5 minutes — potential attack wave"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = local.tags
}
