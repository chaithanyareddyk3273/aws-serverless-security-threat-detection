# ── Lambda — Ingestor ─────────────────────────────────────────────────────────
resource "aws_lambda_function" "ingestor" {
  function_name = "${var.project_name}-ingestor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "handler.handler"
  runtime       = "python3.11"
  timeout       = 30
  memory_size   = 256

  filename         = "../lambda/ingestor/package.zip"
  source_code_hash = filebase64sha256("../lambda/ingestor/package.zip")

  environment {
    variables = {
      LOG_BUCKET               = aws_s3_bucket.logs.bucket
      CLASSIFIER_FUNCTION_NAME = aws_lambda_function.classifier.function_name
    }
  }

  tags = local.tags
}

resource "aws_lambda_permission" "apigw_ingestor" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingestor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.ingest_api.execution_arn}/*/*"
}

# ── Lambda — Classifier ───────────────────────────────────────────────────────
resource "aws_lambda_function" "classifier" {
  function_name = "${var.project_name}-classifier"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "handler.handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 512 # ML model needs more RAM

  filename         = "../lambda/classifier/package.zip"
  source_code_hash = filebase64sha256("../lambda/classifier/package.zip")

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  tags = local.tags
}

# ── CloudWatch Log Groups ─────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "ingestor" {
  name              = "/aws/lambda/${aws_lambda_function.ingestor.function_name}"
  retention_in_days = 30
  tags              = local.tags
}

resource "aws_cloudwatch_log_group" "classifier" {
  name              = "/aws/lambda/${aws_lambda_function.classifier.function_name}"
  retention_in_days = 30
  tags              = local.tags
}
