# =============================================================================
# Module: api
# HTTP API Gateway (v2) in front of the sample_submitter Lambda.
#
# Exposes a single endpoint:
#   POST /submit  — accepts a sample submission request, returns a pre-signed
#                   S3 upload URL and a job ID
#
# Authentication: AWS_IAM (SigV4 request signing)
# Callers need execute-api:Invoke permission on this API. Use the
# submitter_policy_arn output to grant access to users or roles that need
# to submit samples.
#
# Throttling is set conservatively — one bare metal host can only process
# so many samples concurrently. Tune via variables if needed.
# =============================================================================

# -----------------------------------------------------------------------------
# HTTP API
# -----------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "this" {
  name          = "${var.name_prefix}-api"
  protocol_type = "HTTP"
  description   = "Malware sample submission API"

  tags = merge(var.tags, { Name = "${var.name_prefix}-api" })
}

# -----------------------------------------------------------------------------
# Access logs — who submitted what, and when
# Retention matches RDS IOC data (90 days) for correlation if needed
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "access_logs" {
  name              = "/aws/apigateway/${var.name_prefix}"
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Stage — $default with auto-deploy and throttling
# -----------------------------------------------------------------------------

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.this.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access_logs.arn

    # Structured JSON logs — makes CloudWatch Insights queries straightforward
    format = jsonencode({
      requestId      = "$context.requestId"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      responseLength = "$context.responseLength"
      sourceIp       = "$context.identity.sourceIp"
      userArn        = "$context.identity.userArn"  # IAM identity of caller
      errorMessage   = "$context.error.message"
    })
  }

  default_route_settings {
    # Conservative throttle — Cape can only process so much concurrently.
    # Tune upward if you add more bare metal capacity.
    throttling_burst_limit = var.throttle_burst_limit
    throttling_rate_limit  = var.throttle_rate_limit

    detailed_metrics_enabled = true
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Lambda integration — AWS_PROXY passes the full request to sample_submitter
# payload_format_version 2.0 is the modern format for HTTP API
# -----------------------------------------------------------------------------

resource "aws_apigatewayv2_integration" "sample_submitter" {
  api_id                 = aws_apigatewayv2_api.this.id
  integration_type       = "AWS_PROXY"
  integration_uri        = var.sample_submitter_invoke_arn
  payload_format_version = "2.0"
}

# -----------------------------------------------------------------------------
# Route: POST /submit
# AWS_IAM auth — callers must sign requests with SigV4
# -----------------------------------------------------------------------------

resource "aws_apigatewayv2_route" "submit" {
  api_id             = aws_apigatewayv2_api.this.id
  route_key          = "POST /submit"
  target             = "integrations/${aws_apigatewayv2_integration.sample_submitter.id}"
  authorization_type = "AWS_IAM"
}

# Allow API Gateway to invoke the Lambda function
resource "aws_lambda_permission" "api_gw_invoke" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.sample_submitter_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.this.execution_arn}/*/*/submit"
}

# -----------------------------------------------------------------------------
# IAM policy for sample submitters
# Attach this to any IAM user or role that needs to call POST /submit.
# The composition layer creates the actual users/roles; this just defines
# the permission they need.
# -----------------------------------------------------------------------------

resource "aws_iam_policy" "submitter" {
  name        = "${var.name_prefix}-sample-submitter-policy"
  description = "Allows calling POST /submit on the malware analysis API"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeSubmitEndpoint"
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = "${aws_apigatewayv2_api.this.execution_arn}/$default/POST/submit"
    }]
  })

  tags = var.tags
}
