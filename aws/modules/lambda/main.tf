# =============================================================================
# Module: lambda
# Serverless pipeline triggers for the analysis agent suite.
#
# Functions:
#   report_processor  — triggered by S3 on new Cape report; parses JSON,
#                       writes normalized IOCs to RDS, fans out to enrichment
#   sample_submitter  — accepts new sample via API GW, generates pre-signed
#                       S3 URL, submits job to Cape via SQS job queue
#
# This module provisions the IAM roles, SGs, and Lambda functions.
# Actual Python handler code lives in src/ — deploy with `terraform apply`
# after zipping (or use a CI pipeline).
# =============================================================================

# -----------------------------------------------------------------------------
# Security Group for Lambda — needs RDS access, S3 via VPC endpoint
# -----------------------------------------------------------------------------

resource "aws_security_group" "lambda" {
  name        = "${var.name_prefix}-lambda-sg"
  description = "Lambda functions — outbound to RDS and VPC endpoints only"
  vpc_id      = var.vpc_id

  # Egress rules are added in the composition layer (aws/envs/prod/main.tf) using
  # aws_vpc_security_group_egress_rule so the RDS rule can reference the RDS
  # security group directly instead of hardcoding the VPC CIDR.
  # See: lambda_to_rds_egress, lambda_to_endpoints_egress

  tags = merge(var.tags, { Name = "${var.name_prefix}-lambda-sg" })
}

# -----------------------------------------------------------------------------
# IAM Role — shared by Lambda functions in this module
# -----------------------------------------------------------------------------

resource "aws_iam_role" "lambda" {
  name = "${var.name_prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "lambda_s3" {
  name = "${var.name_prefix}-lambda-s3-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          var.samples_bucket_arn,
          "${var.samples_bucket_arn}/*",
          var.reports_bucket_arn,
          "${var.reports_bucket_arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
      },
      {
        # Read Cape API key and DB password from Secrets Manager
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.secrets_arn_prefix]
      },
      {
        # sample_submitter puts analysis jobs on the queue; bare metal host polls and submits to Cape
        Effect   = "Allow"
        Action   = ["sqs:SendMessage", "sqs:GetQueueAttributes"]
        Resource = [var.sqs_queue_arn]
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups (explicit so retention is set)
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "report_processor" {
  name              = "/aws/lambda/${var.name_prefix}-report-processor"
  retention_in_days = 30
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "sample_submitter" {
  name              = "/aws/lambda/${var.name_prefix}-sample-submitter"
  retention_in_days = 30
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# -----------------------------------------------------------------------------
# Lambda: report_processor
# Triggered by S3 when a new Cape JSON report lands in the reports bucket.
# Parses behavioral data → writes IOCs, API call sequences, network indicators
# to RDS → triggers downstream static/memory agents if warranted.
# -----------------------------------------------------------------------------

resource "aws_lambda_function" "report_processor" {
  function_name = "${var.name_prefix}-report-processor"
  role          = aws_iam_role.lambda.arn
  handler       = "report_processor.handler"
  runtime       = "python3.12"
  timeout       = 300   # Cape reports can be large; give it time
  memory_size   = 512

  filename         = var.report_processor_zip
  source_code_hash = filebase64sha256(var.report_processor_zip)

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      DB_SECRET_ARN      = var.db_secret_arn
      DB_ENDPOINT        = var.db_endpoint
      DB_NAME            = var.db_name
      CAPE_API_SECRET_ARN = var.cape_api_secret_arn
      # CAPE_HOST removed — job submission is via SQS, not direct Cape API call
      AWS_REGION_NAME    = var.aws_region
    }
  }

  depends_on = [aws_cloudwatch_log_group.report_processor]

  tags = merge(var.tags, { Name = "${var.name_prefix}-report-processor" })
}

# Allow S3 to invoke this function
resource "aws_lambda_permission" "s3_invoke_report_processor" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.report_processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = var.reports_bucket_arn
}

# -----------------------------------------------------------------------------
# Lambda: sample_submitter
# Called by API Gateway. Accepts a sample upload request, generates a
# pre-signed S3 URL for the client, then submits an analysis job to Cape.
# Returns a task_id the client can poll.
# -----------------------------------------------------------------------------

resource "aws_lambda_function" "sample_submitter" {
  function_name = "${var.name_prefix}-sample-submitter"
  role          = aws_iam_role.lambda.arn
  handler       = "sample_submitter.handler"
  runtime       = "python3.12"
  timeout       = 30
  memory_size   = 256

  filename         = var.sample_submitter_zip
  source_code_hash = filebase64sha256(var.sample_submitter_zip)

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      SAMPLES_BUCKET      = var.samples_bucket_name
      SQS_QUEUE_URL       = var.sqs_queue_url
      CAPE_API_SECRET_ARN = var.cape_api_secret_arn
      AWS_REGION_NAME     = var.aws_region
    }
  }

  depends_on = [aws_cloudwatch_log_group.sample_submitter]

  tags = merge(var.tags, { Name = "${var.name_prefix}-sample-submitter" })
}
