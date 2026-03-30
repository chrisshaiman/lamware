# =============================================================================
# Module: sqs
# Job queue for malware analysis submission.
#
# Flow:
#   sample_submitter Lambda  →  SendMessage  →  this queue
#   bare metal sqs-agent     ←  ReceiveMessage/DeleteMessage  ←  this queue
#
# The bare metal host polls via the public SQS HTTPS endpoint using an IAM
# user with minimal permissions (receive + delete only). Lambda reaches the
# queue via the VPC Interface Endpoint in aws/modules/vpc.
#
# A dead-letter queue captures jobs that fail after max_receive_count attempts
# so they can be inspected without being lost.
# =============================================================================

# -----------------------------------------------------------------------------
# Dead-letter queue — receives jobs that fail repeatedly
# Alarm on this queue if you want alerting on stuck jobs
# -----------------------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name              = "${var.name_prefix}-analysis-jobs-dlq"
  kms_master_key_id = var.kms_key_id

  tags = merge(var.tags, { Name = "${var.name_prefix}-analysis-jobs-dlq" })
}

# -----------------------------------------------------------------------------
# Main job queue
# -----------------------------------------------------------------------------

resource "aws_sqs_queue" "jobs" {
  name              = "${var.name_prefix}-analysis-jobs"
  kms_master_key_id = var.kms_key_id

  # Cape analysis can take several minutes. Visibility timeout must exceed the
  # longest expected analysis duration so in-progress jobs aren't re-delivered.
  visibility_timeout_seconds = var.visibility_timeout_seconds

  # How long a message waits in the queue before expiring. 4 days gives plenty
  # of buffer if the bare metal host is down for maintenance or rebuild.
  message_retention_seconds = 345600  # 4 days

  # Long polling — reduces empty receives and AWS API call cost
  receive_wait_time_seconds = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-analysis-jobs" })
}

# -----------------------------------------------------------------------------
# Queue policy — restricts who can send and receive
# Lambda (via IAM role) sends; bare metal IAM user receives and deletes
# -----------------------------------------------------------------------------

resource "aws_sqs_queue_policy" "jobs" {
  queue_url = aws_sqs_queue.jobs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Lambda SendMessage is controlled by the Lambda IAM role policy,
        # not here — avoids circular dependency. Same-account IAM policy
        # is sufficient; no queue resource policy statement required.
        Sid    = "AllowBaremetalPoll"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_user.baremetal_agent.arn
        }
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"  # Needed to extend timeout on long-running jobs
        ]
        Resource = aws_sqs_queue.jobs.arn
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# IAM user for bare metal polling agent
# Not an EC2 instance role — OVH is outside AWS, so we use an IAM user with
# an access key. Credentials stored in Secrets Manager; Ansible injects at runtime.
# Permissions are intentionally minimal: poll + delete only, no send.
# -----------------------------------------------------------------------------

resource "aws_iam_user" "baremetal_agent" {
  name = "${var.name_prefix}-baremetal-agent"
  tags = var.tags
}

resource "aws_iam_user_policy" "baremetal_agent" {
  name = "${var.name_prefix}-baremetal-agent-policy"
  user = aws_iam_user.baremetal_agent.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SQSPoll"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ]
        Resource = aws_sqs_queue.jobs.arn
      },
      {
        Sid    = "S3WriteReports"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = "${var.reports_bucket_arn}/reports/*"
      },
      {
        Sid    = "S3ReadSamples"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = "${var.samples_bucket_arn}/samples/*"
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.kms_key_arn
      }
    ]
  })
}

resource "aws_iam_access_key" "baremetal_agent" {
  user = aws_iam_user.baremetal_agent.name
}

# Store credentials in Secrets Manager — Ansible pulls these at configure time
resource "aws_secretsmanager_secret" "baremetal_credentials" {
  name        = "${var.name_prefix}/baremetal-agent-credentials"
  description = "AWS IAM credentials for the bare metal SQS polling agent"
  kms_key_id  = var.kms_key_id

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "baremetal_credentials" {
  secret_id = aws_secretsmanager_secret.baremetal_credentials.id

  secret_string = jsonencode({
    access_key_id     = aws_iam_access_key.baremetal_agent.id
    secret_access_key = aws_iam_access_key.baremetal_agent.secret
    sqs_queue_url     = aws_sqs_queue.jobs.url
    aws_region        = var.aws_region
  })
}
