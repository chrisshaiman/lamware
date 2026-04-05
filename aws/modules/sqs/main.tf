# =============================================================================
# Module: sqs
# Job queue for malware analysis submission.
#
# Flow:
#   sample_submitter Lambda  →  SendMessage  →  this queue
#   bare metal sqs-agent     ←  ReceiveMessage/DeleteMessage  ←  this queue
#
# The bare metal host polls via the public SQS HTTPS endpoint. It authenticates
# using an IAM user with a single permission: sts:AssumeRole. The actual queue
# and S3 permissions live on the assumed role (1-hour sessions). If the host is
# compromised and static credentials are exfiltrated, the attacker can only
# obtain short-lived sessions — they cannot read secrets, modify IAM, or
# escalate. CloudTrail AssumeRole calls are the detection surface.
#
# Lambda reaches the queue via the VPC Interface Endpoint in aws/modules/vpc.
#
# A dead-letter queue captures jobs that fail after max_receive_count attempts
# so they can be inspected without being lost.
# =============================================================================

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Dead-letter queue — receives jobs that fail repeatedly
# Alarm on this queue if you want alerting on stuck jobs
# -----------------------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name              = "${var.name_prefix}-analysis-jobs-dlq"
  kms_master_key_id = var.kms_key_id

  # 14 days (SQS maximum) — gives enough time to investigate failed jobs even
  # during extended downtime or a multi-day bare metal rebuild.
  message_retention_seconds = 1209600

  tags = merge(var.tags, { Name = "${var.name_prefix}-analysis-jobs-dlq" })
}

# -----------------------------------------------------------------------------
# Main job queue
# -----------------------------------------------------------------------------

resource "aws_sqs_queue" "jobs" {
  name              = "${var.name_prefix}-analysis-jobs"
  kms_master_key_id = var.kms_key_id

  # Cape analysis can take 30–60 minutes for complex samples. Visibility timeout
  # must exceed the longest expected analysis duration so in-progress jobs aren't
  # re-delivered and run twice.
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
# Lambda (via IAM role) sends; bare metal assumed-role sessions receive/delete
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
          # Role ARN covers all sessions assumed from this role.
          # The static IAM user credentials cannot reach the queue directly —
          # they can only call sts:AssumeRole.
          AWS = aws_iam_role.baremetal_agent.arn
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
#
# OVH is outside AWS so there is no instance role available. An IAM user with
# a static access key is unavoidable. The blast radius is minimized by scoping
# the user to a single action: sts:AssumeRole. All real permissions live on
# the role below (1-hour sessions). Exfiltrated static credentials can only
# generate short-lived sessions — they cannot be used directly against S3 or
# SQS, and every AssumeRole call is logged in CloudTrail.
# -----------------------------------------------------------------------------

resource "aws_iam_user" "baremetal_agent" {
  name = "${var.name_prefix}-baremetal-agent"
  tags = var.tags
}

# Restrict the user to a single action: assume the agent role.
# No S3, SQS, or KMS permissions here — those live on the role.
resource "aws_iam_user_policy" "baremetal_agent" {
  name = "${var.name_prefix}-baremetal-agent-policy"
  user = aws_iam_user.baremetal_agent.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAssumeAgentRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.baremetal_agent.arn
      }
    ]
  })
}

resource "aws_iam_access_key" "baremetal_agent" {
  user = aws_iam_user.baremetal_agent.name
}

# -----------------------------------------------------------------------------
# IAM role — assumed by the bare metal agent, holds all real permissions
#
# Sessions expire after 1 hour. The sqs-agent must refresh via AssumeRole
# before expiry. Every call is logged in CloudTrail: alert on AssumeRole
# calls outside expected hours or from unexpected source IPs.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "baremetal_agent" {
  name                 = "${var.name_prefix}-baremetal-agent-role"
  max_session_duration = 3600  # 1 hour
  tags                 = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBaremetalUserToAssume"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_user.baremetal_agent.arn
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "baremetal_agent" {
  name = "${var.name_prefix}-baremetal-agent-role-policy"
  role = aws_iam_role.baremetal_agent.name

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

# -----------------------------------------------------------------------------
# Secrets Manager — Ansible pulls these at configure time
#
# The secret contains the static IAM user credentials (used only for
# sts:AssumeRole) and the role ARN to assume. The sqs-agent calls AssumeRole
# on startup and refreshes before the 1-hour session expires.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# DLQ alarm — fires when any job lands in the dead-letter queue
# Failed jobs accumulating silently is the primary operational blind spot for
# this pipeline. Alarm state changes in CloudWatch regardless of whether
# alarm_sns_topic_arns is set — wire SNS for active paging.
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${var.name_prefix}-dlq-depth"
  alarm_description   = "Jobs in the dead-letter queue - analysis failures need investigation. Check sqs-agent logs and Cape status on the bare metal host."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300  # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  # Leave alarm_sns_topic_arns empty to create the alarm without active paging.
  # Set it in terraform.tfvars once you have an SNS topic for ops notifications.
  alarm_actions = var.alarm_sns_topic_arns
  ok_actions    = var.alarm_sns_topic_arns

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Secrets Manager — Ansible pulls these at configure time
resource "aws_secretsmanager_secret" "baremetal_credentials" {
  name        = "${var.name_prefix}/baremetal-agent-credentials"
  description = "AWS IAM credentials for the bare metal SQS polling agent. Static key can only call sts:AssumeRole — all real permissions require assuming the role ARN also stored here."
  kms_key_id  = var.kms_key_id

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "baremetal_credentials" {
  secret_id = aws_secretsmanager_secret.baremetal_credentials.id

  secret_string = jsonencode({
    # Static credentials — scoped to sts:AssumeRole only
    access_key_id     = aws_iam_access_key.baremetal_agent.id
    secret_access_key = aws_iam_access_key.baremetal_agent.secret
    # Role to assume; sessions last 1 hour, refresh before expiry
    role_arn          = aws_iam_role.baremetal_agent.arn
    session_duration  = 3600
    sqs_queue_url     = aws_sqs_queue.jobs.url
    aws_region        = var.aws_region
  })
}
