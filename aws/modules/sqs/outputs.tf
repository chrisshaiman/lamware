# =============================================================================
# Module: sqs — outputs
# =============================================================================

output "queue_url" {
  value       = aws_sqs_queue.jobs.url
  description = "Job queue URL — passed to sample_submitter Lambda as SQS_QUEUE_URL env var"
}

output "queue_arn" {
  value       = aws_sqs_queue.jobs.arn
  description = "Job queue ARN — used in Lambda IAM policy"
}

output "dlq_arn" {
  value       = aws_sqs_queue.dlq.arn
  description = "Dead-letter queue ARN — wire to a CloudWatch alarm to alert on stuck jobs"
}

output "baremetal_agent_secret_arn" {
  value       = aws_secretsmanager_secret.baremetal_credentials.arn
  description = "Secrets Manager ARN for bare metal agent credentials — Ansible pulls this at configure time"
}

output "baremetal_agent_iam_user" {
  value       = aws_iam_user.baremetal_agent.name
  description = "IAM username for the bare metal polling agent"
}
