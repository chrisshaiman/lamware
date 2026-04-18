# =============================================================================
# aws/envs/prod/outputs.tf
# Values needed by the operator and by Ansible at configure time
# =============================================================================

output "api_endpoint" {
  value       = module.api.api_endpoint
  description = "HTTPS endpoint — POST /submit to this URL to submit a sample"
}

output "submitter_policy_arn" {
  value       = module.api.submitter_policy_arn
  description = "Attach this IAM policy to any user or role that needs to submit samples"
}

output "sqs_queue_url" {
  value       = module.sqs.queue_url
  description = "SQS job queue URL — for reference; bare metal agent reads this from Secrets Manager"
}

output "baremetal_agent_secret_arn" {
  value       = module.sqs.baremetal_agent_secret_arn
  description = "Secrets Manager ARN for bare metal agent credentials — pass to Ansible as extra var"
}

output "dsdt_secret_arn" {
  value       = aws_secretsmanager_secret.dsdt.arn
  description = "Secrets Manager ARN for DSDT values — populate manually before running Ansible"
}

output "cape_api_secret_arn" {
  value       = aws_secretsmanager_secret.cape_api_key.arn
  description = "Secrets Manager ARN for Cape API key — populate after Cape is deployed"
}

output "kms_key_arn" {
  value       = aws_kms_key.main.arn
  description = "Project KMS key ARN"
}

output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "VPC ID"
}
