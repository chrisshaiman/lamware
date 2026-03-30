# =============================================================================
# Module: sqs — variables
# =============================================================================

variable "name_prefix" {
  type        = string
  description = "Prefix applied to all resource names"
}

variable "aws_region" {
  type        = string
  description = "AWS region — stored in the baremetal agent credentials secret"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources"
}

variable "kms_key_id" {
  type        = string
  description = "KMS key ID (not ARN) for SQS queue encryption"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for IAM policy — allows bare metal agent to decrypt messages"
}

# lambda_role_arn intentionally absent — Lambda's SendMessage access is
# granted via its IAM role policy in the lambda module. For same-account
# access, an IAM role policy alone is sufficient; no queue resource policy
# needed, which avoids a circular dependency with the lambda module.

variable "reports_bucket_arn" {
  type        = string
  description = "ARN of the reports S3 bucket — bare metal agent needs PutObject here"
}

variable "samples_bucket_arn" {
  type        = string
  description = "ARN of the samples S3 bucket — bare metal agent needs GetObject to fetch samples for analysis"
}

variable "visibility_timeout_seconds" {
  type        = number
  default     = 1800  # 30 minutes — covers typical Cape analysis duration
  description = "How long a received message is hidden from other consumers. Must exceed the longest expected Cape analysis run."
}

variable "max_receive_count" {
  type        = number
  default     = 3
  description = "Number of times a job can be received before being sent to the DLQ. Set low — a job that fails 3 times likely has a structural problem."
}
