# =============================================================================
# Module: lambda — variables
# =============================================================================

# -----------------------------------------------------------------------------
# Naming and tagging
# -----------------------------------------------------------------------------

variable "name_prefix" {
  type        = string
  description = "Prefix applied to all resource names in this module"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources"
}

variable "aws_region" {
  type        = string
  description = "AWS region — passed to Lambda as AWS_REGION_NAME env var"
}

# -----------------------------------------------------------------------------
# Networking — Lambda runs inside the VPC to reach RDS
# -----------------------------------------------------------------------------

variable "vpc_id" {
  type        = string
  description = "VPC ID for Lambda security group and S3 VPC endpoint"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for Lambda VPC config"
}

# -----------------------------------------------------------------------------
# S3 — samples ingestion and report output
# -----------------------------------------------------------------------------

variable "samples_bucket_arn" {
  type        = string
  description = "ARN of the samples bucket — Lambda needs GetObject/PutObject for pre-signed URL generation"
}

variable "samples_bucket_name" {
  type        = string
  description = "Name of the samples bucket — passed to sample_submitter for pre-signed URL construction"
}

variable "reports_bucket_arn" {
  type        = string
  description = "ARN of the reports bucket — report_processor is triggered by new objects here"
}

# -----------------------------------------------------------------------------
# SQS — job queue for analysis submission
# -----------------------------------------------------------------------------

variable "sqs_queue_url" {
  type        = string
  description = "URL of the SQS job queue — sample_submitter puts analysis jobs here after pre-signed URL is issued"
}

variable "sqs_queue_arn" {
  type        = string
  description = "ARN of the SQS job queue — used in the Lambda IAM SendMessage policy"
}

# -----------------------------------------------------------------------------
# Encryption
# -----------------------------------------------------------------------------

variable "kms_key_arn" {
  type        = string
  description = "ARN of the project KMS key — used for S3, RDS, and CloudWatch log encryption"
}

# -----------------------------------------------------------------------------
# Secrets Manager
# -----------------------------------------------------------------------------


variable "db_secret_arn" {
  type        = string
  description = "ARN of the RDS credentials secret — passed to report_processor as DB_SECRET_ARN"
}

variable "cape_api_secret_arn" {
  type        = string
  description = "ARN of the Cape API key secret — available to both functions for future Cape API calls"
}

# -----------------------------------------------------------------------------
# RDS — report_processor writes normalized IOCs here
# -----------------------------------------------------------------------------

variable "db_endpoint" {
  type        = string
  description = "RDS PostgreSQL endpoint hostname"
}

variable "db_name" {
  type        = string
  description = "RDS database name"
}

# -----------------------------------------------------------------------------
# Lambda deployment packages
# Built separately and zipped before terraform apply
# -----------------------------------------------------------------------------

variable "report_processor_zip" {
  type        = string
  description = "Path to the report_processor Lambda deployment zip file"
}

variable "sample_submitter_zip" {
  type        = string
  description = "Path to the sample_submitter Lambda deployment zip file"
}
