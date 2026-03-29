# =============================================================================
# Module: lambda — outputs
# =============================================================================

# -----------------------------------------------------------------------------
# report_processor — consumed by the S3 module for bucket event notification
# -----------------------------------------------------------------------------

output "report_processor_arn" {
  value       = aws_lambda_function.report_processor.arn
  description = "ARN of report_processor — wire to S3 reports bucket event notification"
}

output "report_processor_function_name" {
  value       = aws_lambda_function.report_processor.function_name
  description = "Function name of report_processor"
}

# -----------------------------------------------------------------------------
# sample_submitter — consumed by the API Gateway module for Lambda integration
# -----------------------------------------------------------------------------

output "sample_submitter_arn" {
  value       = aws_lambda_function.sample_submitter.arn
  description = "ARN of sample_submitter — wire to API Gateway Lambda integration"
}

output "sample_submitter_function_name" {
  value       = aws_lambda_function.sample_submitter.function_name
  description = "Function name of sample_submitter — used by API Gateway invoke permission"
}

# -----------------------------------------------------------------------------
# Shared resources — consumed by other modules
# -----------------------------------------------------------------------------

output "security_group_id" {
  value       = aws_security_group.lambda.id
  description = "Lambda security group ID — add as allowed ingress source on RDS security group"
}

output "role_arn" {
  value       = aws_iam_role.lambda.arn
  description = "IAM role ARN shared by both Lambda functions"
}
