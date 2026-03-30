output "api_endpoint" {
  value       = aws_apigatewayv2_stage.default.invoke_url
  description = "HTTPS endpoint for the API — POST /submit to this URL to submit a sample"
}

output "api_id" {
  value       = aws_apigatewayv2_api.this.id
  description = "API Gateway ID"
}

output "execution_arn" {
  value       = aws_apigatewayv2_api.this.execution_arn
  description = "Execution ARN — used to scope IAM execute-api:Invoke permissions"
}

output "submitter_policy_arn" {
  value       = aws_iam_policy.submitter.arn
  description = "IAM policy ARN granting POST /submit access — attach to users or roles that need to submit samples"
}
