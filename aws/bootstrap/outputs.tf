output "tfstate_bucket_name" {
  value       = aws_s3_bucket.tfstate.bucket
  description = "Copy this value into shared/backend-aws.hcl as the 'bucket' field"
}

output "tfstate_lock_table" {
  value       = aws_dynamodb_table.tfstate_lock.name
  description = "Copy this value into shared/backend-aws.hcl as the 'dynamodb_table' field"
}

output "aws_region" {
  value       = var.aws_region
  description = "Region to use in shared/backend-aws.hcl"
}
