# shared/backend-aws.hcl
# S3 remote state backend for AWS infra.
# Create the bucket + DynamoDB table manually before first `terraform init`,
# or bootstrap with: aws/bootstrap/main.tf (not yet built — add to backlog)

bucket         = "sandbox-tfstate-yourorg"      # replace with your bucket
key            = "prod/aws/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "sandbox-tfstate-lock"
