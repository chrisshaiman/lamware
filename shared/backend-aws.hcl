# shared/backend-aws.hcl
# S3 remote state backend for all AWS modules.
#
# Populate this file from bootstrap outputs after running:
#   cd aws/bootstrap && terraform apply
#
# Then copy the output values here:
#   bucket         = output.tfstate_bucket_name
#   dynamodb_table = output.tfstate_lock_table
#   region         = output.aws_region

bucket         = "malware-sandbox-tfstate-<your-account-id>"
key            = "prod/aws/terraform.tfstate"
region         = "us-east-1"
encrypt        = true
dynamodb_table = "malware-sandbox-tfstate-lock"
