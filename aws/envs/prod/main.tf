# =============================================================================
# aws/envs/prod/main.tf — STUB
# Claude Code: implement this file.
#
# This is the composition layer that wires all AWS modules together.
# It should instantiate:
#   - module "vpc"      (aws/modules/vpc)
#   - module "s3"       (aws/modules/s3)
#   - module "rds"      (aws/modules/rds)
#   - module "lambda"   (aws/modules/lambda)
#   - module "api"      (aws/modules/api) — not yet built
#
# Also needs to create directly (not in a module):
#   - aws_kms_key + aws_kms_alias — used by S3, RDS, Lambda logs
#   - aws_secretsmanager_secret for: wireguard keys, cape API key,
#     db password, dsdt_string, s3 bucket names
#   - aws_iam_role for sandbox host (OVH server instance role equiv —
#     actually an IAM user with minimal S3 perms since it's not an EC2 instance)
#
# Wire module outputs to module inputs:
#   vpc.private_subnet_ids → rds, lambda
#   vpc.vpc_id → rds, lambda
#   s3.reports_bucket_arn → lambda (trigger)
#   s3.samples_bucket_arn → lambda (IAM policy)
#   lambda.report_processor_arn → s3 (notification)
#   rds.db_endpoint → lambda (env var)
#   kms_key.arn → s3, rds, lambda
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "malware-sandbox"
      Environment = "prod"
      ManagedBy   = "terraform"
      Owner       = "christopher-shaiman"
    }
  }
}

# STUB — implement module composition. See file header for full spec.
