# =============================================================================
# aws/bootstrap/main.tf
# One-time setup: creates the S3 bucket and DynamoDB table used as the
# Terraform remote state backend for all other modules.
#
# Run this FIRST, before any other terraform init.
# Uses local state intentionally — there is no remote backend yet.
#
# Usage:
#   cd aws/bootstrap
#   terraform init
#   terraform apply
#   # Then update shared/backend-aws.hcl with the output bucket name
#   # Commit the resulting terraform.tfstate — it's the only record of this
#
# Do NOT add a backend "s3" block here. This module bootstraps that backend.
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # No backend block — local state only
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "malware-sandbox"
      ManagedBy = "terraform"
      Owner     = "christopher-shaiman"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  # Account ID in the bucket name guarantees global uniqueness without
  # requiring the operator to invent a name
  bucket_name = "malware-sandbox-tfstate-${data.aws_caller_identity.current.account_id}"
}

# -----------------------------------------------------------------------------
# S3 — remote state bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "tfstate" {
  bucket = local.bucket_name

  # Prevent accidental deletion — state loss is catastrophic
  lifecycle {
    prevent_destroy = true
  }

  tags = { Name = local.bucket_name }
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # SSE-S3, not KMS — KMS key doesn't exist yet
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  # Keep state history manageable — noncurrent versions expire after 90 days
  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# -----------------------------------------------------------------------------
# DynamoDB — state locking
# Prevents concurrent applies from corrupting state.
# PAY_PER_REQUEST — lock operations are infrequent, no need for provisioned capacity
# -----------------------------------------------------------------------------

resource "aws_dynamodb_table" "tfstate_lock" {
  name         = "malware-sandbox-tfstate-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  # Protect the lock table from accidental deletion
  lifecycle {
    prevent_destroy = true
  }

  tags = { Name = "malware-sandbox-tfstate-lock" }
}
