# =============================================================================
# aws/envs/prod/main.tf — Production composition layer
# Wires all AWS modules together. This is the single terraform apply target
# for all AWS-side infrastructure.
#
# Run bootstrap first:
#   cd aws/bootstrap && terraform init && terraform apply
#   # update shared/backend-aws.hcl with output values
#
# Then:
#   cd aws/envs/prod
#   terraform init -backend-config=../../shared/backend-aws.hcl
#   terraform plan -var-file=terraform.tfvars
#   terraform apply -var-file=terraform.tfvars
# =============================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(var.tags, {
      Project     = "malware-sandbox"
      Environment = "prod"
      ManagedBy   = "terraform"
      Owner       = "christopher-shaiman"
    })
  }
}

data "aws_caller_identity" "current" {}

locals {
  secrets_arn_prefix = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}/*"
}

# =============================================================================
# KMS — single key for the project
# Used by: S3 (both buckets), RDS, SQS, Lambda logs, Secrets Manager secrets
# =============================================================================

resource "aws_kms_key" "main" {
  description             = "Malware sandbox — encryption at rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = { Name = "${var.name_prefix}-key" }
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name_prefix}"
  target_key_id = aws_kms_key.main.key_id
}

# =============================================================================
# Secrets Manager — create all secrets upfront so ARNs are stable
# Values are populated here or by Ansible at configure time
# =============================================================================

# DB password — generated here, stored in Secrets Manager, never in tfvars
resource "random_password" "db" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${var.name_prefix}/db-credentials"
  description = "RDS PostgreSQL credentials for the analysis database"
  kms_key_id  = aws_kms_key.main.id
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id

  secret_string = jsonencode({
    host     = module.rds.db_endpoint
    dbname   = var.db_name
    username = var.db_username
    password = random_password.db.result
  })
}

# Cape API key — populated manually after Cape is deployed
resource "aws_secretsmanager_secret" "cape_api_key" {
  name        = "${var.name_prefix}/cape-api-key"
  description = "Cape REST API key — set manually after Cape deployment"
  kms_key_id  = aws_kms_key.main.id
}

resource "aws_secretsmanager_secret_version" "cape_api_key" {
  secret_id     = aws_secretsmanager_secret.cape_api_key.id
  secret_string = jsonencode({ api_key = "PLACEHOLDER — set after Cape deployment" })

  lifecycle {
    # Prevent Terraform from overwriting a value set manually after deployment
    ignore_changes = [secret_string]
  }
}

# DSDT values — set manually or by Ansible after bare metal host boots
# Hardware-specific; cannot be known at Terraform apply time
resource "aws_secretsmanager_secret" "dsdt" {
  name        = "${var.name_prefix}/dsdt-values"
  description = "ACPI DSDT values for Cape sandbox evasion bypass — hardware-specific, set by Ansible"
  kms_key_id  = aws_kms_key.main.id
}

resource "aws_secretsmanager_secret_version" "dsdt" {
  secret_id     = aws_secretsmanager_secret.dsdt.id
  secret_string = jsonencode({ dsdt_string = "PLACEHOLDER — set by Ansible after first boot" })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# WireGuard keys — generated locally by operator, stored here for Ansible
resource "aws_secretsmanager_secret" "wireguard" {
  name        = "${var.name_prefix}/wireguard-keys"
  description = "WireGuard keypair for admin VPN — set manually before running Ansible"
  kms_key_id  = aws_kms_key.main.id
}

resource "aws_secretsmanager_secret_version" "wireguard" {
  secret_id = aws_secretsmanager_secret.wireguard.id
  secret_string = jsonencode({
    private_key = "PLACEHOLDER — run: wg genkey | tee private.key | wg pubkey"
    public_key  = "PLACEHOLDER"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# =============================================================================
# Modules — instantiated in dependency order
# =============================================================================

module "vpc" {
  source = "../../modules/vpc"

  name_prefix = var.name_prefix
  vpc_cidr    = var.vpc_cidr
  aws_region  = var.aws_region
}

module "s3" {
  source = "../../modules/s3"

  samples_bucket_name = var.samples_bucket_name
  reports_bucket_name = var.reports_bucket_name
  kms_key_arn         = aws_kms_key.main.arn
}

module "rds" {
  source = "../../modules/rds"

  name_prefix        = var.name_prefix
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  kms_key_arn        = aws_kms_key.main.arn
  db_name            = var.db_name
  db_username        = var.db_username
  db_password        = random_password.db.result
  instance_class     = var.db_instance_class
}

module "sqs" {
  source = "../../modules/sqs"

  name_prefix        = var.name_prefix
  aws_region         = var.aws_region
  kms_key_id         = aws_kms_key.main.key_id
  kms_key_arn        = aws_kms_key.main.arn
  reports_bucket_arn = module.s3.reports_bucket_arn
  samples_bucket_arn = module.s3.samples_bucket_arn
}

module "lambda" {
  source = "../../modules/lambda"

  name_prefix        = var.name_prefix
  aws_region         = var.aws_region
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids

  samples_bucket_arn  = module.s3.samples_bucket_arn
  samples_bucket_name = module.s3.samples_bucket_name
  reports_bucket_arn  = module.s3.reports_bucket_arn

  sqs_queue_url = module.sqs.queue_url
  sqs_queue_arn = module.sqs.queue_arn

  kms_key_arn        = aws_kms_key.main.arn
  secrets_arn_prefix = local.secrets_arn_prefix
  db_secret_arn      = aws_secretsmanager_secret.db_credentials.arn
  cape_api_secret_arn = aws_secretsmanager_secret.cape_api_key.arn

  db_endpoint = module.rds.db_endpoint
  db_name     = var.db_name

  report_processor_zip = var.report_processor_zip
  sample_submitter_zip = var.sample_submitter_zip
}

module "api" {
  source = "../../modules/api"

  name_prefix                    = var.name_prefix
  kms_key_arn                    = aws_kms_key.main.arn
  sample_submitter_invoke_arn    = module.lambda.sample_submitter_invoke_arn
  sample_submitter_function_name = module.lambda.sample_submitter_function_name
  throttle_burst_limit           = var.api_throttle_burst_limit
  throttle_rate_limit            = var.api_throttle_rate_limit
}

# =============================================================================
# Cross-module wiring — resources that depend on multiple modules
# =============================================================================

# Lambda SG → RDS SG ingress rule (avoids circular dep between rds and lambda modules)
resource "aws_vpc_security_group_ingress_rule" "lambda_to_rds" {
  security_group_id            = module.rds.rds_sg_id
  description                  = "PostgreSQL from Lambda"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = module.lambda.security_group_id
}

# S3 event notification — reports bucket triggers report_processor Lambda
# (avoids circular dep between s3 and lambda modules)
resource "aws_s3_bucket_notification" "reports_to_lambda" {
  bucket = module.s3.reports_bucket_name

  lambda_function {
    lambda_function_arn = module.lambda.report_processor_arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "reports/"
    filter_suffix       = ".json"
  }

  depends_on = [module.lambda]
}
