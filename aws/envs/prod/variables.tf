variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region — must be a US region per project jurisdiction requirements"
}

variable "name_prefix" {
  type        = string
  default     = "malware-sandbox"
  description = "Prefix applied to all resource names"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.20.0.0/16"
  description = "VPC CIDR block"
}

# -----------------------------------------------------------------------------
# S3 bucket names — must be globally unique across all AWS accounts
# -----------------------------------------------------------------------------

variable "samples_bucket_name" {
  type        = string
  description = "S3 bucket name for malware samples — must be globally unique"
}

variable "reports_bucket_name" {
  type        = string
  description = "S3 bucket name for Cape analysis reports — must be globally unique"
}

# -----------------------------------------------------------------------------
# RDS
# -----------------------------------------------------------------------------

variable "db_name" {
  type        = string
  default     = "sandbox_analysis"
  description = "PostgreSQL database name"
}

variable "db_username" {
  type        = string
  default     = "sandbox_admin"
  description = "PostgreSQL master username"
}

variable "db_instance_class" {
  type        = string
  default     = "db.t4g.micro"
  description = "RDS instance class — upgrade to t4g.small if query load increases"
}

# -----------------------------------------------------------------------------
# Lambda deployment packages
# Build these before running terraform apply:
#   cd src && zip report_processor.zip report_processor.py
#   cd src && zip sample_submitter.zip sample_submitter.py
# -----------------------------------------------------------------------------

variable "report_processor_zip" {
  type        = string
  default     = "../../src/report_processor.zip"
  description = "Path to report_processor Lambda deployment zip"
}

variable "sample_submitter_zip" {
  type        = string
  default     = "../../src/sample_submitter.zip"
  description = "Path to sample_submitter Lambda deployment zip"
}

# -----------------------------------------------------------------------------
# API throttling — tune to match bare metal capacity
# -----------------------------------------------------------------------------

variable "api_throttle_burst_limit" {
  type    = number
  default = 10
}

variable "api_throttle_rate_limit" {
  type    = number
  default = 5
}

variable "tags" {
  type    = map(string)
  default = {}
}
