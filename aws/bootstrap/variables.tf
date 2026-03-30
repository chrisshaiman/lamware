variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region — must match the region used in shared/backend-aws.hcl"
}
