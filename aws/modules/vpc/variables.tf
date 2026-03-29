variable "name_prefix" {
  type        = string
  description = "Prefix applied to all resource names"
}

variable "vpc_cidr" {
  type        = string
  default     = "10.20.0.0/16"
  description = "CIDR block for the VPC"
}

variable "aws_region" {
  type        = string
  description = "AWS region — used to construct VPC endpoint service names"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources"
}
