variable "name_prefix" {
  type        = string
  description = "Prefix applied to all resource names"
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Tags applied to all resources"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for CloudWatch access log encryption"
}

variable "sample_submitter_invoke_arn" {
  type        = string
  description = "Invoke ARN of the sample_submitter Lambda — from lambda module output"
}

variable "sample_submitter_function_name" {
  type        = string
  description = "Function name of sample_submitter — used in the Lambda invoke permission"
}

variable "throttle_burst_limit" {
  type        = number
  default     = 10
  description = "Maximum concurrent requests allowed before throttling. Keep low — one bare metal host has finite capacity."
}

variable "throttle_rate_limit" {
  type        = number
  default     = 5
  description = "Sustained requests per second. Tune upward if you add more bare metal capacity."
}
