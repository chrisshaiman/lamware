# variables.tf
variable "samples_bucket_name"         { type = string }
variable "reports_bucket_name"         { type = string }
variable "kms_key_arn"                 { type = string }
variable "sandbox_role_arn"            { type = string }
variable "report_processor_lambda_arn" { type = string }
variable "tags"                        { type = map(string); default = {} }
