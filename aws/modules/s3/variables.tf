# variables.tf
variable "samples_bucket_name" { type = string }
variable "reports_bucket_name" { type = string }
variable "kms_key_arn"         { type = string }
variable "tags"                { type = map(string); default = {} }
# sandbox_role_arn and report_processor_lambda_arn intentionally absent —
# cross-module wiring is done in the composition layer to avoid circular deps
