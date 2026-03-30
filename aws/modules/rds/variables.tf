# variables.tf
variable "name_prefix"          { type = string }
variable "vpc_id"               { type = string }
variable "private_subnet_ids"   { type = list(string) }
# lambda_sg_id intentionally absent — ingress rule is added in the composition
# layer to avoid a circular dependency with the lambda module
variable "kms_key_arn"          { type = string }
variable "db_name"              { type = string; default = "sandbox_analysis" }
variable "db_username"          { type = string; default = "sandbox_admin" }
variable "db_password"          { type = string; sensitive = true }
variable "instance_class"       { type = string; default = "db.t4g.medium" }
variable "allocated_storage"    { type = number; default = 100 }
variable "max_allocated_storage"{ type = number; default = 500 }
variable "tags"                 { type = map(string); default = {} }
