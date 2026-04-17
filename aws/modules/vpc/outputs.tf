output "vpc_id" {
  value       = aws_vpc.this.id
  description = "VPC ID — passed to RDS, Lambda, and endpoint security groups"
}

output "private_subnet_ids" {
  value       = aws_subnet.private[*].id
  description = "Private subnet IDs — used by RDS subnet group and Lambda VPC config"
}

output "private_route_table_id" {
  value       = aws_route_table.private.id
  description = "Private route table ID — referenced by any additional Gateway endpoints"
}

output "s3_prefix_list_id" {
  value       = aws_vpc_endpoint.s3.prefix_list_id
  description = "S3 Gateway endpoint prefix list ID — needed for security group egress rules (S3 uses public IPs routed through the gateway, not VPC-internal IPs)"
}
