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
