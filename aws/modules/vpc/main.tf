# =============================================================================
# Module: vpc
# Private VPC for sandbox supporting infrastructure.
# RDS and Lambda live here. No internet gateway, no NAT gateway.
#
# All AWS service traffic stays within the VPC via endpoints:
#   - S3:              Gateway endpoint (free)
#   - SQS:             Interface endpoint (Lambda → job queue)
#   - Secrets Manager: Interface endpoint (Lambda → secrets at runtime)
#
# If external internet access is ever needed, add a NAT gateway to the
# public subnets. Public subnets are intentionally omitted for now.
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true  # Required for Interface Endpoint private DNS resolution

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}

# -----------------------------------------------------------------------------
# Subnets — two private AZs for RDS multi-AZ requirement and Lambda spread
# No public subnets: nothing in this VPC needs inbound internet access
# -----------------------------------------------------------------------------

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.this.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.tags, { Name = "${var.name_prefix}-private-${count.index}" })
}

data "aws_availability_zones" "available" {
  state = "available"
}

# -----------------------------------------------------------------------------
# Route table — private subnets have no default route (no NAT, no IGW)
# All routable traffic is intra-VPC or via VPC endpoints
# -----------------------------------------------------------------------------

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name_prefix}-private-rt" })
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# -----------------------------------------------------------------------------
# VPC Endpoints — keep all AWS API traffic off the internet
# -----------------------------------------------------------------------------

# S3 Gateway endpoint — free; Lambda reads/writes samples and reports buckets
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = merge(var.tags, { Name = "${var.name_prefix}-s3-endpoint" })
}

# Security group for Interface endpoints — accept 443 from within the VPC only
resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-endpoints-sg"
  description = "Allow HTTPS from within VPC to Interface endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-endpoints-sg" })
}

# SQS Interface endpoint — sample_submitter Lambda puts jobs here
resource "aws_vpc_endpoint" "sqs" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.sqs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true  # Lets Lambda use standard SDK endpoint URLs

  tags = merge(var.tags, { Name = "${var.name_prefix}-sqs-endpoint" })
}

# Secrets Manager Interface endpoint — Lambda fetches DB password and Cape API key
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-secretsmanager-endpoint" })
}

# -----------------------------------------------------------------------------
# VPC Flow Logs — log all traffic for forensic visibility
# -----------------------------------------------------------------------------

resource "aws_flow_log" "this" {
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/vpc/flow-logs/${var.name_prefix}"
  retention_in_days = 90
  tags              = var.tags
}

resource "aws_iam_role" "flow_log" {
  name = "${var.name_prefix}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_log" {
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}
