# =============================================================================
# Module: rds
# PostgreSQL for storing structured analysis results, IOCs, job state.
# Private subnet only — no public endpoint, no internet route.
# Cape's own DB runs locally on the bare metal host. This DB is for your
# agent pipeline and API layer — normalized IOCs, enrichment results, etc.
# =============================================================================

# -----------------------------------------------------------------------------
# Security Group — only Lambda and admin CIDRs via VPN can reach 5432
# -----------------------------------------------------------------------------

resource "aws_security_group" "rds" {
  name        = "${var.name_prefix}-rds-sg"
  description = "RDS access — Lambda and admin VPN only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from Lambda SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.lambda_sg_id]
  }

  # Uncomment and set var.vpn_cidr if you want direct psql access over WireGuard
  # ingress {
  #   description = "PostgreSQL from admin VPN"
  #   from_port   = 5432
  #   to_port     = 5432
  #   protocol    = "tcp"
  #   cidr_blocks = [var.vpn_cidr]
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-rds-sg" })
}

# -----------------------------------------------------------------------------
# Subnet Group — private subnets only
# -----------------------------------------------------------------------------

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db-subnet-group"
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

# -----------------------------------------------------------------------------
# Parameter Group — tune for analysis workload
# Mostly read-heavy (agents query results); some write bursts (new reports)
# -----------------------------------------------------------------------------

resource "aws_db_parameter_group" "this" {
  name   = "${var.name_prefix}-pg16"
  family = "postgres16"

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_duration"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log queries > 1s
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# RDS Instance
# db.t4g.medium is a good starting point — upgrade to db.r7g.large
# if your IOC enrichment agents hammer it heavily
# -----------------------------------------------------------------------------

resource "aws_db_instance" "this" {
  identifier = "${var.name_prefix}-analysis-db"

  engine               = "postgres"
  engine_version       = "16"
  instance_class       = var.instance_class
  allocated_storage    = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage  # Autoscaling ceiling

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password  # Sourced from Secrets Manager in prod (see envs/prod)

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.this.name

  # Encryption at rest
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  # No public endpoint — ever
  publicly_accessible = false

  # Backups — 7 day retention, point-in-time recovery
  backup_retention_period   = 7
  backup_window             = "03:00-04:00"
  maintenance_window        = "sun:04:00-sun:05:00"
  delete_automated_backups  = false

  # Performance Insights — useful for identifying slow enrichment queries
  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = var.kms_key_arn

  # Logging to CloudWatch
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Prevent accidental deletion
  deletion_protection = true
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.name_prefix}-final-snapshot"

  tags = merge(var.tags, { Name = "${var.name_prefix}-analysis-db" })
}
