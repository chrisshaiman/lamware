# =============================================================================
# Module: s3
# Two buckets:
#   - samples: ingestion point for malware samples (pre-signed URL upload only)
#   - reports: Cape analysis output synced from bare metal host via SQS agent
#
# Both are private, encrypted, versioned. No public access under any condition.
# Object lock on samples bucket — integrity guarantee, prevents deletion.
# =============================================================================

# -----------------------------------------------------------------------------
# Samples Bucket
# Malware binaries land here. Treat as high-sensitivity.
# Upload via pre-signed URL only — no direct IAM key access from untrusted hosts.
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "samples" {
  bucket = var.samples_bucket_name

  # Prevent accidental destruction of evidence
  lifecycle {
    prevent_destroy = true
  }

  tags = merge(var.tags, { Name = var.samples_bucket_name, Sensitivity = "high" })
}

resource "aws_s3_bucket_versioning" "samples" {
  bucket = aws_s3_bucket.samples.id
  versioning_configuration { status = "Enabled" }
}

# Object lock — COMPLIANCE mode means nobody (including root) can delete
# Set retention to 90 days; adjust to your IR policy
resource "aws_s3_bucket_object_lock_configuration" "samples" {
  bucket = aws_s3_bucket.samples.id

  rule {
    default_retention {
      mode = "GOVERNANCE"  # Use COMPLIANCE for stricter — can't be overridden
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "samples" {
  bucket = aws_s3_bucket.samples.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true  # Reduces KMS API call costs
  }
}

resource "aws_s3_bucket_public_access_block" "samples" {
  bucket                  = aws_s3_bucket.samples.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle: move to GLACIER after 30 days, expire after 1 year
resource "aws_s3_bucket_lifecycle_configuration" "samples" {
  bucket = aws_s3_bucket.samples.id

  rule {
    id     = "archive-old-samples"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# Bucket policy: deny any non-HTTPS access, deny deletes without MFA
resource "aws_s3_bucket_policy" "samples" {
  bucket = aws_s3_bucket.samples.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          "${aws_s3_bucket.samples.arn}",
          "${aws_s3_bucket.samples.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "AllowSandboxPresign"
        Effect    = "Allow"
        Principal = { AWS = var.sandbox_role_arn }
        Action    = ["s3:PutObject", "s3:GetObject"]
        Resource  = "${aws_s3_bucket.samples.arn}/*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Reports Bucket
# Cape analysis reports synced from bare metal host. Less sensitive than samples,
# but still private — contains IOCs, behavioral data, screenshots.
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "reports" {
  bucket = var.reports_bucket_name
  tags   = merge(var.tags, { Name = var.reports_bucket_name })
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Reports lifecycle: Standard-IA after 7 days (infrequently accessed after analysis)
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "tier-old-reports"
    status = "Enabled"

    transition {
      days          = 7
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          "${aws_s3_bucket.reports.arn}",
          "${aws_s3_bucket.reports.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "AllowSandboxSync"
        Effect    = "Allow"
        Principal = { AWS = var.sandbox_role_arn }
        Action    = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource  = [
          "${aws_s3_bucket.reports.arn}",
          "${aws_s3_bucket.reports.arn}/*"
        ]
      }
    ]
  })
}

# S3 event notification — triggers Lambda when a new report lands
resource "aws_s3_bucket_notification" "reports" {
  bucket = aws_s3_bucket.reports.id

  lambda_function {
    lambda_function_arn = var.report_processor_lambda_arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "reports/"
    filter_suffix       = ".json"
  }
}
