# =============================================================================
# S3 TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================

include "root" {
  path = find_in_parent_folders("root.hcl")
}

include "env" {
  path = find_in_parent_folders("env.hcl")
}

include "region" {
  path = find_in_parent_folders("region.hcl")
}

# =============================================================================
# DEPENDENCIES
# =============================================================================
dependency "kms" {
  config_path = "../kms"
  
  mock_outputs = {
    s3_key_arn        = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    s3_backup_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/87654321-4321-4321-4321-210987654321"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/s3-bucket/aws?version=4.1.2"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  s3_key_arn        = dependency.kms.outputs.s3_key_arn
  s3_backup_key_arn = dependency.kms.outputs.s3_backup_key_arn
  
  cost_config = local.env_vars.locals.cost_config
  
  s3_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component      = "Storage"
      Service        = "S3"
      DevelopmentS3  = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS - PRIMARY APPLICATION ASSETS BUCKET
# =============================================================================
inputs = {
  bucket = "${local.env_vars.locals.name_prefix}-app-assets"
  
  # Versioning
  versioning = {
    enabled = true
  }
  
  # Server-side encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = local.s3_key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
  
  # Lifecycle configuration
  lifecycle_configuration = {
    rule = [
      {
        id     = "app_assets_lifecycle"
        status = "Enabled"
        
        noncurrent_version_transition = [
          {
            days          = local.cost_config.storage_class_transition.standard_to_ia
            storage_class = "STANDARD_IA"
          },
          {
            days          = local.cost_config.storage_class_transition.ia_to_glacier
            storage_class = "GLACIER"
          }
        ]
        
        noncurrent_version_expiration = {
          days = 90  # Shorter for development
        }
      }
    ]
  }
  
  # CORS configuration
  cors_rule = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
      allowed_origins = local.env_vars.locals.app_config.allowed_origins
      expose_headers  = ["ETag"]
      max_age_seconds = 3000
    }
  ]
  
  # Public access block
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Tags
  tags = merge(local.s3_tags, {
    Name    = "${local.env_vars.locals.name_prefix}-app-assets"
    Purpose = "ApplicationAssets"
  })
}

# =============================================================================
# GENERATE ADDITIONAL S3 BUCKETS AND FEATURES
# =============================================================================
generate "additional_s3_buckets" {
  path      = "additional_s3_buckets.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# BACKUP BUCKET
# =============================================================================
module "backup_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.env_vars.locals.name_prefix}-backups"

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = local.s3_backup_key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }

  lifecycle_configuration = {
    rule = [
      {
        id     = "backup_lifecycle"
        status = "Enabled"

        transition = [
          {
            days          = 7
            storage_class = "STANDARD_IA"
          },
          {
            days          = 30
            storage_class = "GLACIER"
          },
          {
            days          = 90
            storage_class = "DEEP_ARCHIVE"
          }
        ]

        expiration = {
          days = 365  # 1 year retention for dev
        }

        noncurrent_version_expiration = {
          days = 30
        }
      }
    ]
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = merge(local.s3_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-backups"
    Purpose = "Backups"
  })
}

# =============================================================================
# STATIC WEBSITE BUCKET
# =============================================================================
module "static_website_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.env_vars.locals.name_prefix}-static-website"

  website = {
    index_document = "index.html"
    error_document = "error.html"
  }

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = local.s3_key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }

  cors_rule = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET", "HEAD"]
      allowed_origins = ["*"]
      expose_headers  = ["ETag"]
      max_age_seconds = 3600
    }
  ]

  # Public read access for static website
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false

  tags = merge(local.s3_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-static-website"
    Purpose = "StaticWebsite"
  })
}

# =============================================================================
# LOGS BUCKET
# =============================================================================
module "logs_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.env_vars.locals.name_prefix}-logs"

  versioning = {
    enabled = false  # Not needed for logs
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"  # Use AES256 for logs to reduce costs
      }
    }
  }

  lifecycle_configuration = {
    rule = [
      {
        id     = "logs_lifecycle"
        status = "Enabled"

        transition = [
          {
            days          = 7
            storage_class = "STANDARD_IA"
          },
          {
            days          = 30
            storage_class = "GLACIER"
          }
        ]

        expiration = {
          days = 90  # Shorter retention for dev logs
        }
      }
    ]
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = merge(local.s3_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-logs"
    Purpose = "Logging"
  })
}

# =============================================================================
# CLOUDFRONT LOGS BUCKET
# =============================================================================
module "cloudfront_logs_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.env_vars.locals.name_prefix}-cloudfront-logs"

  versioning = {
    enabled = false
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_configuration = {
    rule = [
      {
        id     = "cloudfront_logs_lifecycle"
        status = "Enabled"

        transition = [
          {
            days          = 30
            storage_class = "STANDARD_IA"
          },
          {
            days          = 90
            storage_class = "GLACIER"
          }
        ]

        expiration = {
          days = 180  # 6 months for CloudFront logs
        }
      }
    ]
  }

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = merge(local.s3_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-cloudfront-logs"
    Purpose = "CloudFrontLogs"
  })
}

# =============================================================================
# DEVELOPMENT-SPECIFIC BUCKET FOR TESTING
# =============================================================================
module "dev_testing_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.env_vars.locals.name_prefix}-dev-testing"

  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = local.s3_key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }

  lifecycle_configuration = {
    rule = [
      {
        id     = "dev_testing_lifecycle"
        status = "Enabled"

        expiration = {
          days = 7  # Very short retention for testing
        }

        noncurrent_version_expiration = {
          days = 1
        }

        abort_incomplete_multipart_upload = {
          days_after_initiation = 1
        }
      }
    ]
  }

  cors_rule = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
      allowed_origins = ["*"]  # Permissive for development
      expose_headers  = ["ETag", "x-amz-meta-*"]
      max_age_seconds = 300
    }
  ]

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  tags = merge(local.s3_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-dev-testing"
    Purpose = "DevelopmentTesting"
    AutoCleanup = "enabled"
  })
}

# =============================================================================
# BUCKET POLICIES
# =============================================================================

# Static website bucket policy for public read access
resource "aws_s3_bucket_policy" "static_website_policy" {
  bucket = module.static_website_bucket.s3_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "$${module.static_website_bucket.s3_bucket_arn}/*"
      }
    ]
  })
}

# =============================================================================
# BUCKET NOTIFICATIONS (DEVELOPMENT-SPECIFIC)
# =============================================================================

# SNS topic for S3 notifications
resource "aws_sns_topic" "s3_notifications" {
  name = "$${local.env_vars.locals.name_prefix}-s3-notifications"

  tags = merge(local.s3_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-s3-notifications"
    Purpose = "S3Notifications"
  })
}

# S3 bucket notification for app assets bucket
resource "aws_s3_bucket_notification" "app_assets_notification" {
  bucket = module.s3_bucket.s3_bucket_id

  topic {
    topic_arn     = aws_sns_topic.s3_notifications.arn
    events        = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    filter_prefix = "uploads/"
    filter_suffix = ".jpg"
  }

  topic {
    topic_arn     = aws_sns_topic.s3_notifications.arn
    events        = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    filter_prefix = "uploads/"
    filter_suffix = ".png"
  }

  depends_on = [aws_sns_topic_policy.s3_notifications]
}

# SNS topic policy to allow S3 to publish
resource "aws_sns_topic_policy" "s3_notifications" {
  arn = aws_sns_topic.s3_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.s3_notifications.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = local.aws_account_id
          }
        }
      }
    ]
  })
}

# =============================================================================
# CLOUDWATCH METRICS AND ALARMS
# =============================================================================

# CloudWatch Dashboard for S3 monitoring
resource "aws_cloudwatch_dashboard" "s3_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-s3-dev"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/S3", "BucketSizeBytes", "BucketName", module.s3_bucket.s3_bucket_id, "StorageType", "StandardStorage"],
            [".", "NumberOfObjects", ".", ".", ".", "AllStorageTypes"],
            [".", "BucketSizeBytes", ".", module.backup_bucket.s3_bucket_id, ".", "StandardStorage"],
            [".", "NumberOfObjects", ".", ".", ".", "AllStorageTypes"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "S3 Bucket Metrics"
          period  = 86400
        }
      }
    ]
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "app_assets_bucket_id" {
  description = "ID of the app assets bucket"
  value       = module.s3_bucket.s3_bucket_id
}

output "app_assets_bucket_arn" {
  description = "ARN of the app assets bucket"
  value       = module.s3_bucket.s3_bucket_arn
}

output "backup_bucket_id" {
  description = "ID of the backup bucket"
  value       = module.backup_bucket.s3_bucket_id
}

output "backup_bucket_arn" {
  description = "ARN of the backup bucket"
  value       = module.backup_bucket.s3_bucket_arn
}

output "static_website_bucket_id" {
  description = "ID of the static website bucket"
  value       = module.static_website_bucket.s3_bucket_id
}

output "static_website_bucket_arn" {
  description = "ARN of the static website bucket"
  value       = module.static_website_bucket.s3_bucket_arn
}

output "static_website_bucket_website_endpoint" {
  description = "Website endpoint of the static website bucket"
  value       = module.static_website_bucket.s3_bucket_website_endpoint
}

output "logs_bucket_id" {
  description = "ID of the logs bucket"
  value       = module.logs_bucket.s3_bucket_id
}

output "logs_bucket_arn" {
  description = "ARN of the logs bucket"
  value       = module.logs_bucket.s3_bucket_arn
}

output "cloudfront_logs_bucket_id" {
  description = "ID of the CloudFront logs bucket"
  value       = module.cloudfront_logs_bucket.s3_bucket_id
}

output "cloudfront_logs_bucket_arn" {
  description = "ARN of the CloudFront logs bucket"
  value       = module.cloudfront_logs_bucket.s3_bucket_arn
}

output "dev_testing_bucket_id" {
  description = "ID of the development testing bucket"
  value       = module.dev_testing_bucket.s3_bucket_id
}

output "dev_testing_bucket_arn" {
  description = "ARN of the development testing bucket"
  value       = module.dev_testing_bucket.s3_bucket_arn
}

output "s3_notifications_topic_arn" {
  description = "ARN of the S3 notifications SNS topic"
  value       = aws_sns_topic.s3_notifications.arn
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.s3_development.dashboard_name}"
}

# Development-specific outputs
output "bucket_summary" {
  description = "Summary of all S3 buckets created"
  value = {
    app_assets      = module.s3_bucket.s3_bucket_id
    backups        = module.backup_bucket.s3_bucket_id
    static_website = module.static_website_bucket.s3_bucket_id
    logs           = module.logs_bucket.s3_bucket_id
    cloudfront_logs = module.cloudfront_logs_bucket.s3_bucket_id
    dev_testing    = module.dev_testing_bucket.s3_bucket_id
  }
}
EOF
}
