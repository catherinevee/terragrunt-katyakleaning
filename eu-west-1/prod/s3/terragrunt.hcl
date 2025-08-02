# =============================================================================
# S3 TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates S3 buckets for static assets, backups, and application
# data with encryption, versioning, and lifecycle policies.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/s3-bucket/aws?version=4.1.2"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # PRIMARY APPLICATION BUCKET
  # =============================================================================
  bucket = "${local.name_prefix}-app-assets"
  
  # Access control
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  
  # Block public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # =============================================================================
  # VERSIONING CONFIGURATION
  # =============================================================================
  versioning = {
    enabled = true
  }
  
  # =============================================================================
  # ENCRYPTION CONFIGURATION
  # =============================================================================
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = "alias/s3-encryption-key"
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
  
  # =============================================================================
  # LIFECYCLE CONFIGURATION
  # =============================================================================
  lifecycle_configuration = {
    rule = [
      {
        id     = "main_lifecycle"
        status = "Enabled"
        
        filter = {
          prefix = ""
        }
        
        transition = [
          {
            days          = local.env_vars.locals.cost_config.storage_class_transition.standard_to_ia
            storage_class = "STANDARD_IA"
          },
          {
            days          = local.env_vars.locals.cost_config.storage_class_transition.ia_to_glacier
            storage_class = "GLACIER"
          },
          {
            days          = local.env_vars.locals.cost_config.storage_class_transition.glacier_to_deep_archive
            storage_class = "DEEP_ARCHIVE"
          }
        ]
        
        noncurrent_version_transition = [
          {
            noncurrent_days = 30
            storage_class   = "STANDARD_IA"
          },
          {
            noncurrent_days = 60
            storage_class   = "GLACIER"
          }
        ]
        
        noncurrent_version_expiration = {
          noncurrent_days = 365
        }
      },
      {
        id     = "temp_files_cleanup"
        status = "Enabled"
        
        filter = {
          prefix = "temp/"
        }
        
        expiration = {
          days = 7
        }
      },
      {
        id     = "uploads_cleanup"
        status = "Enabled"
        
        filter = {
          prefix = "uploads/temp/"
        }
        
        expiration = {
          days = 1
        }
      }
    ]
  }
  
  # =============================================================================
  # INTELLIGENT TIERING
  # =============================================================================
  intelligent_tiering = {
    general = {
      status = "Enabled"
      filter = {
        prefix = "data/"
      }
      tiering = {
        ARCHIVE_ACCESS = {
          days = 90
        }
        DEEP_ARCHIVE_ACCESS = {
          days = 180
        }
      }
    }
  }
  
  # =============================================================================
  # CORS CONFIGURATION
  # =============================================================================
  cors_rule = [
    {
      allowed_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
      allowed_origins = local.env_vars.locals.app_config.allowed_origins
      allowed_headers = ["*"]
      expose_headers  = ["ETag", "x-amz-meta-*"]
      max_age_seconds = 3600
    }
  ]
  
  # =============================================================================
  # LOGGING CONFIGURATION
  # =============================================================================
  logging = {
    target_bucket = "${local.name_prefix}-access-logs"
    target_prefix = "s3-access-logs/"
  }
  
  # =============================================================================
  # NOTIFICATION CONFIGURATION
  # =============================================================================
  notification_configuration = {
    topic = [
      {
        topic_arn = "arn:aws:sns:${local.aws_region}:${local.aws_account_id}:s3-notifications"
        events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
        filter_prefix = "uploads/"
      }
    ]
    
    lambda_function = [
      {
        lambda_function_arn = "arn:aws:lambda:${local.aws_region}:${local.aws_account_id}:function:process-uploads"
        events             = ["s3:ObjectCreated:*"]
        filter_prefix      = "uploads/"
        filter_suffix      = ".jpg"
      }
    ]
  }
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-app-assets"
      Component      = "Storage"
      Service        = "S3"
      Purpose        = "Application Assets"
      Description    = "Primary S3 bucket for application assets and user uploads"
      Encryption     = "KMS"
      Versioning     = "Enabled"
      LifecyclePolicy = "Enabled"
      IntelligentTiering = "Enabled"
    }
  )
}

# =============================================================================
# GENERATE ADDITIONAL S3 BUCKETS
# =============================================================================
generate "additional_buckets" {
  path      = "additional_buckets.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# BACKUP BUCKET
# =============================================================================
module "backup_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.name_prefix}-backups"
  
  # Access control
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  
  # Block public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Versioning
  versioning = {
    enabled = true
  }
  
  # Encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = "alias/s3-backup-key"
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
  
  # Cross-region replication for disaster recovery
  replication_configuration = {
    role = "arn:aws:iam::$${local.aws_account_id}:role/s3-replication-role"
    
    rules = [
      {
        id       = "backup-replication"
        status   = "Enabled"
        priority = 10
        
        filter = {
          prefix = ""
        }
        
        destination = {
          bucket        = "arn:aws:s3:::$${local.name_prefix}-backups-dr"
          storage_class = "STANDARD_IA"
          
          encryption_configuration = {
            replica_kms_key_id = "alias/s3-backup-key"
          }
        }
      }
    ]
  }
  
  # Lifecycle for backup retention
  lifecycle_configuration = {
    rule = [
      {
        id     = "backup_retention"
        status = "Enabled"
        
        filter = {
          prefix = ""
        }
        
        transition = [
          {
            days          = 30
            storage_class = "STANDARD_IA"
          },
          {
            days          = 90
            storage_class = "GLACIER"
          },
          {
            days          = 365
            storage_class = "DEEP_ARCHIVE"
          }
        ]
        
        expiration = {
          days = 2555  # 7 years retention
        }
      }
    ]
  }
  
  tags = merge(local.common_tags, {
    Name        = "$${local.name_prefix}-backups"
    Component   = "Storage"
    Service     = "S3"
    Purpose     = "Backups"
    Replication = "Cross-Region"
    Retention   = "7-Years"
  })
}

# =============================================================================
# STATIC WEBSITE BUCKET
# =============================================================================
module "static_website_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.name_prefix}-static-website"
  
  # Website configuration
  website = {
    index_document = "index.html"
    error_document = "error.html"
  }
  
  # Public read access for website
  acl                      = "public-read"
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  
  # Allow public read access
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
  
  # Bucket policy for public read
  attach_policy = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::$${local.name_prefix}-static-website/*"
      }
    ]
  })
  
  # Encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # CORS for web access
  cors_rule = [
    {
      allowed_methods = ["GET", "HEAD"]
      allowed_origins = ["*"]
      allowed_headers = ["*"]
      max_age_seconds = 3600
    }
  ]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-static-website"
    Component = "Storage"
    Service   = "S3"
    Purpose   = "Static Website"
    Access    = "Public"
  })
}

# =============================================================================
# LOGS BUCKET
# =============================================================================
module "logs_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.name_prefix}-logs"
  
  # Access control
  acl                      = "log-delivery-write"
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  
  # Block public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Lifecycle for log retention
  lifecycle_configuration = {
    rule = [
      {
        id     = "log_retention"
        status = "Enabled"
        
        filter = {
          prefix = ""
        }
        
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
          days = 365
        }
      }
    ]
  }
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-logs"
    Component = "Storage"
    Service   = "S3"
    Purpose   = "Access Logs"
    Retention = "1-Year"
  })
}

# =============================================================================
# CLOUDFRONT LOGS BUCKET
# =============================================================================
module "cloudfront_logs_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "$${local.name_prefix}-cloudfront-logs"
  
  # Access control
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "BucketOwnerPreferred"
  
  # Block public access
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  # Encryption
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
  
  # Lifecycle for CloudFront log retention
  lifecycle_configuration = {
    rule = [
      {
        id     = "cloudfront_log_retention"
        status = "Enabled"
        
        filter = {
          prefix = ""
        }
        
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
          days = 365
        }
      }
    ]
  }
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-cloudfront-logs"
    Component = "Storage"
    Service   = "S3"
    Purpose   = "CloudFront Logs"
    Retention = "1-Year"
  })
}
EOF
}
