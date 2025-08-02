# =============================================================================
# KMS TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/kms/aws?version=2.2.1"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  kms_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component      = "Security"
      Service        = "KMS"
      DevelopmentKMS = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS - PRIMARY EBS KEY
# =============================================================================
inputs = {
  description = "KMS key for EBS encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow EC2 Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["ec2.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    }
  ]
  
  # Aliases
  aliases = ["ebs-key"]
  
  # Tags
  tags = merge(local.kms_tags, {
    Name    = "${local.env_vars.locals.name_prefix}-ebs-key"
    Purpose = "EBSEncryption"
  })
}

# =============================================================================
# GENERATE ADDITIONAL KMS KEYS
# =============================================================================
generate "additional_kms_keys" {
  path      = "additional_kms_keys.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# RDS ENCRYPTION KEY
# =============================================================================
module "rds_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for RDS encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow RDS Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["rds.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    }
  ]

  aliases = ["rds-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-rds-key"
    Purpose = "RDSEncryption"
  })
}

# =============================================================================
# S3 ENCRYPTION KEY
# =============================================================================
module "s3_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for S3 encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow S3 Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["s3.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    },
    {
      sid    = "Allow CloudFront Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["cloudfront.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      resources = ["*"]
    }
  ]

  aliases = ["s3-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-s3-key"
    Purpose = "S3Encryption"
  })
}

# =============================================================================
# S3 BACKUP ENCRYPTION KEY
# =============================================================================
module "s3_backup_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for S3 backup encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow S3 Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["s3.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    }
  ]

  aliases = ["s3-backup-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-s3-backup-key"
    Purpose = "S3BackupEncryption"
  })
}

# =============================================================================
# ELASTICACHE ENCRYPTION KEY
# =============================================================================
module "elasticache_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for ElastiCache encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow ElastiCache Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["elasticache.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    }
  ]

  aliases = ["elasticache-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-elasticache-key"
    Purpose = "ElastiCacheEncryption"
  })
}

# =============================================================================
# SECRETS MANAGER ENCRYPTION KEY
# =============================================================================
module "secrets_manager_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for Secrets Manager encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow Secrets Manager Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["secretsmanager.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    }
  ]

  aliases = ["secrets-manager-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-secrets-manager-key"
    Purpose = "SecretsManagerEncryption"
  })
}

# =============================================================================
# CLOUDWATCH LOGS ENCRYPTION KEY
# =============================================================================
module "cloudwatch_logs_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for CloudWatch Logs encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow CloudWatch Logs Service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["logs.$${local.aws_region}.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = ["*"]
      condition = {
        ArnEquals = {
          "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:$${local.aws_region}:$${local.aws_account_id}:log-group:*"
        }
      }
    }
  ]

  aliases = ["cloudwatch-logs-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-cloudwatch-logs-key"
    Purpose = "CloudWatchLogsEncryption"
  })
}

# =============================================================================
# TERRAGRUNT STATE ENCRYPTION KEY
# =============================================================================
module "terragrunt_state_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for Terragrunt state encryption in development environment"
  key_usage   = "ENCRYPT_DECRYPT"

  key_statements = [
    {
      sid    = "Enable IAM User Permissions"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:root"]
        }
      ]
      actions   = ["kms:*"]
      resources = ["*"]
    },
    {
      sid    = "Allow S3 Service for State"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["s3.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ]
      resources = ["*"]
    }
  ]

  aliases = ["terragrunt-state-key"]

  tags = merge(local.kms_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-terragrunt-state-key"
    Purpose = "TerragruntStateEncryption"
  })
}

# =============================================================================
# DEVELOPMENT-SPECIFIC KMS FEATURES
# =============================================================================

# KMS key rotation monitoring
resource "aws_cloudwatch_metric_alarm" "kms_key_rotation" {
  for_each = {
    ebs             = module.kms.key_id
    rds             = module.rds_key.key_id
    s3              = module.s3_key.key_id
    s3_backup       = module.s3_backup_key.key_id
    elasticache     = module.elasticache_key.key_id
    secrets_manager = module.secrets_manager_key.key_id
    cloudwatch_logs = module.cloudwatch_logs_key.key_id
    terragrunt_state = module.terragrunt_state_key.key_id
  }

  alarm_name          = "$${local.env_vars.locals.name_prefix}-kms-$${each.key}-rotation"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "KeyRotation"
  namespace           = "AWS/KMS"
  period              = "86400"  # Daily check
  statistic           = "Maximum"
  threshold           = "1"
  alarm_description   = "KMS key rotation check for $${each.key}"
  treat_missing_data  = "breaching"

  dimensions = {
    KeyId = each.value
  }

  tags = merge(local.kms_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-kms-$${each.key}-rotation-alarm"
    KeyType = each.key
  })
}

# CloudWatch Dashboard for KMS monitoring
resource "aws_cloudwatch_dashboard" "kms_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-kms-dev"

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
            ["AWS/KMS", "NumberOfRequestsSucceeded", "KeyId", module.kms.key_id],
            [".", "NumberOfRequestsFailed", ".", "."],
            [".", "NumberOfRequestsSucceeded", ".", module.rds_key.key_id],
            [".", "NumberOfRequestsFailed", ".", "."],
            [".", "NumberOfRequestsSucceeded", ".", module.s3_key.key_id],
            [".", "NumberOfRequestsFailed", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "KMS Key Usage Metrics"
          period  = 300
        }
      }
    ]
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "ebs_key_arn" {
  description = "The Amazon Resource Name (ARN) of the EBS KMS key"
  value       = module.kms.key_arn
}

output "ebs_key_id" {
  description = "The globally unique identifier for the EBS KMS key"
  value       = module.kms.key_id
}

output "rds_key_arn" {
  description = "The Amazon Resource Name (ARN) of the RDS KMS key"
  value       = module.rds_key.key_arn
}

output "rds_key_id" {
  description = "The globally unique identifier for the RDS KMS key"
  value       = module.rds_key.key_id
}

output "s3_key_arn" {
  description = "The Amazon Resource Name (ARN) of the S3 KMS key"
  value       = module.s3_key.key_arn
}

output "s3_key_id" {
  description = "The globally unique identifier for the S3 KMS key"
  value       = module.s3_key.key_id
}

output "s3_backup_key_arn" {
  description = "The Amazon Resource Name (ARN) of the S3 backup KMS key"
  value       = module.s3_backup_key.key_arn
}

output "s3_backup_key_id" {
  description = "The globally unique identifier for the S3 backup KMS key"
  value       = module.s3_backup_key.key_id
}

output "elasticache_key_arn" {
  description = "The Amazon Resource Name (ARN) of the ElastiCache KMS key"
  value       = module.elasticache_key.key_arn
}

output "elasticache_key_id" {
  description = "The globally unique identifier for the ElastiCache KMS key"
  value       = module.elasticache_key.key_id
}

output "secrets_manager_key_arn" {
  description = "The Amazon Resource Name (ARN) of the Secrets Manager KMS key"
  value       = module.secrets_manager_key.key_arn
}

output "secrets_manager_key_id" {
  description = "The globally unique identifier for the Secrets Manager KMS key"
  value       = module.secrets_manager_key.key_id
}

output "cloudwatch_logs_key_arn" {
  description = "The Amazon Resource Name (ARN) of the CloudWatch Logs KMS key"
  value       = module.cloudwatch_logs_key.key_arn
}

output "cloudwatch_logs_key_id" {
  description = "The globally unique identifier for the CloudWatch Logs KMS key"
  value       = module.cloudwatch_logs_key.key_id
}

output "terragrunt_state_key_arn" {
  description = "The Amazon Resource Name (ARN) of the Terragrunt state KMS key"
  value       = module.terragrunt_state_key.key_arn
}

output "terragrunt_state_key_id" {
  description = "The globally unique identifier for the Terragrunt state KMS key"
  value       = module.terragrunt_state_key.key_id
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.kms_development.dashboard_name}"
}

# Development-specific outputs
output "kms_keys_summary" {
  description = "Summary of all KMS keys created"
  value = {
    ebs             = module.kms.key_id
    rds             = module.rds_key.key_id
    s3              = module.s3_key.key_id
    s3_backup       = module.s3_backup_key.key_id
    elasticache     = module.elasticache_key.key_id
    secrets_manager = module.secrets_manager_key.key_id
    cloudwatch_logs = module.cloudwatch_logs_key.key_id
    terragrunt_state = module.terragrunt_state_key.key_id
  }
}

output "encryption_coverage" {
  description = "Services covered by KMS encryption"
  value = {
    ebs_volumes        = "encrypted"
    rds_databases      = "encrypted"
    s3_buckets         = "encrypted"
    s3_backups         = "encrypted"
    elasticache_data   = "encrypted"
    secrets_manager    = "encrypted"
    cloudwatch_logs    = "encrypted"
    terragrunt_state   = "encrypted"
  }
}
EOF
}
