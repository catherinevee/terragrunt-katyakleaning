# =============================================================================
# KMS TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates KMS encryption keys for various AWS services with
# proper key policies and aliases for the production environment.

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
  source = "tfr:///terraform-aws-modules/kms/aws?version=2.2.1"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # We'll use generate blocks to create multiple KMS keys
  create = false  # We'll create individual keys via generate
}

# =============================================================================
# GENERATE KMS KEYS AND POLICIES
# =============================================================================
generate "kms_keys" {
  path      = "kms_keys.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# EBS ENCRYPTION KEY
# =============================================================================
module "ebs_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for EBS volume encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for EBS"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-ec2-instance-role"]
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
      condition = [
        {
          test     = "StringEquals"
          variable = "kms:ViaService"
          values   = ["ec2.$${local.aws_region}.amazonaws.com"]
        }
      ]
    },
    {
      sid    = "Allow attachment of persistent resources"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = ["arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-ec2-instance-role"]
        }
      ]
      actions = [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ]
      resources = ["*"]
      condition = [
        {
          test     = "Bool"
          variable = "kms:GrantIsForAWSResource"
          values   = ["true"]
        }
      ]
    }
  ]
  
  # Aliases
  aliases = ["ebs-encryption-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-ebs-encryption-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "EBS Encryption"
  })
}

# =============================================================================
# RDS ENCRYPTION KEY
# =============================================================================
module "rds_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for RDS encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for RDS"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["rds.amazonaws.com"]
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
    },
    {
      sid    = "Allow RDS to create grants"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["rds.amazonaws.com"]
        }
      ]
      actions = [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant"
      ]
      resources = ["*"]
      condition = [
        {
          test     = "Bool"
          variable = "kms:GrantIsForAWSResource"
          values   = ["true"]
        }
      ]
    }
  ]
  
  # Aliases
  aliases = ["rds-encryption-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-rds-encryption-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "RDS Encryption"
  })
}

# =============================================================================
# S3 ENCRYPTION KEY
# =============================================================================
module "s3_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for S3 bucket encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for S3"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = [
            "arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-ec2-instance-role",
            "arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-lambda-execution-role"
          ]
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
      condition = [
        {
          test     = "StringEquals"
          variable = "kms:ViaService"
          values   = ["s3.$${local.aws_region}.amazonaws.com"]
        }
      ]
    },
    {
      sid    = "Allow S3 service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["s3.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]
      resources = ["*"]
    }
  ]
  
  # Aliases
  aliases = ["s3-encryption-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-s3-encryption-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "S3 Encryption"
  })
}

# =============================================================================
# S3 BACKUP ENCRYPTION KEY
# =============================================================================
module "s3_backup_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for S3 backup bucket encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for S3 backups"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = [
            "arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-s3-replication-role"
          ]
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
      condition = [
        {
          test     = "StringEquals"
          variable = "kms:ViaService"
          values   = [
            "s3.$${local.aws_region}.amazonaws.com",
            "s3.eu-west-2.amazonaws.com"
          ]
        }
      ]
    }
  ]
  
  # Aliases
  aliases = ["s3-backup-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-s3-backup-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "S3 Backup Encryption"
  })
}

# =============================================================================
# ELASTICACHE ENCRYPTION KEY
# =============================================================================
module "elasticache_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for ElastiCache encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for ElastiCache"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["elasticache.amazonaws.com"]
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
    }
  ]
  
  # Aliases
  aliases = ["elasticache-encryption-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-elasticache-encryption-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "ElastiCache Encryption"
  })
}

# =============================================================================
# SECRETS MANAGER ENCRYPTION KEY
# =============================================================================
module "secrets_manager_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for Secrets Manager encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for Secrets Manager"
      effect = "Allow"
      principals = [
        {
          type        = "AWS"
          identifiers = [
            "arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-ec2-instance-role",
            "arn:aws:iam::$${local.aws_account_id}:role/$${local.name_prefix}-lambda-execution-role"
          ]
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
      condition = [
        {
          test     = "StringEquals"
          variable = "kms:ViaService"
          values   = ["secretsmanager.$${local.aws_region}.amazonaws.com"]
        }
      ]
    },
    {
      sid    = "Allow Secrets Manager service"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["secretsmanager.amazonaws.com"]
        }
      ]
      actions = [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]
      resources = ["*"]
    }
  ]
  
  # Aliases
  aliases = ["secrets-manager-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-secrets-manager-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "Secrets Manager Encryption"
  })
}

# =============================================================================
# TERRAGRUNT STATE ENCRYPTION KEY
# =============================================================================
module "terragrunt_state_encryption_key" {
  source = "terraform-aws-modules/kms/aws"
  version = "2.2.1"

  description = "KMS key for Terragrunt state encryption"
  key_usage   = "ENCRYPT_DECRYPT"
  
  # Key policy
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
      sid    = "Allow use of the key for Terragrunt state"
      effect = "Allow"
      principals = [
        {
          type        = "Service"
          identifiers = ["s3.amazonaws.com"]
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
    }
  ]
  
  # Aliases
  aliases = ["terragrunt-state-key"]
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-terragrunt-state-key"
    Component = "Security"
    Service   = "KMS"
    Purpose   = "Terragrunt State Encryption"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "ebs_encryption_key_arn" {
  description = "ARN of the EBS encryption key"
  value       = module.ebs_encryption_key.key_arn
}

output "rds_encryption_key_arn" {
  description = "ARN of the RDS encryption key"
  value       = module.rds_encryption_key.key_arn
}

output "s3_encryption_key_arn" {
  description = "ARN of the S3 encryption key"
  value       = module.s3_encryption_key.key_arn
}

output "s3_backup_encryption_key_arn" {
  description = "ARN of the S3 backup encryption key"
  value       = module.s3_backup_encryption_key.key_arn
}

output "elasticache_encryption_key_arn" {
  description = "ARN of the ElastiCache encryption key"
  value       = module.elasticache_encryption_key.key_arn
}

output "secrets_manager_encryption_key_arn" {
  description = "ARN of the Secrets Manager encryption key"
  value       = module.secrets_manager_encryption_key.key_arn
}

output "terragrunt_state_encryption_key_arn" {
  description = "ARN of the Terragrunt state encryption key"
  value       = module.terragrunt_state_encryption_key.key_arn
}
EOF
}
