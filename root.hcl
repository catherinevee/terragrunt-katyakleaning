# =============================================================================
# ROOT TERRAGRUNT CONFIGURATION
# =============================================================================
# This file contains the global configuration for all Terragrunt deployments
# across all environments and regions.

# =============================================================================
# KMS DEPENDENCY FOR SECURE STATE ENCRYPTION
# =============================================================================
dependency "kms" {
  config_path = "./kms"
  
  mock_outputs = {
    terragrunt_state_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    terragrunt_state_key_id  = "12345678-1234-1234-1234-123456789012"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "init"]
  mock_outputs_merge_strategy_with_state  = "shallow"
  
  # Skip dependency for KMS module itself to avoid circular dependency
  skip = get_env("TERRAGRUNT_WORKING_DIR", "") == "${get_parent_terragrunt_dir()}/kms"
}

locals {
  # Account-level configuration
  account_vars = read_terragrunt_config(find_in_parent_folders("account.hcl"))
  region_vars  = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  env_vars     = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  
  # Extract commonly used values
  aws_account_id = local.account_vars.locals.aws_account_id
  aws_region     = local.region_vars.locals.aws_region
  environment    = local.env_vars.locals.environment
  
  # KMS key for state encryption (with fallback for KMS module itself)
  terragrunt_state_key_arn = try(dependency.kms.outputs.terragrunt_state_key_arn, "alias/terragrunt-state-key")
  
  # S3 bucket names for state and audit logging
  state_bucket_name = "katyacleaning-terragrunt-state-${local.aws_account_id}"
  audit_logs_bucket_name = "katyacleaning-audit-logs-${local.aws_account_id}"
  
  # Global tags applied to all resources
  common_tags = {
    Environment   = local.environment
    ManagedBy     = "Terragrunt"
    Project       = "KatyaCleaning"
    Owner         = "Infrastructure Team"
    CostCenter    = "Operations"
    Compliance    = "SOC2"
    BackupPolicy  = "Standard"
    CreatedDate   = formatdate("YYYY-MM-DD", timestamp())
    SecurityLevel = "High"
    DataClass     = "Confidential"
  }
}

# =============================================================================
# REMOTE STATE CONFIGURATION
# =============================================================================
remote_state {
  backend = "s3"
  
  config = {
    # S3 bucket for storing Terraform state files
    bucket = local.state_bucket_name
    key    = "${path_relative_to_include()}/terraform.tfstate"
    region = local.aws_region
    
    # STEP 1: Dynamic KMS key management
    encrypt = true
    server_side_encryption_configuration = {
      rule = {
        apply_server_side_encryption_by_default = {
          kms_master_key_id = local.terragrunt_state_key_arn
          sse_algorithm     = "aws:kms"
        }
        bucket_key_enabled = true  # Cost optimization
      }
    }
    
    # STEP 2: Explicit S3 bucket policy for TLS-only access
    s3_bucket_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "DenyInsecureConnections"
          Effect    = "Deny"
          Principal = "*"
          Action    = "s3:*"
          Resource = [
            "arn:aws:s3:::${local.state_bucket_name}",
            "arn:aws:s3:::${local.state_bucket_name}/*"
          ]
          Condition = {
            Bool = {
              "aws:SecureTransport" = "false"
            }
          }
        },
        {
          Sid       = "RestrictToTerragruntOperations"
          Effect    = "Allow"
          Principal = {
            AWS = "arn:aws:iam::${local.aws_account_id}:root"
          }
          Action = [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucket",
            "s3:GetBucketVersioning",
            "s3:GetBucketLocation"
          ]
          Resource = [
            "arn:aws:s3:::${local.state_bucket_name}",
            "arn:aws:s3:::${local.state_bucket_name}/*"
          ]
          Condition = {
            Bool = {
              "aws:SecureTransport" = "true"
            }
          }
        }
      ]
    })
    
    # STEP 4: S3 access logging for audit trails
    s3_bucket_logging = {
      target_bucket = local.audit_logs_bucket_name
      target_prefix = "terragrunt-state-access/"
    }
    
    # DynamoDB table for state locking
    dynamodb_table = "katyacleaning-terragrunt-locks"
    
    # STEP 3: DynamoDB encryption at rest
    dynamodb_table_encryption = {
      enabled    = true
      kms_key_id = local.terragrunt_state_key_arn
    }
    
    # Enhanced security and reliability settings
    skip_bucket_versioning              = false
    skip_bucket_ssencryption           = false
    skip_bucket_root_access            = false
    skip_bucket_enforced_tls           = false
    skip_bucket_public_access_blocking = false
    
    # DynamoDB security enhancements
    enable_point_in_time_recovery = true
    dynamodb_table_tags = merge(local.common_tags, {
      Purpose           = "TerragruntStateLocking"
      SecurityLevel     = "Critical"
      EncryptionEnabled = "true"
      BackupEnabled     = "true"
    })
  }
  
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite_terragrunt"
  }
}

# =============================================================================
# PROVIDER CONFIGURATION
# =============================================================================
generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
terraform {
  required_version = ">= 1.13.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# AWS Provider Configuration
provider "aws" {
  region = "${local.aws_region}"
  
  # Assume role for cross-account access (if needed)
  assume_role {
    role_arn = "${local.account_vars.locals.aws_account_role}"
  }
  
  # Default tags applied to all resources
  default_tags {
    tags = {
      Environment   = "${local.environment}"
      ManagedBy     = "Terragrunt"
      Project       = "KatyaCleaning"
      Owner         = "Infrastructure Team"
      CostCenter    = "Operations"
      Compliance    = "SOC2"
      BackupPolicy  = "Standard"
      Region        = "${local.aws_region}"
      Account       = "${local.aws_account_id}"
    }
  }
}

# Random provider for generating unique resource names
provider "random" {}

# TLS provider for certificate generation
provider "tls" {}
EOF
}

# =============================================================================
# TERRAFORM CONFIGURATION
# =============================================================================
terraform {
  # Global Terraform configuration
  extra_arguments "common_vars" {
    commands = get_terraform_commands_that_need_vars()
    
    optional_var_files = [
      find_in_parent_folders("account.tfvars", "ignore"),
      find_in_parent_folders("region.tfvars", "ignore"),
      find_in_parent_folders("env.tfvars", "ignore"),
    ]
  }
  
  # Retry configuration for transient errors
  extra_arguments "retry" {
    commands = [
      "init",
      "apply",
      "refresh",
      "import",
      "plan",
      "taint",
      "untaint"
    ]
    
    arguments = [
      "-lock-timeout=20m"
    ]
  }
  
  # Parallelism configuration for performance
  extra_arguments "parallelism" {
    commands = [
      "apply",
      "plan",
      "destroy"
    ]
    
    arguments = [
      "-parallelism=10"
    ]
  }
}

# =============================================================================
# INPUTS AVAILABLE TO ALL MODULES
# =============================================================================
inputs = {
  # Global configuration
  aws_region     = local.aws_region
  aws_account_id = local.aws_account_id
  environment    = local.environment
  project_name   = "katyacleaning"
  
  # Common tags
  common_tags = local.common_tags
  
  # Naming convention
  name_prefix = "katyacleaning-${local.environment}"
  
  # Security settings
  enable_deletion_protection = local.environment == "prod" ? true : false
  enable_backup             = true
  enable_monitoring         = true
  enable_logging           = true
  
  # Network configuration
  availability_zones = ["${local.aws_region}a", "${local.aws_region}b", "${local.aws_region}c"]
  
  # Cost optimization
  enable_cost_optimization = true
  
  # Compliance and security
  compliance_framework = "SOC2"
  encryption_at_rest  = true
  encryption_in_transit = true
}
