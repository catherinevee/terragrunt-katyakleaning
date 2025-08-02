# =============================================================================
# ELASTICACHE TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates a Redis ElastiCache cluster for session storage and
# application caching in the production environment.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# Dependencies
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id           = "vpc-mock"
    private_subnets  = ["subnet-mock-1", "subnet-mock-2"]
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    cache_security_group_id = "sg-mock-cache"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/elasticache/aws?version=1.2.0"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC CLUSTER CONFIGURATION
  # =============================================================================
  create = true
  
  # Cluster identification
  cluster_id   = "${local.name_prefix}-redis"
  description  = "Redis cluster for Katya Cleaning Services production environment"
  
  # Engine configuration
  engine               = "redis"
  engine_version       = "7.0"
  node_type           = local.env_vars.locals.instance_types.cache
  port                = 6379
  parameter_group_name = "default.redis7"
  
  # =============================================================================
  # CLUSTER TOPOLOGY
  # =============================================================================
  
  # Replication group for high availability
  create_replication_group = true
  num_cache_clusters      = 2
  
  # Multi-AZ configuration
  multi_az_enabled           = true
  automatic_failover_enabled = true
  
  # =============================================================================
  # NETWORK CONFIGURATION
  # =============================================================================
  
  # Subnet group
  create_subnet_group = true
  subnet_group_name   = "${local.name_prefix}-redis-subnet-group"
  subnet_ids          = dependency.vpc.outputs.private_subnets
  
  # Security groups
  security_group_ids = [dependency.security_groups.outputs.cache_security_group_id]
  
  # =============================================================================
  # SECURITY CONFIGURATION
  # =============================================================================
  
  # Encryption at rest
  at_rest_encryption_enabled = true
  kms_key_id                = "alias/elasticache-encryption-key"
  
  # Encryption in transit
  transit_encryption_enabled = true
  
  # Authentication
  auth_token_enabled = true
  auth_token         = null  # Will be auto-generated and stored in Secrets Manager
  
  # =============================================================================
  # BACKUP AND MAINTENANCE
  # =============================================================================
  
  # Snapshot configuration
  snapshot_retention_limit = 7
  snapshot_window         = "03:00-05:00"  # UTC
  
  # Maintenance window
  maintenance_window = "sun:05:00-sun:07:00"  # UTC
  
  # Automatic minor version upgrades
  auto_minor_version_upgrade = true
  
  # =============================================================================
  # PERFORMANCE AND MONITORING
  # =============================================================================
  
  # CloudWatch logs
  log_delivery_configuration = [
    {
      destination      = "/aws/elasticache/redis/slow-log"
      destination_type = "cloudwatch-logs"
      log_format      = "text"
      log_type        = "slow-log"
    }
  ]
  
  # Notification configuration
  notification_topic_arn = "arn:aws:sns:${local.aws_region}:${local.aws_account_id}:elasticache-notifications"
  
  # =============================================================================
  # PARAMETER GROUP CONFIGURATION
  # =============================================================================
  
  # Custom parameter group
  create_parameter_group = true
  parameter_group_family = "redis7"
  
  parameters = [
    {
      name  = "maxmemory-policy"
      value = "allkeys-lru"
    },
    {
      name  = "timeout"
      value = "300"
    },
    {
      name  = "tcp-keepalive"
      value = "300"
    },
    {
      name  = "maxclients"
      value = "1000"
    }
  ]
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-redis"
      Component      = "Cache"
      Service        = "ElastiCache"
      Engine         = "Redis"
      EngineVersion  = "7.0"
      Description    = "Production Redis cluster for session storage and caching"
      NodeType       = local.env_vars.locals.instance_types.cache
      MultiAZ        = "true"
      Encryption     = "Enabled"
      BackupSchedule = "03:00-05:00 UTC"
      MaintenanceWindow = "Sunday 05:00-07:00 UTC"
    }
  )
}
