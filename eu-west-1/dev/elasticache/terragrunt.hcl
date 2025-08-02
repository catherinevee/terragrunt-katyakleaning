# =============================================================================
# ELASTICACHE TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id           = "vpc-12345678"
    private_subnets  = ["subnet-11111111", "subnet-22222222"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    cache_security_group_id = "sg-44444444"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "kms" {
  config_path = "../kms"
  
  mock_outputs = {
    elasticache_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/elasticache/aws?version=1.2.0"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  vpc_id          = dependency.vpc.outputs.vpc_id
  private_subnets = dependency.vpc.outputs.private_subnets
  cache_sg_id     = dependency.security_groups.outputs.cache_security_group_id
  kms_key_arn     = dependency.kms.outputs.elasticache_key_arn
  
  cache_config = local.env_vars.locals.cache_config
  
  cache_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component      = "Cache"
      Service        = "ElastiCache"
      Engine         = "Redis"
      EngineVersion  = local.cache_config.engine_version
      NodeType       = local.cache_config.node_type
      DevelopmentCache = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # Basic configuration
  cluster_id           = "${local.env_vars.locals.name_prefix}-redis-dev"
  description         = "Development Redis cluster for ${local.env_vars.locals.app_config.app_name}"
  
  # Engine configuration
  engine               = "redis"
  engine_version       = local.cache_config.engine_version
  node_type           = local.cache_config.node_type
  num_cache_nodes     = local.cache_config.num_cache_clusters
  port                = local.cache_config.port
  
  # Network configuration
  subnet_group_name   = "${local.env_vars.locals.name_prefix}-redis-subnet-group"
  subnet_ids          = local.private_subnets
  security_group_ids  = [local.cache_sg_id]
  
  # Parameter group
  parameter_group_name = "${local.env_vars.locals.name_prefix}-redis-params"
  parameter_group_family = local.cache_config.parameter_group_family
  
  # Security
  at_rest_encryption_enabled  = local.cache_config.at_rest_encryption_enabled
  transit_encryption_enabled  = local.cache_config.transit_encryption_enabled
  kms_key_id                 = local.kms_key_arn
  
  # Backup and maintenance
  snapshot_retention_limit = local.cache_config.snapshot_retention_limit
  snapshot_window         = local.cache_config.snapshot_window
  maintenance_window      = local.cache_config.maintenance_window
  
  # Multi-AZ configuration
  multi_az_enabled           = local.cache_config.multi_az_enabled
  automatic_failover_enabled = local.cache_config.automatic_failover_enabled
  
  # Notification
  notification_topic_arn = ""
  
  # Tags
  tags = local.cache_tags
}

# =============================================================================
# GENERATE ADDITIONAL CACHE RESOURCES
# =============================================================================
generate "cache_development_features" {
  path      = "cache_development_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# Development-specific ElastiCache parameter group
resource "aws_elasticache_parameter_group" "development" {
  family = local.cache_config.parameter_group_family
  name   = "$${local.env_vars.locals.name_prefix}-redis-dev-params"
  description = "Development Redis parameter group"

  dynamic "parameter" {
    for_each = local.cache_config.parameters
    content {
      name  = parameter.key
      value = parameter.value
    }
  }

  tags = merge(local.cache_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-redis-dev-params"
    Type = "ParameterGroup"
  })
}

# CloudWatch Dashboard for Redis monitoring
resource "aws_cloudwatch_dashboard" "redis_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-redis-dev"

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
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", module.elasticache.cluster_id],
            [".", "DatabaseMemoryUsagePercentage", ".", "."],
            [".", "NetworkBytesIn", ".", "."],
            [".", "NetworkBytesOut", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Redis Cluster Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Development-specific CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-redis-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Redis CPU utilization is high"
  alarm_actions       = []

  dimensions = {
    CacheClusterId = module.elasticache.cluster_id
  }

  tags = merge(local.cache_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-redis-cpu-alarm"
  })
}

# Store Redis connection details in SSM
resource "aws_ssm_parameter" "redis_endpoint" {
  name  = "/$${local.env_vars.locals.name_prefix}/cache/endpoint"
  type  = "String"
  value = module.elasticache.cluster_address
  description = "Redis cluster endpoint"

  tags = merge(local.cache_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-redis-endpoint"
  })
}

resource "aws_ssm_parameter" "redis_port" {
  name  = "/$${local.env_vars.locals.name_prefix}/cache/port"
  type  = "String"
  value = tostring(local.cache_config.port)
  description = "Redis port"

  tags = merge(local.cache_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-redis-port"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "cluster_id" {
  description = "Redis cluster ID"
  value       = module.elasticache.cluster_id
}

output "cluster_address" {
  description = "Redis cluster endpoint address"
  value       = module.elasticache.cluster_address
}

output "cluster_port" {
  description = "Redis cluster port"
  value       = module.elasticache.cluster_port
}

output "parameter_group_name" {
  description = "Redis parameter group name"
  value       = aws_elasticache_parameter_group.development.name
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.redis_development.dashboard_name}"
}

output "connection_parameters" {
  description = "Redis connection parameters in SSM"
  value = {
    endpoint_parameter = aws_ssm_parameter.redis_endpoint.name
    port_parameter     = aws_ssm_parameter.redis_port.name
  }
}
EOF
}
