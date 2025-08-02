# =============================================================================
# CLOUDWATCH TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
    cloudwatch_logs_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/cloudwatch/aws?version=5.3.1"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  cloudwatch_logs_key_arn = dependency.kms.outputs.cloudwatch_logs_key_arn
  
  monitoring_config = local.env_vars.locals.monitoring_config
  
  cloudwatch_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component           = "Monitoring"
      Service            = "CloudWatch"
      DevelopmentMonitoring = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS - PRIMARY LOG GROUP
# =============================================================================
inputs = {
  # We'll create individual CloudWatch resources using generate blocks
  create_log_group = false
}

# =============================================================================
# GENERATE COMPREHENSIVE CLOUDWATCH RESOURCES
# =============================================================================
generate "cloudwatch_development_resources" {
  path      = "cloudwatch_development_resources.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# CLOUDWATCH LOG GROUPS
# =============================================================================

# Application log group
resource "aws_cloudwatch_log_group" "application" {
  name              = "/aws/application/$${local.env_vars.locals.name_prefix}"
  retention_in_days = local.monitoring_config.log_retention_days
  kms_key_id       = local.cloudwatch_logs_key_arn

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-application-logs"
    Purpose = "ApplicationLogging"
  })
}

# System log group
resource "aws_cloudwatch_log_group" "system" {
  name              = "/aws/system/$${local.env_vars.locals.name_prefix}"
  retention_in_days = local.monitoring_config.log_retention_days
  kms_key_id       = local.cloudwatch_logs_key_arn

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-system-logs"
    Purpose = "SystemLogging"
  })
}

# Security log group
resource "aws_cloudwatch_log_group" "security" {
  name              = "/aws/security/$${local.env_vars.locals.name_prefix}"
  retention_in_days = 90  # Longer retention for security logs
  kms_key_id       = local.cloudwatch_logs_key_arn

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-security-logs"
    Purpose = "SecurityLogging"
  })
}

# Performance log group
resource "aws_cloudwatch_log_group" "performance" {
  name              = "/aws/performance/$${local.env_vars.locals.name_prefix}"
  retention_in_days = local.monitoring_config.log_retention_days
  kms_key_id       = local.cloudwatch_logs_key_arn

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-performance-logs"
    Purpose = "PerformanceLogging"
  })
}

# =============================================================================
# SNS TOPICS FOR ALERTS
# =============================================================================

# Critical alerts topic
resource "aws_sns_topic" "critical_alerts" {
  name = "$${local.env_vars.locals.name_prefix}-critical-alerts"

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-critical-alerts"
    Purpose = "CriticalAlerting"
  })
}

# Warning alerts topic
resource "aws_sns_topic" "warning_alerts" {
  name = "$${local.env_vars.locals.name_prefix}-warning-alerts"

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-warning-alerts"
    Purpose = "WarningAlerting"
  })
}

# Development alerts topic (for non-critical notifications)
resource "aws_sns_topic" "dev_alerts" {
  name = "$${local.env_vars.locals.name_prefix}-dev-alerts"

  tags = merge(local.cloudwatch_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-dev-alerts"
    Purpose = "DevelopmentAlerting"
  })
}

# SNS topic subscriptions (email)
resource "aws_sns_topic_subscription" "critical_email" {
  topic_arn = aws_sns_topic.critical_alerts.arn
  protocol  = "email"
  endpoint  = local.monitoring_config.alert_email
}

resource "aws_sns_topic_subscription" "warning_email" {
  topic_arn = aws_sns_topic.warning_alerts.arn
  protocol  = "email"
  endpoint  = local.monitoring_config.alert_email
}

resource "aws_sns_topic_subscription" "dev_email" {
  topic_arn = aws_sns_topic.dev_alerts.arn
  protocol  = "email"
  endpoint  = local.monitoring_config.alert_email
}

# =============================================================================
# CLOUDWATCH DASHBOARDS
# =============================================================================

# Main application dashboard
resource "aws_cloudwatch_dashboard" "application" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-application-dev"

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
            ["KatyaCleaning/Application/Development", "RequestCount"],
            [".", "ResponseTime"],
            [".", "ErrorRate"],
            [".", "ActiveUsers"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Application Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 6
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization"],
            [".", "NetworkIn"],
            [".", "NetworkOut"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "EC2 Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 6
        y      = 6
        width  = 6
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization"],
            [".", "DatabaseConnections"],
            [".", "ReadLatency"],
            [".", "WriteLatency"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "RDS Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 6

        properties = {
          query   = "SOURCE '/aws/application/$${local.env_vars.locals.name_prefix}' | fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp desc | limit 20"
          region  = local.aws_region
          title   = "Recent Application Errors"
          view    = "table"
        }
      }
    ]
  })
}

# Infrastructure dashboard
resource "aws_cloudwatch_dashboard" "infrastructure" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-infrastructure-dev"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount"],
            [".", "TargetResponseTime"],
            [".", "HTTPCode_Target_2XX_Count"],
            [".", "HTTPCode_Target_4XX_Count"],
            [".", "HTTPCode_Target_5XX_Count"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Load Balancer Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["AWS/AutoScaling", "GroupDesiredCapacity"],
            [".", "GroupInServiceInstances"],
            [".", "GroupTotalInstances"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Auto Scaling Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["AWS/ElastiCache", "CPUUtilization"],
            [".", "DatabaseMemoryUsagePercentage"],
            [".", "NetworkBytesIn"],
            [".", "NetworkBytesOut"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "ElastiCache Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Security dashboard
resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-security-dev"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "log"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          query   = "SOURCE '/aws/security/$${local.env_vars.locals.name_prefix}' | fields @timestamp, @message | filter @message like /FAILED_LOGIN/ | sort @timestamp desc | limit 20"
          region  = local.aws_region
          title   = "Failed Login Attempts"
          view    = "table"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          query   = "SOURCE '/aws/security/$${local.env_vars.locals.name_prefix}' | fields @timestamp, @message | filter @message like /SUSPICIOUS/ | sort @timestamp desc | limit 20"
          region  = local.aws_region
          title   = "Suspicious Activities"
          view    = "table"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6

        properties = {
          metrics = [
            ["KatyaCleaning/Security/Development", "FailedLogins"],
            [".", "SuspiciousActivities"],
            [".", "BlockedRequests"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Security Metrics"
          period  = 300
        }
      }
    ]
  })
}

# =============================================================================
# CLOUDWATCH ALARMS
# =============================================================================

# Application error rate alarm
resource "aws_cloudwatch_metric_alarm" "application_error_rate" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-application-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ErrorRate"
  namespace           = "KatyaCleaning/Application/Development"
  period              = "300"
  statistic           = "Average"
  threshold           = local.monitoring_config.error_rate_threshold
  alarm_description   = "Application error rate is high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]
  ok_actions          = [aws_sns_topic.dev_alerts.arn]

  tags = merge(local.cloudwatch_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-application-error-rate-alarm"
    Severity = "Warning"
  })
}

# Application response time alarm
resource "aws_cloudwatch_metric_alarm" "application_response_time" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-application-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ResponseTime"
  namespace           = "KatyaCleaning/Application/Development"
  period              = "300"
  statistic           = "Average"
  threshold           = local.monitoring_config.response_time_threshold
  alarm_description   = "Application response time is high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]
  ok_actions          = [aws_sns_topic.dev_alerts.arn]

  tags = merge(local.cloudwatch_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-application-response-time-alarm"
    Severity = "Warning"
  })
}

# EC2 CPU utilization alarm
resource "aws_cloudwatch_metric_alarm" "ec2_cpu_utilization" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-ec2-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = local.monitoring_config.cpu_alarm_threshold
  alarm_description   = "EC2 CPU utilization is high"
  alarm_actions       = [aws_sns_topic.warning_alerts.arn]

  tags = merge(local.cloudwatch_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-cpu-alarm"
    Severity = "Warning"
  })
}

# RDS CPU utilization alarm
resource "aws_cloudwatch_metric_alarm" "rds_cpu_utilization" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-rds-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = local.monitoring_config.cpu_alarm_threshold
  alarm_description   = "RDS CPU utilization is high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  tags = merge(local.cloudwatch_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-rds-cpu-alarm"
    Severity = "Critical"
  })
}

# Disk space alarm
resource "aws_cloudwatch_metric_alarm" "disk_space_utilization" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-disk-space-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "DiskSpaceUtilization"
  namespace           = "System/Linux"
  period              = "300"
  statistic           = "Average"
  threshold           = local.monitoring_config.disk_alarm_threshold
  alarm_description   = "Disk space utilization is high"
  alarm_actions       = [aws_sns_topic.critical_alerts.arn]

  tags = merge(local.cloudwatch_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-disk-space-alarm"
    Severity = "Critical"
  })
}

# =============================================================================
# CLOUDWATCH INSIGHTS QUERIES
# =============================================================================

# Application error analysis query
resource "aws_cloudwatch_query_definition" "application_errors" {
  name = "$${local.env_vars.locals.name_prefix}-application-errors"

  log_group_names = [
    aws_cloudwatch_log_group.application.name
  ]

  query_string = <<EOF
fields @timestamp, @message, @requestId
| filter @message like /ERROR/
| stats count() by bin(5m)
| sort @timestamp desc
EOF
}

# Performance analysis query
resource "aws_cloudwatch_query_definition" "performance_analysis" {
  name = "$${local.env_vars.locals.name_prefix}-performance-analysis"

  log_group_names = [
    aws_cloudwatch_log_group.performance.name
  ]

  query_string = <<EOF
fields @timestamp, @message, @duration
| filter @type = "REPORT"
| stats avg(@duration), max(@duration), min(@duration) by bin(5m)
| sort @timestamp desc
EOF
}

# Security analysis query
resource "aws_cloudwatch_query_definition" "security_analysis" {
  name = "$${local.env_vars.locals.name_prefix}-security-analysis"

  log_group_names = [
    aws_cloudwatch_log_group.security.name
  ]

  query_string = <<EOF
fields @timestamp, @message, @sourceIP
| filter @message like /FAILED_LOGIN/ or @message like /SUSPICIOUS/
| stats count() by @sourceIP
| sort count desc
EOF
}

# Database slow query analysis
resource "aws_cloudwatch_query_definition" "database_slow_queries" {
  name = "$${local.env_vars.locals.name_prefix}-database-slow-queries"

  log_group_names = [
    "/aws/rds/cluster/$${local.env_vars.locals.name_prefix}-aurora-dev/postgresql"
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /duration:/
| parse @message /duration: (?<duration>\\d+\\.\\d+) ms/
| filter duration > 1000
| sort @timestamp desc
| limit 20
EOF
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "application_log_group_name" {
  description = "Name of the application log group"
  value       = aws_cloudwatch_log_group.application.name
}

output "system_log_group_name" {
  description = "Name of the system log group"
  value       = aws_cloudwatch_log_group.system.name
}

output "security_log_group_name" {
  description = "Name of the security log group"
  value       = aws_cloudwatch_log_group.security.name
}

output "performance_log_group_name" {
  description = "Name of the performance log group"
  value       = aws_cloudwatch_log_group.performance.name
}

output "critical_alerts_topic_arn" {
  description = "ARN of the critical alerts SNS topic"
  value       = aws_sns_topic.critical_alerts.arn
}

output "warning_alerts_topic_arn" {
  description = "ARN of the warning alerts SNS topic"
  value       = aws_sns_topic.warning_alerts.arn
}

output "dev_alerts_topic_arn" {
  description = "ARN of the development alerts SNS topic"
  value       = aws_sns_topic.dev_alerts.arn
}

output "dashboard_urls" {
  description = "URLs to CloudWatch dashboards"
  value = {
    application    = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.application.dashboard_name}"
    infrastructure = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.infrastructure.dashboard_name}"
    security      = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.security.dashboard_name}"
  }
}

# Development-specific outputs
output "monitoring_features" {
  description = "Monitoring features enabled for development"
  value = {
    log_retention_days     = local.monitoring_config.log_retention_days
    detailed_monitoring    = local.monitoring_config.enable_detailed_monitoring
    debug_logging         = local.monitoring_config.enable_debug_logging
    performance_logging   = local.monitoring_config.enable_performance_logs
    insights_queries      = "enabled"
    custom_dashboards     = "3"
    alert_thresholds      = "development-optimized"
  }
}

output "query_definitions" {
  description = "CloudWatch Insights query definitions created"
  value = {
    application_errors    = aws_cloudwatch_query_definition.application_errors.name
    performance_analysis  = aws_cloudwatch_query_definition.performance_analysis.name
    security_analysis     = aws_cloudwatch_query_definition.security_analysis.name
    database_slow_queries = aws_cloudwatch_query_definition.database_slow_queries.name
  }
}
EOF
}
