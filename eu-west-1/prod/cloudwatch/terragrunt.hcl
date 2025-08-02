# =============================================================================
# CLOUDWATCH TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates CloudWatch log groups, dashboards, alarms, and monitoring
# configuration for comprehensive observability of the production environment.

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
  source = "tfr:///terraform-aws-modules/cloudwatch/aws?version=5.3.1"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # We'll use generate blocks to create comprehensive CloudWatch resources
  create_cloudwatch_log_group = false  # We'll create individual resources via generate
}

# =============================================================================
# GENERATE CLOUDWATCH RESOURCES
# =============================================================================
generate "cloudwatch_resources" {
  path      = "cloudwatch_resources.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# LOG GROUPS
# =============================================================================

# Application logs
resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/aws/ec2/application"
  retention_in_days = local.env_vars.locals.monitoring_config.log_retention_days
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-app-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    LogType   = "Application"
  })
}

# System logs
resource "aws_cloudwatch_log_group" "system_logs" {
  name              = "/aws/ec2/system"
  retention_in_days = local.env_vars.locals.monitoring_config.log_retention_days
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-system-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    LogType   = "System"
  })
}

# HTTP access logs
resource "aws_cloudwatch_log_group" "httpd_access_logs" {
  name              = "/aws/ec2/httpd/access"
  retention_in_days = local.env_vars.locals.monitoring_config.log_retention_days
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-httpd-access-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    LogType   = "Access"
  })
}

# HTTP error logs
resource "aws_cloudwatch_log_group" "httpd_error_logs" {
  name              = "/aws/ec2/httpd/error"
  retention_in_days = local.env_vars.locals.monitoring_config.log_retention_days
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-httpd-error-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    LogType   = "Error"
  })
}

# Lambda logs
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/$${local.name_prefix}-functions"
  retention_in_days = local.env_vars.locals.monitoring_config.log_retention_days
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-lambda-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    LogType   = "Lambda"
  })
}

# Route 53 query logs
resource "aws_cloudwatch_log_group" "route53_query_logs" {
  name              = "/aws/route53/queries"
  retention_in_days = 30  # DNS queries don't need long retention
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-route53-query-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    LogType   = "DNS"
  })
}

# =============================================================================
# CLOUDWATCH DASHBOARD
# =============================================================================
resource "aws_cloudwatch_dashboard" "main_dashboard" {
  dashboard_name = "$${local.name_prefix}-main-dashboard"

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
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", "$${local.name_prefix}-alb"],
            [".", "TargetResponseTime", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
            [".", "HTTPCode_Target_5XX_Count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Application Load Balancer Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "$${local.name_prefix}-web-asg"],
            [".", "NetworkIn", ".", "."],
            [".", "NetworkOut", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "EC2 Auto Scaling Group Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBClusterIdentifier", "$${local.name_prefix}-postgres-cluster"],
            [".", "DatabaseConnections", ".", "."],
            [".", "ReadLatency", ".", "."],
            [".", "WriteLatency", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "RDS Aurora Cluster Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ElastiCache", "CPUUtilization", "CacheClusterId", "$${local.name_prefix}-redis-001"],
            [".", "CurrConnections", ".", "."],
            [".", "CacheHits", ".", "."],
            [".", "CacheMisses", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "ElastiCache Redis Metrics"
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
          query   = "SOURCE '/aws/ec2/httpd/error' | fields @timestamp, @message | filter @message like /ERROR/ | sort @timestamp desc | limit 100"
          region  = local.aws_region
          title   = "Recent HTTP Errors"
          view    = "table"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-main-dashboard"
    Component = "Monitoring"
    Service   = "CloudWatch"
    Purpose   = "Main Dashboard"
  })
}

# =============================================================================
# CLOUDWATCH ALARMS
# =============================================================================

# High CPU utilization alarm
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "$${local.name_prefix}-high-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = "$${local.name_prefix}-web-asg"
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-high-cpu-alarm"
    Component = "Monitoring"
    Service   = "CloudWatch"
    AlarmType = "CPU"
  })
}

# High memory utilization alarm
resource "aws_cloudwatch_metric_alarm" "high_memory" {
  alarm_name          = "$${local.name_prefix}-high-memory-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "mem_used_percent"
  namespace           = "KatyaCleaning/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "85"
  alarm_description   = "This metric monitors ec2 memory utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = "$${local.name_prefix}-web-asg"
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-high-memory-alarm"
    Component = "Monitoring"
    Service   = "CloudWatch"
    AlarmType = "Memory"
  })
}

# High response time alarm
resource "aws_cloudwatch_metric_alarm" "high_response_time" {
  alarm_name          = "$${local.name_prefix}-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Average"
  threshold           = "2"
  alarm_description   = "This metric monitors ALB response time"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = "$${local.name_prefix}-alb"
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-high-response-time-alarm"
    Component = "Monitoring"
    Service   = "CloudWatch"
    AlarmType = "ResponseTime"
  })
}

# High error rate alarm
resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "$${local.name_prefix}-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors 5XX error rate"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    LoadBalancer = "$${local.name_prefix}-alb"
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-high-error-rate-alarm"
    Component = "Monitoring"
    Service   = "CloudWatch"
    AlarmType = "ErrorRate"
  })
}

# Database connection alarm
resource "aws_cloudwatch_metric_alarm" "high_db_connections" {
  alarm_name          = "$${local.name_prefix}-high-db-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS connection count"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  dimensions = {
    DBClusterIdentifier = "$${local.name_prefix}-postgres-cluster"
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-high-db-connections-alarm"
    Component = "Monitoring"
    Service   = "CloudWatch"
    AlarmType = "Database"
  })
}

# =============================================================================
# SNS TOPIC FOR ALERTS
# =============================================================================
resource "aws_sns_topic" "alerts" {
  name = "$${local.name_prefix}-alerts"
  
  kms_master_key_id = "alias/sns-encryption-key"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-alerts"
    Component = "Monitoring"
    Service   = "SNS"
    Purpose   = "Alerts"
  })
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = local.env_vars.locals.monitoring_config.alert_email
}

# =============================================================================
# CLOUDWATCH INSIGHTS QUERIES
# =============================================================================
resource "aws_cloudwatch_query_definition" "error_analysis" {
  name = "$${local.name_prefix}-error-analysis"

  log_group_names = [
    aws_cloudwatch_log_group.httpd_error_logs.name,
    aws_cloudwatch_log_group.app_logs.name
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /ERROR/
| stats count() by bin(5m)
| sort @timestamp desc
EOF

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-error-analysis-query"
    Component = "Monitoring"
    Service   = "CloudWatch"
    QueryType = "ErrorAnalysis"
  })
}

resource "aws_cloudwatch_query_definition" "performance_analysis" {
  name = "$${local.name_prefix}-performance-analysis"

  log_group_names = [
    aws_cloudwatch_log_group.httpd_access_logs.name
  ]

  query_string = <<EOF
fields @timestamp, @message
| filter @message like /GET|POST/
| parse @message /(?<ip>\S+) \S+ \S+ \[(?<timestamp>[^\]]+)\] "(?<method>\S+) (?<url>\S+) \S+" (?<status>\d+) (?<size>\d+) "(?<referer>[^"]*)" "(?<agent>[^"]*)"/
| filter status >= 200 and status < 400
| stats avg(size), count() by bin(5m)
| sort @timestamp desc
EOF

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-performance-analysis-query"
    Component = "Monitoring"
    Service   = "CloudWatch"
    QueryType = "PerformanceAnalysis"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.main_dashboard.dashboard_name}"
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "log_groups" {
  description = "List of created log groups"
  value = {
    app_logs         = aws_cloudwatch_log_group.app_logs.name
    system_logs      = aws_cloudwatch_log_group.system_logs.name
    httpd_access     = aws_cloudwatch_log_group.httpd_access_logs.name
    httpd_error      = aws_cloudwatch_log_group.httpd_error_logs.name
    lambda_logs      = aws_cloudwatch_log_group.lambda_logs.name
    route53_queries  = aws_cloudwatch_log_group.route53_query_logs.name
  }
}
EOF
}
