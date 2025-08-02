# =============================================================================
# ALB TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
    vpc_id         = "vpc-12345678"
    public_subnets = ["subnet-12345678", "subnet-87654321"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    alb_security_group_id = "sg-12345678"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/alb/aws?version=9.4.0"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  vpc_id         = dependency.vpc.outputs.vpc_id
  public_subnets = dependency.vpc.outputs.public_subnets
  alb_sg_id      = dependency.security_groups.outputs.alb_security_group_id
  
  domain_config = local.env_vars.locals.domain_config
  
  alb_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component      = "LoadBalancer"
      Service        = "ALB"
      LoadBalancerType = "application"
      DevelopmentALB = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # Basic configuration
  name               = "${local.env_vars.locals.name_prefix}-alb"
  load_balancer_type = "application"
  
  # Network configuration
  vpc_id  = local.vpc_id
  subnets = local.public_subnets
  security_groups = [local.alb_sg_id]
  
  # ALB configuration
  enable_deletion_protection = false  # Disabled for development
  enable_http2              = true
  enable_cross_zone_load_balancing = true
  
  # Access logs
  access_logs = {
    bucket  = "${local.env_vars.locals.name_prefix}-alb-logs"
    enabled = true
    prefix  = "alb-access-logs"
  }
  
  # Connection logs
  connection_logs = {
    bucket  = "${local.env_vars.locals.name_prefix}-alb-logs"
    enabled = true
    prefix  = "alb-connection-logs"
  }
  
  # Listeners
  http_tcp_listeners = [
    {
      port               = 80
      protocol           = "HTTP"
      action_type        = "redirect"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  ]
  
  https_listeners = [
    {
      port               = 443
      protocol           = "HTTPS"
      certificate_arn    = local.domain_config.certificate_arn
      ssl_policy         = local.env_vars.locals.security_config.ssl_policy
      action_type        = "forward"
      target_group_index = 0
    }
  ]
  
  # Target groups
  target_groups = [
    {
      name                 = "${local.env_vars.locals.name_prefix}-web-tg"
      backend_protocol     = "HTTP"
      backend_port         = 8080
      target_type          = "instance"
      deregistration_delay = 30  # Faster for development
      
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        interval            = 15  # More frequent for development
        matcher             = "200"
        path                = "/health"
        port                = "traffic-port"
        protocol            = "HTTP"
        timeout             = 5
        unhealthy_threshold = 3
      }
      
      stickiness = {
        enabled         = false
        cookie_duration = 86400
        type            = "lb_cookie"
      }
    }
  ]
  
  # Tags
  tags = local.alb_tags
}

# =============================================================================
# GENERATE ADDITIONAL ALB RESOURCES
# =============================================================================
generate "alb_development_features" {
  path      = "alb_development_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# S3 bucket for ALB access logs
resource "aws_s3_bucket" "alb_logs" {
  bucket = "$${local.env_vars.locals.name_prefix}-alb-logs"

  tags = merge(local.alb_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-alb-logs"
    Purpose = "ALBLogging"
  })
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" {
  bucket = aws_s3_bucket.alb_logs.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "log_lifecycle"
    status = "Enabled"

    expiration {
      days = 30  # Shorter retention for development
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# ALB access log policy
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::156460612806:root"  # ELB service account for eu-west-1
        }
        Action   = "s3:PutObject"
        Resource = "$${aws_s3_bucket.alb_logs.arn}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "$${aws_s3_bucket.alb_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# CloudWatch Dashboard for ALB monitoring
resource "aws_cloudwatch_dashboard" "alb_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-alb-dev"

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
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", module.alb.lb_arn_suffix],
            [".", "TargetResponseTime", ".", "."],
            [".", "HTTPCode_Target_2XX_Count", ".", "."],
            [".", "HTTPCode_Target_4XX_Count", ".", "."],
            [".", "HTTPCode_Target_5XX_Count", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "ALB Request Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Development-specific CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "alb_response_time" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-alb-high-response-time"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Average"
  threshold           = "2"  # 2 seconds
  alarm_description   = "ALB response time is high"
  alarm_actions       = []

  dimensions = {
    LoadBalancer = module.alb.lb_arn_suffix
  }

  tags = merge(local.alb_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-alb-response-time-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx_errors" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-alb-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "ALB 5XX error count is high"
  alarm_actions       = []

  dimensions = {
    LoadBalancer = module.alb.lb_arn_suffix
  }

  tags = merge(local.alb_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-alb-5xx-errors-alarm"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "lb_id" {
  description = "The ID and ARN of the load balancer"
  value       = module.alb.lb_id
}

output "lb_arn" {
  description = "The ARN of the load balancer"
  value       = module.alb.lb_arn
}

output "lb_dns_name" {
  description = "The DNS name of the load balancer"
  value       = module.alb.lb_dns_name
}

output "lb_zone_id" {
  description = "The zone ID of the load balancer"
  value       = module.alb.lb_zone_id
}

output "target_group_arns" {
  description = "ARNs of the target groups"
  value       = module.alb.target_group_arns
}

output "target_group_names" {
  description = "Names of the target groups"
  value       = module.alb.target_group_names
}

output "http_tcp_listener_arns" {
  description = "The ARNs of the HTTP TCP listeners"
  value       = module.alb.http_tcp_listener_arns
}

output "https_listener_arns" {
  description = "The ARNs of the HTTPS listeners"
  value       = module.alb.https_listener_arns
}

output "access_logs_bucket" {
  description = "S3 bucket for ALB access logs"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.alb_development.dashboard_name}"
}
EOF
}
