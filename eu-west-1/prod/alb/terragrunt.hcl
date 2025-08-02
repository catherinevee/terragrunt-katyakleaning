# =============================================================================
# APPLICATION LOAD BALANCER TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates an Application Load Balancer with SSL termination,
# health checks, and routing rules for the production environment.

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
    vpc_id         = "vpc-mock"
    public_subnets = ["subnet-mock-1", "subnet-mock-2"]
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    alb_security_group_id = "sg-mock-alb"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

dependency "kms" {
  config_path = "../kms"
  
  mock_outputs = {
    s3_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    s3_key_id  = "12345678-1234-1234-1234-123456789012"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  kms_s3_key_arn = dependency.kms.outputs.s3_key_arn
  kms_s3_key_id  = dependency.kms.outputs.s3_key_id
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/alb/aws?version=9.9.0"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC ALB CONFIGURATION
  # =============================================================================
  name               = "${local.name_prefix}-alb"
  load_balancer_type = "application"
  
  # Network configuration
  vpc_id  = dependency.vpc.outputs.vpc_id
  subnets = dependency.vpc.outputs.public_subnets
  
  # Security groups
  security_groups = [dependency.security_groups.outputs.alb_security_group_id]
  
  # =============================================================================
  # ALB ATTRIBUTES
  # =============================================================================
  
  # Performance and availability
  enable_cross_zone_load_balancing   = true
  enable_deletion_protection         = local.environment == "prod" ? true : false
  enable_http2                      = true
  enable_waf_fail_open              = false
  
  # Access logs
  access_logs = {
    bucket  = "${local.name_prefix}-alb-access-logs"
    enabled = true
    prefix  = "alb-logs"
  }
  
  # Connection logs
  connection_logs = {
    bucket  = "${local.name_prefix}-alb-connection-logs"
    enabled = true
    prefix  = "connection-logs"
  }
  
  # Timeouts
  idle_timeout                = 60
  enable_xff_client_port     = true
  preserve_host_header       = true
  
  # =============================================================================
  # TARGET GROUPS
  # =============================================================================
  target_groups = [
    {
      name             = "${local.name_prefix}-web-tg"
      backend_protocol = "HTTP"
      backend_port     = 8080
      target_type      = "instance"
      
      # Health check configuration
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        unhealthy_threshold = 3
        timeout             = 5
        interval            = 30
        path                = "/health"
        matcher             = "200"
        port                = "traffic-port"
        protocol            = "HTTP"
      }
      
      # Stickiness for session affinity
      stickiness = {
        enabled         = true
        cookie_duration = 3600
        type           = "lb_cookie"
      }
      
      # Target group attributes
      target_group_health_check_grace_period_seconds = 300
      target_group_health_check_enabled             = true
      
      tags = {
        Name      = "${local.name_prefix}-web-tg"
        Component = "LoadBalancer"
        Service   = "TargetGroup"
        Tier      = "Web"
      }
    },
    {
      name             = "${local.name_prefix}-api-tg"
      backend_protocol = "HTTP"
      backend_port     = 8080
      target_type      = "instance"
      
      # Health check configuration for API
      health_check = {
        enabled             = true
        healthy_threshold   = 2
        unhealthy_threshold = 3
        timeout             = 5
        interval            = 30
        path                = "/api/health"
        matcher             = "200"
        port                = "traffic-port"
        protocol            = "HTTP"
      }
      
      # No stickiness for API (stateless)
      stickiness = {
        enabled = false
        type    = "lb_cookie"
      }
      
      tags = {
        Name      = "${local.name_prefix}-api-tg"
        Component = "LoadBalancer"
        Service   = "TargetGroup"
        Tier      = "API"
      }
    }
  ]
  
  # =============================================================================
  # LISTENERS
  # =============================================================================
  
  # HTTP Listener (redirect to HTTPS)
  http_tcp_listeners = [
    {
      port        = 80
      protocol    = "HTTP"
      action_type = "redirect"
      redirect = {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  ]
  
  # HTTPS Listeners
  https_listeners = [
    {
      port               = 443
      protocol           = "HTTPS"
      certificate_arn    = "arn:aws:acm:${local.aws_region}:${local.aws_account_id}:certificate/12345678-1234-1234-1234-123456789012"  # Placeholder
      ssl_policy         = local.env_vars.locals.security_config.ssl_policy
      target_group_index = 0  # Default to web target group
    }
  ]
  
  # =============================================================================
  # LISTENER RULES
  # =============================================================================
  https_listener_rules = [
    {
      https_listener_index = 0
      priority            = 100
      
      actions = [
        {
          type               = "forward"
          target_group_index = 1  # API target group
        }
      ]
      
      conditions = [
        {
          path_patterns = ["/api/*"]
        }
      ]
    },
    {
      https_listener_index = 0
      priority            = 200
      
      actions = [
        {
          type               = "forward"
          target_group_index = 0  # Web target group
        }
      ]
      
      conditions = [
        {
          host_headers = ["admin.${local.env_vars.locals.domain_config.primary_domain}"]
        }
      ]
    },
    {
      https_listener_index = 0
      priority            = 300
      
      actions = [
        {
          type = "fixed-response"
          fixed_response = {
            content_type = "text/plain"
            message_body = "Maintenance Mode"
            status_code  = "503"
          }
        }
      ]
      
      conditions = [
        {
          path_patterns = ["/maintenance"]
        }
      ]
    }
  ]
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-alb"
      Component      = "LoadBalancer"
      Service        = "ALB"
      Description    = "Production Application Load Balancer for Katya Cleaning Services"
      Type           = "Application"
      Scheme         = "Internet-facing"
      IPAddressType  = "ipv4"
      SecurityLevel  = "High"
      SSLPolicy      = local.env_vars.locals.security_config.ssl_policy
    }
  )
}

# =============================================================================
# GENERATE S3 BUCKETS FOR ACCESS LOGS
# =============================================================================
generate "s3_buckets" {
  path      = "s3_buckets.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# S3 BUCKETS FOR ALB ACCESS LOGS
# =============================================================================

# ALB Access Logs Bucket
resource "aws_s3_bucket" "alb_access_logs" {
  bucket = "$${local.name_prefix}-alb-access-logs"
  
  tags = merge(local.common_tags, {
    Name        = "$${local.name_prefix}-alb-access-logs"
    Component   = "Storage"
    Service     = "S3"
    Purpose     = "ALB Access Logs"
    LogType     = "Access"
  })
}

resource "aws_s3_bucket_versioning" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = local.kms_s3_key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  rule {
    id     = "access_logs_lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "alb_access_logs" {
  bucket = aws_s3_bucket.alb_access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::156460612806:root"  # ELB service account for eu-west-1
        }
        Action   = "s3:PutObject"
        Resource = "$${aws_s3_bucket.alb_access_logs.arn}/alb-logs/AWSLogs/$${local.aws_account_id}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "$${aws_s3_bucket.alb_access_logs.arn}/alb-logs/AWSLogs/$${local.aws_account_id}/*"
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
        Resource = aws_s3_bucket.alb_access_logs.arn
      }
    ]
  })
}

# ALB Connection Logs Bucket
resource "aws_s3_bucket" "alb_connection_logs" {
  bucket = "$${local.name_prefix}-alb-connection-logs"
  
  tags = merge(local.common_tags, {
    Name        = "$${local.name_prefix}-alb-connection-logs"
    Component   = "Storage"
    Service     = "S3"
    Purpose     = "ALB Connection Logs"
    LogType     = "Connection"
  })
}

resource "aws_s3_bucket_versioning" "alb_connection_logs" {
  bucket = aws_s3_bucket.alb_connection_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "alb_connection_logs" {
  bucket = aws_s3_bucket.alb_connection_logs.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = local.kms_s3_key_arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_connection_logs" {
  bucket = aws_s3_bucket.alb_connection_logs.id

  rule {
    id     = "connection_logs_lifecycle"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}
EOF
}

# =============================================================================
# OUTPUTS
# =============================================================================

# Load Balancer Outputs
output "lb_arn" {
  description = "The ARN of the Application Load Balancer"
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

output "lb_id" {
  description = "The ID of the load balancer"
  value       = module.alb.lb_id
}

output "lb_arn_suffix" {
  description = "The ARN suffix of the load balancer"
  value       = module.alb.lb_arn_suffix
}

# Target Group Outputs
output "target_group_arns" {
  description = "ARNs of the target groups"
  value       = module.alb.target_group_arns
}

output "target_group_names" {
  description = "Names of the target groups"
  value       = module.alb.target_group_names
}

output "target_group_arn_suffixes" {
  description = "ARN suffixes of the target groups"
  value       = module.alb.target_group_arn_suffixes
}

output "web_target_group_arn" {
  description = "ARN of the web target group"
  value       = length(module.alb.target_group_arns) > 0 ? module.alb.target_group_arns[0] : null
}

output "api_target_group_arn" {
  description = "ARN of the API target group"
  value       = length(module.alb.target_group_arns) > 1 ? module.alb.target_group_arns[1] : null
}

# Listener Outputs
output "http_tcp_listener_arns" {
  description = "The ARNs of the HTTP TCP listeners"
  value       = module.alb.http_tcp_listener_arns
}

output "https_listener_arns" {
  description = "The ARNs of the HTTPS listeners"
  value       = module.alb.https_listener_arns
}

output "listener_rule_arns" {
  description = "The ARNs of the listener rules"
  value       = module.alb.https_listener_rule_arns
}

# Security Outputs
output "security_group_id" {
  description = "Security group ID attached to the ALB"
  value       = dependency.security_groups.outputs.alb_security_group_id
}

output "security_group_arn" {
  description = "Security group ARN attached to the ALB"
  value       = "arn:aws:ec2:${local.aws_region}:${local.aws_account_id}:security-group/${dependency.security_groups.outputs.alb_security_group_id}"
}

# Network Outputs
output "vpc_id" {
  description = "VPC ID where the ALB is deployed"
  value       = dependency.vpc.outputs.vpc_id
}

output "subnet_ids" {
  description = "Subnet IDs where the ALB is deployed"
  value       = dependency.vpc.outputs.public_subnets
}

# S3 Bucket Outputs
output "access_logs_bucket_name" {
  description = "Name of the S3 bucket for ALB access logs"
  value       = "${local.name_prefix}-alb-access-logs"
}

output "access_logs_bucket_arn" {
  description = "ARN of the S3 bucket for ALB access logs"
  value       = "arn:aws:s3:::${local.name_prefix}-alb-access-logs"
}

output "connection_logs_bucket_name" {
  description = "Name of the S3 bucket for ALB connection logs"
  value       = "${local.name_prefix}-alb-connection-logs"
}

output "connection_logs_bucket_arn" {
  description = "ARN of the S3 bucket for ALB connection logs"
  value       = "arn:aws:s3:::${local.name_prefix}-alb-connection-logs"
}

# Configuration Outputs
output "alb_configuration" {
  description = "ALB configuration summary"
  value = {
    name                = "${local.name_prefix}-alb"
    type                = "application"
    scheme              = "internet-facing"
    ip_address_type     = "ipv4"
    deletion_protection = local.environment == "prod" ? true : false
    http2_enabled       = true
    waf_enabled         = true
    access_logs_enabled = true
    ssl_policy          = local.env_vars.locals.security_config.ssl_policy
  }
}

output "target_groups_configuration" {
  description = "Target groups configuration summary"
  value = {
    web_target_group = {
      name             = "${local.name_prefix}-web-tg"
      port             = 8080
      protocol         = "HTTP"
      health_check_path = "/health"
      stickiness_enabled = true
    }
    api_target_group = {
      name             = "${local.name_prefix}-api-tg"
      port             = 8080
      protocol         = "HTTP"
      health_check_path = "/api/health"
      stickiness_enabled = false
    }
  }
}

output "routing_configuration" {
  description = "ALB routing configuration summary"
  value = {
    http_redirect = {
      enabled = true
      target_port = 443
      target_protocol = "HTTPS"
      status_code = "HTTP_301"
    }
    https_rules = [
      {
        priority = 100
        condition = "path:/api/*"
        action = "forward to api target group"
      },
      {
        priority = 200
        condition = "host:admin.${local.env_vars.locals.domain_config.primary_domain}"
        action = "forward to web target group"
      },
      {
        priority = 300
        condition = "path:/maintenance"
        action = "fixed response: 503"
      }
    ]
  }
}

# Monitoring and Logging Outputs
output "monitoring_configuration" {
  description = "Monitoring and logging configuration"
  value = {
    access_logs = {
      enabled = true
      bucket = "${local.name_prefix}-alb-access-logs"
      prefix = "alb-logs"
    }
    connection_logs = {
      enabled = true
      bucket = "${local.name_prefix}-alb-connection-logs"
      prefix = "connection-logs"
    }
    cloudwatch_metrics = {
      enabled = true
      namespace = "AWS/ApplicationELB"
    }
  }
}

# Integration Outputs for Other Modules
output "alb_integration_info" {
  description = "Information needed by other modules to integrate with this ALB"
  value = {
    alb_arn = module.alb.lb_arn
    alb_dns_name = module.alb.lb_dns_name
    alb_zone_id = module.alb.lb_zone_id
    alb_arn_suffix = module.alb.lb_arn_suffix
    target_group_arns = module.alb.target_group_arns
    listener_arns = module.alb.https_listener_arns
    security_group_id = dependency.security_groups.outputs.alb_security_group_id
  }
}
