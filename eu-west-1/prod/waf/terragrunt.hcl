# =============================================================================
# WAF TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates AWS WAF v2 web ACL with comprehensive security rules
# to protect the application from common web attacks and threats.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# Dependencies
dependency "alb" {
  config_path = "../alb"
  
  mock_outputs = {
    lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/mock-alb/1234567890123456"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/wafv2/aws?version=1.1.0"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # WEB ACL CONFIGURATION
  # =============================================================================
  name  = "${local.name_prefix}-web-acl"
  scope = "REGIONAL"  # For ALB, use REGIONAL; for CloudFront, use CLOUDFRONT
  
  description = "WAF Web ACL for Katya Cleaning Services production environment"
  
  # =============================================================================
  # DEFAULT ACTION
  # =============================================================================
  default_action = "allow"
  
  # =============================================================================
  # MANAGED RULE GROUPS
  # =============================================================================
  rules = [
    # AWS Managed Core Rule Set
    {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 1
      
      override_action = "none"
      
      managed_rule_group_statement = {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        
        # Exclude specific rules if needed
        excluded_rule = []
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "CommonRuleSetMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # AWS Managed Known Bad Inputs Rule Set
    {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 2
      
      override_action = "none"
      
      managed_rule_group_statement = {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "KnownBadInputsRuleSetMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # AWS Managed SQL Injection Rule Set
    {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 3
      
      override_action = "none"
      
      managed_rule_group_statement = {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "SQLiRuleSetMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # AWS Managed Linux Operating System Rule Set
    {
      name     = "AWSManagedRulesLinuxRuleSet"
      priority = 4
      
      override_action = "none"
      
      managed_rule_group_statement = {
        name        = "AWSManagedRulesLinuxRuleSet"
        vendor_name = "AWS"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "LinuxRuleSetMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # Rate limiting rule
    {
      name     = "RateLimitRule"
      priority = 5
      
      action = "block"
      
      rate_based_statement = {
        limit              = 2000
        aggregate_key_type = "IP"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "RateLimitRuleMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # Geo-blocking rule (block specific countries if needed)
    {
      name     = "GeoBlockRule"
      priority = 6
      
      action = "block"
      
      geo_match_statement = {
        country_codes = ["CN", "RU", "KP", "IR"]  # Block specific countries
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoBlockRuleMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # IP reputation rule
    {
      name     = "AWSManagedRulesAmazonIpReputationList"
      priority = 7
      
      override_action = "none"
      
      managed_rule_group_statement = {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "IpReputationListMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # Anonymous IP list
    {
      name     = "AWSManagedRulesAnonymousIpList"
      priority = 8
      
      override_action = "none"
      
      managed_rule_group_statement = {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "AnonymousIpListMetric"
        sampled_requests_enabled   = true
      }
    }
  ]
  
  # =============================================================================
  # CUSTOM RULES
  # =============================================================================
  custom_rules = [
    # Block requests with suspicious user agents
    {
      name     = "BlockSuspiciousUserAgents"
      priority = 100
      
      action = "block"
      
      byte_match_statement = {
        search_string = "bot"
        field_to_match = {
          single_header = {
            name = "user-agent"
          }
        }
        text_transformation = [
          {
            priority = 1
            type     = "LOWERCASE"
          }
        ]
        positional_constraint = "CONTAINS"
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "BlockSuspiciousUserAgentsMetric"
        sampled_requests_enabled   = true
      }
    },
    
    # Allow only specific HTTP methods
    {
      name     = "AllowedHTTPMethods"
      priority = 101
      
      action = "block"
      
      not_statement = {
        byte_match_statement = {
          search_string = "GET"
          field_to_match = {
            method = {}
          }
          text_transformation = [
            {
              priority = 1
              type     = "NONE"
            }
          ]
          positional_constraint = "EXACTLY"
        }
        
        or_statement = {
          statements = [
            {
              byte_match_statement = {
                search_string = "POST"
                field_to_match = {
                  method = {}
                }
                text_transformation = [
                  {
                    priority = 1
                    type     = "NONE"
                  }
                ]
                positional_constraint = "EXACTLY"
              }
            },
            {
              byte_match_statement = {
                search_string = "PUT"
                field_to_match = {
                  method = {}
                }
                text_transformation = [
                  {
                    priority = 1
                    type     = "NONE"
                  }
                ]
                positional_constraint = "EXACTLY"
              }
            },
            {
              byte_match_statement = {
                search_string = "DELETE"
                field_to_match = {
                  method = {}
                }
                text_transformation = [
                  {
                    priority = 1
                    type     = "NONE"
                  }
                ]
                positional_constraint = "EXACTLY"
              }
            },
            {
              byte_match_statement = {
                search_string = "HEAD"
                field_to_match = {
                  method = {}
                }
                text_transformation = [
                  {
                    priority = 1
                    type     = "NONE"
                  }
                ]
                positional_constraint = "EXACTLY"
              }
            },
            {
              byte_match_statement = {
                search_string = "OPTIONS"
                field_to_match = {
                  method = {}
                }
                text_transformation = [
                  {
                    priority = 1
                    type     = "NONE"
                  }
                ]
                positional_constraint = "EXACTLY"
              }
            }
          ]
        }
      }
      
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "AllowedHTTPMethodsMetric"
        sampled_requests_enabled   = true
      }
    }
  ]
  
  # =============================================================================
  # LOGGING CONFIGURATION
  # =============================================================================
  enable_logging = true
  
  log_destination_configs = [
    "arn:aws:s3:::${local.name_prefix}-waf-logs"
  ]
  
  # =============================================================================
  # ASSOCIATION WITH ALB
  # =============================================================================
  associate_alb = true
  alb_arn      = dependency.alb.outputs.lb_arn
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-web-acl"
      Component      = "Security"
      Service        = "WAF"
      Description    = "WAF Web ACL for comprehensive web application protection"
      Scope          = "REGIONAL"
      DefaultAction  = "Allow"
      RulesCount     = "8"
      CustomRules    = "2"
      RateLimit      = "2000"
      GeoBlocking    = "Enabled"
      IPReputation   = "Enabled"
      SQLInjection   = "Enabled"
      XSS            = "Enabled"
    }
  )
}

# =============================================================================
# GENERATE S3 BUCKET FOR WAF LOGS
# =============================================================================
generate "waf_logs_bucket" {
  path      = "waf_logs_bucket.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# S3 BUCKET FOR WAF LOGS
# =============================================================================
resource "aws_s3_bucket" "waf_logs" {
  bucket = "$${local.name_prefix}-waf-logs"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-waf-logs"
    Component = "Security"
    Service   = "S3"
    Purpose   = "WAF Logs"
  })
}

resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "waf_logs_lifecycle"
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

resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# CLOUDWATCH DASHBOARD FOR WAF METRICS
# =============================================================================
resource "aws_cloudwatch_dashboard" "waf_dashboard" {
  dashboard_name = "$${local.name_prefix}-waf-dashboard"

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
            ["AWS/WAFV2", "AllowedRequests", "WebACL", "$${local.name_prefix}-web-acl", "Region", local.aws_region, "Rule", "ALL"],
            [".", "BlockedRequests", ".", ".", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "WAF Allowed vs Blocked Requests"
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
            ["AWS/WAFV2", "BlockedRequests", "WebACL", "$${local.name_prefix}-web-acl", "Region", local.aws_region, "Rule", "RateLimitRule"],
            [".", ".", ".", ".", ".", ".", ".", "GeoBlockRule"],
            [".", ".", ".", ".", ".", ".", ".", "AWSManagedRulesCommonRuleSet"]
          ]
          view    = "timeSeries"
          stacked = true
          region  = local.aws_region
          title   = "WAF Blocked Requests by Rule"
          period  = 300
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-waf-dashboard"
    Component = "Security"
    Service   = "CloudWatch"
    Purpose   = "WAF Monitoring"
  })
}
EOF
}
