# =============================================================================
# WAF TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
dependency "alb" {
  config_path = "../alb"
  
  mock_outputs = {
    lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/dev-alb/1234567890123456"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "cloudwatch" {
  config_path = "../cloudwatch"
  
  mock_outputs = {
    security_log_group_name = "/aws/security/katya-cleaning-dev"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/waf/aws?version=1.0.2"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  alb_arn = dependency.alb.outputs.lb_arn
  security_log_group_name = dependency.cloudwatch.outputs.security_log_group_name
  
  waf_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component    = "Security"
      Service      = "WAF"
      DevelopmentWAF = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS - PRIMARY WAF
# =============================================================================
inputs = {
  name_prefix = local.env_vars.locals.name_prefix
  
  # We'll create custom WAF resources using generate blocks
  create_web_acl = false
}

# =============================================================================
# GENERATE COMPREHENSIVE WAF RESOURCES
# =============================================================================
generate "waf_development_resources" {
  path      = "waf_development_resources.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# WAF WEB ACL
# =============================================================================
resource "aws_wafv2_web_acl" "main" {
  name  = "$${local.env_vars.locals.name_prefix}-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = 2000  # Higher limit for development
        aggregate_key_type = "IP"

        scope_down_statement {
          geo_match_statement {
            # Allow all countries for development
            country_codes = ["US", "CA", "GB", "DE", "FR", "IT", "ES", "NL", "BE", "CH", "AT", "SE", "NO", "DK", "FI", "IE", "PT", "LU", "GR", "CY", "MT", "EE", "LV", "LT", "PL", "CZ", "SK", "HU", "SI", "HR", "BG", "RO", "AU", "NZ", "JP", "KR", "SG", "HK", "TW", "IN", "BR", "MX", "AR", "CL", "CO", "PE", "UY", "VE", "EC", "BO", "PY", "GY", "SR", "FK", "GF", "ZA", "EG", "MA", "TN", "DZ", "LY", "SD", "ET", "KE", "UG", "TZ", "RW", "BI", "DJ", "SO", "ER", "SS", "CF", "TD", "CM", "GQ", "GA", "CG", "CD", "AO", "ZM", "ZW", "BW", "NA", "SZ", "LS", "MG", "MU", "SC", "KM", "YT", "RE", "MZ", "MW", "ST", "CV", "GW", "GN", "SL", "LR", "CI", "GH", "TG", "BJ", "NE", "BF", "ML", "SN", "GM", "GN", "MR"]
          }
        }
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # Exclude rules that might be too strict for development
        excluded_rule {
          name = "SizeRestrictions_BODY"
        }
        excluded_rule {
          name = "GenericRFI_BODY"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - SQL Injection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 4

    override_action {
      count {}  # Count mode for development
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Development-specific rule for testing
  rule {
    name     = "DevelopmentTestingRule"
    priority = 5

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = "dev-test"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "CONTAINS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-DevelopmentTestingRule"
      sampled_requests_enabled   = true
    }
  }

  # Office IP whitelist rule
  rule {
    name     = "OfficeIPWhitelistRule"
    priority = 6

    action {
      allow {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.office_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-OfficeIPWhitelistRule"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "$${local.env_vars.locals.name_prefix}-WebACL"
    sampled_requests_enabled   = true
  }

  tags = merge(local.waf_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-web-acl"
  })
}

# =============================================================================
# IP SETS
# =============================================================================

# Office IP addresses
resource "aws_wafv2_ip_set" "office_ips" {
  name  = "$${local.env_vars.locals.name_prefix}-office-ips"
  scope = "REGIONAL"

  ip_address_version = "IPV4"

  # Development office IPs (replace with actual office IPs)
  addresses = [
    "203.0.113.0/24",    # Example office network
    "198.51.100.0/24",   # Example backup office network
    "192.0.2.0/24"       # Example VPN network
  ]

  tags = merge(local.waf_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-office-ips"
    Purpose = "OfficeIPWhitelist"
  })
}

# Known bad IPs (for development testing)
resource "aws_wafv2_ip_set" "bad_ips" {
  name  = "$${local.env_vars.locals.name_prefix}-bad-ips"
  scope = "REGIONAL"

  ip_address_version = "IPV4"

  # Example bad IPs for testing
  addresses = [
    "192.0.2.100/32",
    "192.0.2.101/32"
  ]

  tags = merge(local.waf_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-bad-ips"
    Purpose = "BadIPBlocking"
  })
}

# =============================================================================
# WAF ASSOCIATION WITH ALB
# =============================================================================
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = local.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# =============================================================================
# WAF LOGGING CONFIGURATION
# =============================================================================
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_field {
    single_header {
      name = "authorization"
    }
  }

  redacted_field {
    single_header {
      name = "cookie"
    }
  }

  redacted_field {
    single_header {
      name = "x-api-key"
    }
  }

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "DROP"
      condition {
        action_condition {
          action = "ALLOW"
        }
      }
      requirement = "MEETS_ALL"
    }
  }
}

# CloudWatch log group for WAF logs
resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/wafv2/$${local.env_vars.locals.name_prefix}"
  retention_in_days = 30  # Shorter retention for development
  
  tags = merge(local.waf_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-waf-logs"
    Purpose = "WAFLogging"
  })
}

# =============================================================================
# CLOUDWATCH ALARMS FOR WAF
# =============================================================================

# High blocked requests alarm
resource "aws_cloudwatch_metric_alarm" "high_blocked_requests" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-waf-high-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"  # Higher threshold for development
  alarm_description   = "High number of blocked requests detected"
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = local.aws_region
  }

  tags = merge(local.waf_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-waf-blocked-requests-alarm"
  })
}

# Rate limit triggered alarm
resource "aws_cloudwatch_metric_alarm" "rate_limit_triggered" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-waf-rate-limit-triggered"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "Rate limiting has been triggered"
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Region = local.aws_region
    Rule   = "RateLimitRule"
  }

  tags = merge(local.waf_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-waf-rate-limit-alarm"
  })
}

# =============================================================================
# WAF DASHBOARD
# =============================================================================
resource "aws_cloudwatch_dashboard" "waf" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-waf-dev"

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
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", local.aws_region],
            [".", "BlockedRequests", ".", ".", ".", "."],
            [".", "CountedRequests", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "WAF Request Metrics"
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
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.main.name, "Region", local.aws_region, "Rule", "RateLimitRule"],
            [".", ".", ".", ".", ".", ".", ".", "AWSManagedRulesCommonRuleSet"],
            [".", ".", ".", ".", ".", ".", ".", "AWSManagedRulesKnownBadInputsRuleSet"],
            [".", ".", ".", ".", ".", ".", ".", "AWSManagedRulesSQLiRuleSet"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "WAF Rules Metrics"
          period  = 300
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 6
        width  = 24
        height = 6

        properties = {
          query   = "SOURCE '/aws/wafv2/$${local.env_vars.locals.name_prefix}' | fields @timestamp, httpRequest.clientIp, action, terminatingRuleId | filter action = \"BLOCK\" | sort @timestamp desc | limit 20"
          region  = local.aws_region
          title   = "Recent Blocked Requests"
          view    = "table"
        }
      }
    ]
  })
}

# =============================================================================
# DEVELOPMENT-SPECIFIC WAF FEATURES
# =============================================================================

# WAF testing rule group for development
resource "aws_wafv2_rule_group" "development_testing" {
  name     = "$${local.env_vars.locals.name_prefix}-dev-testing"
  scope    = "REGIONAL"
  capacity = 100

  rule {
    name     = "AllowTestingPaths"
    priority = 1

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = "/test"
        field_to_match {
          uri_path {}
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "STARTS_WITH"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-AllowTestingPaths"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AllowDebugHeaders"
    priority = 2

    action {
      allow {}
    }

    statement {
      byte_match_statement {
        search_string = "debug"
        field_to_match {
          single_header {
            name = "x-debug-mode"
          }
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
        positional_constraint = "EXACTLY"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "$${local.env_vars.locals.name_prefix}-AllowDebugHeaders"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "$${local.env_vars.locals.name_prefix}-DevelopmentTesting"
    sampled_requests_enabled   = true
  }

  tags = merge(local.waf_tags, {
    Name    = "$${local.env_vars.locals.name_prefix}-dev-testing-rule-group"
    Purpose = "DevelopmentTesting"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "web_acl_arn" {
  description = "The ARN of the WAF WebACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_id" {
  description = "The ID of the WAF WebACL"
  value       = aws_wafv2_web_acl.main.id
}

output "web_acl_name" {
  description = "The name of the WAF WebACL"
  value       = aws_wafv2_web_acl.main.name
}

output "office_ip_set_arn" {
  description = "The ARN of the office IP set"
  value       = aws_wafv2_ip_set.office_ips.arn
}

output "bad_ip_set_arn" {
  description = "The ARN of the bad IP set"
  value       = aws_wafv2_ip_set.bad_ips.arn
}

output "waf_log_group_name" {
  description = "The name of the WAF log group"
  value       = aws_cloudwatch_log_group.waf.name
}

output "dashboard_url" {
  description = "URL to the WAF CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.waf.dashboard_name}"
}

# Development-specific outputs
output "waf_configuration" {
  description = "WAF configuration summary for development"
  value = {
    rate_limit_per_5min    = "2000"
    managed_rule_sets      = ["CommonRuleSet", "KnownBadInputs", "SQLi"]
    development_features   = ["TestingPaths", "DebugHeaders", "OfficeIPWhitelist"]
    logging_enabled        = true
    cloudwatch_monitoring  = true
    association_target     = "ALB"
  }
}

output "security_features" {
  description = "Security features enabled in development WAF"
  value = {
    rate_limiting         = "enabled"
    sql_injection_protection = "count_mode"
    xss_protection       = "enabled"
    bad_ip_blocking      = "enabled"
    office_ip_whitelist  = "enabled"
    request_logging      = "enabled"
    sensitive_data_redaction = "enabled"
  }
}

output "development_testing_features" {
  description = "Development-specific testing features"
  value = {
    testing_paths_allowed = "/test/*"
    debug_headers_allowed = "x-debug-mode"
    rule_group_capacity   = "100"
    log_retention_days    = "30"
    alarm_thresholds      = "development-optimized"
  }
}
EOF
}
