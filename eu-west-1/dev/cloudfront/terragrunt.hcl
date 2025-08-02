# =============================================================================
# CLOUDFRONT TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
    lb_dns_name = "test-alb-123456789.eu-west-1.elb.amazonaws.com"
    lb_zone_id  = "Z32O12XQLNTSW2"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "s3" {
  config_path = "../s3"
  
  mock_outputs = {
    static_website_bucket_id = "test-static-website-bucket"
    static_website_bucket_website_endpoint = "test-static-website-bucket.s3-website-eu-west-1.amazonaws.com"
    cloudfront_logs_bucket_id = "test-cloudfront-logs-bucket"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/cloudfront/aws?version=3.2.2"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  alb_dns_name = dependency.alb.outputs.lb_dns_name
  alb_zone_id  = dependency.alb.outputs.lb_zone_id
  
  static_website_bucket = dependency.s3.outputs.static_website_bucket_id
  static_website_endpoint = dependency.s3.outputs.static_website_bucket_website_endpoint
  cloudfront_logs_bucket = dependency.s3.outputs.cloudfront_logs_bucket_id
  
  domain_config = local.env_vars.locals.domain_config
  
  cloudfront_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component        = "CDN"
      Service          = "CloudFront"
      DevelopmentCDN   = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # Basic configuration
  comment             = "Development CloudFront distribution for ${local.env_vars.locals.app_config.app_name}"
  enabled             = true
  is_ipv6_enabled    = true
  price_class        = "PriceClass_100"  # Use only US, Canada and Europe for dev
  retain_on_delete   = false
  wait_for_deployment = false  # Don't wait in development
  
  # Origins configuration
  create_origin_access_identity = true
  origin_access_identities = {
    s3_bucket_one = "Development S3 bucket access"
  }
  
  origins = {
    alb = {
      domain_name = local.alb_dns_name
      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
    
    s3_static = {
      domain_name = local.static_website_endpoint
      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "http-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
    }
  }
  
  # Default cache behavior
  default_cache_behavior = {
    target_origin_id           = "alb"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods           = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods            = ["GET", "HEAD"]
    compress                  = true
    query_string              = true
    query_string_cache_keys   = []
    cookies_forward           = "none"
    headers                   = ["Host", "CloudFront-Forwarded-Proto"]
    
    # Cache settings optimized for development
    min_ttl                   = 0
    default_ttl               = 300    # 5 minutes
    max_ttl                   = 3600   # 1 hour
    
    # Lambda@Edge functions (none for development)
    lambda_function_association = {}
  }
  
  # Ordered cache behaviors
  ordered_cache_behavior = [
    {
      path_pattern           = "/static/*"
      target_origin_id       = "s3_static"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD", "OPTIONS"]
      cached_methods         = ["GET", "HEAD"]
      compress               = true
      query_string           = false
      cookies_forward        = "none"
      headers                = []
      
      # Longer cache for static assets
      min_ttl                = 0
      default_ttl            = 86400   # 1 day
      max_ttl                = 31536000 # 1 year
      
      lambda_function_association = {}
    },
    
    {
      path_pattern           = "/api/*"
      target_origin_id       = "alb"
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods         = ["GET", "HEAD"]
      compress               = true
      query_string           = true
      cookies_forward        = "all"
      headers                = ["*"]
      
      # No caching for API endpoints in development
      min_ttl                = 0
      default_ttl            = 0
      max_ttl                = 0
      
      lambda_function_association = {}
    }
  ]
  
  # Custom error responses
  custom_error_response = [
    {
      error_code         = 404
      response_code      = 404
      response_page_path = "/error.html"
      error_caching_min_ttl = 300
    },
    {
      error_code         = 500
      response_code      = 500
      response_page_path = "/error.html"
      error_caching_min_ttl = 0  # Don't cache server errors in dev
    }
  ]
  
  # Geo restriction (none for development)
  geo_restriction = {
    restriction_type = "none"
    locations        = []
  }
  
  # Logging configuration
  logging_config = {
    bucket          = "${local.cloudfront_logs_bucket}.s3.amazonaws.com"
    prefix          = "cloudfront-access-logs/"
    include_cookies = false
  }
  
  # SSL certificate
  viewer_certificate = {
    acm_certificate_arn            = local.domain_config.certificate_arn
    ssl_support_method             = "sni-only"
    minimum_protocol_version       = "TLSv1.2_2021"
    cloudfront_default_certificate = local.domain_config.certificate_arn == "" ? true : false
  }
  
  # Aliases
  aliases = local.domain_config.certificate_arn != "" ? [local.domain_config.cdn_domain] : []
  
  # Web ACL (WAF) integration
  web_acl_id = ""  # Will be set by WAF module
  
  # Tags
  tags = local.cloudfront_tags
}

# =============================================================================
# GENERATE ADDITIONAL CLOUDFRONT RESOURCES
# =============================================================================
generate "cloudfront_development_features" {
  path      = "cloudfront_development_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# DEVELOPMENT-SPECIFIC CLOUDFRONT RESOURCES
# =============================================================================

# CloudWatch Dashboard for CloudFront monitoring
resource "aws_cloudwatch_dashboard" "cloudfront_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-cloudfront-dev"

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
            ["AWS/CloudFront", "Requests", "DistributionId", module.cloudfront.cloudfront_distribution_id],
            [".", "BytesDownloaded", ".", "."],
            [".", "BytesUploaded", ".", "."],
            [".", "4xxErrorRate", ".", "."],
            [".", "5xxErrorRate", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"  # CloudFront metrics are in us-east-1
          title   = "CloudFront Distribution Metrics"
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
            ["AWS/CloudFront", "CacheHitRate", "DistributionId", module.cloudfront.cloudfront_distribution_id],
            [".", "OriginLatency", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-1"
          title   = "CloudFront Cache Performance"
          period  = 300
        }
      }
    ]
  })
}

# Development-specific CloudWatch alarms
resource "aws_cloudwatch_metric_alarm" "cloudfront_4xx_errors" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-cloudfront-4xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "4xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "10"  # 10% error rate
  alarm_description   = "CloudFront 4xx error rate is high"
  alarm_actions       = []

  dimensions = {
    DistributionId = module.cloudfront.cloudfront_distribution_id
  }

  tags = merge(local.cloudfront_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-cloudfront-4xx-errors-alarm"
  })
}

resource "aws_cloudwatch_metric_alarm" "cloudfront_5xx_errors" {
  alarm_name          = "$${local.env_vars.locals.name_prefix}-cloudfront-5xx-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "5"   # 5% error rate
  alarm_description   = "CloudFront 5xx error rate is high"
  alarm_actions       = []

  dimensions = {
    DistributionId = module.cloudfront.cloudfront_distribution_id
  }

  tags = merge(local.cloudfront_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-cloudfront-5xx-errors-alarm"
  })
}

# CloudFront invalidation for development deployments
resource "aws_cloudfront_invalidation" "development_invalidation" {
  count = var.create_invalidation ? 1 : 0
  
  distribution_id = module.cloudfront.cloudfront_distribution_id
  paths           = ["/*"]

  lifecycle {
    create_before_destroy = true
  }
}

# Lambda@Edge function for development headers (optional)
resource "aws_lambda_function" "cloudfront_dev_headers" {
  count = var.enable_dev_headers ? 1 : 0
  
  filename         = "dev_headers.zip"
  function_name    = "$${local.env_vars.locals.name_prefix}-cloudfront-dev-headers"
  role            = aws_iam_role.lambda_edge_role[0].arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.dev_headers_zip[0].output_base64sha256
  runtime         = "nodejs18.x"
  publish         = true

  tags = merge(local.cloudfront_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-cloudfront-dev-headers"
    Purpose = "DevelopmentHeaders"
  })
}

# Lambda@Edge IAM role
resource "aws_iam_role" "lambda_edge_role" {
  count = var.enable_dev_headers ? 1 : 0
  
  name = "$${local.env_vars.locals.name_prefix}-lambda-edge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "edgelambda.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = merge(local.cloudfront_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-lambda-edge-role"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_edge_basic" {
  count = var.enable_dev_headers ? 1 : 0
  
  role       = aws_iam_role.lambda_edge_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda function code
data "archive_file" "dev_headers_zip" {
  count = var.enable_dev_headers ? 1 : 0
  
  type        = "zip"
  output_path = "dev_headers.zip"
  
  source {
    content = <<EOF
exports.handler = (event, context, callback) => {
    const response = event.Records[0].cf.response;
    const headers = response.headers;

    // Add development-specific headers
    headers['x-development-environment'] = [{
        key: 'X-Development-Environment',
        value: 'true'
    }];
    
    headers['x-cache-control'] = [{
        key: 'X-Cache-Control',
        value: 'no-cache, no-store, must-revalidate'
    }];
    
    headers['x-debug-info'] = [{
        key: 'X-Debug-Info',
        value: 'Development CloudFront Distribution'
    }];

    callback(null, response);
};
EOF
    filename = "index.js"
  }
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "cloudfront_distribution_id" {
  description = "The identifier for the distribution"
  value       = module.cloudfront.cloudfront_distribution_id
}

output "cloudfront_distribution_arn" {
  description = "The ARN (Amazon Resource Name) for the distribution"
  value       = module.cloudfront.cloudfront_distribution_arn
}

output "cloudfront_distribution_domain_name" {
  description = "The domain name corresponding to the distribution"
  value       = module.cloudfront.cloudfront_distribution_domain_name
}

output "cloudfront_distribution_hosted_zone_id" {
  description = "The CloudFront Route 53 zone ID"
  value       = module.cloudfront.cloudfront_distribution_hosted_zone_id
}

output "cloudfront_origin_access_identities" {
  description = "The origin access identities created"
  value       = module.cloudfront.cloudfront_origin_access_identities
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=$${aws_cloudwatch_dashboard.cloudfront_development.dashboard_name}"
}

# Development-specific outputs
output "development_features" {
  description = "Development features enabled"
  value = {
    price_class           = "PriceClass_100"
    wait_for_deployment  = false
    retain_on_delete     = false
    cache_ttl_optimized  = "short"
    api_caching_disabled = true
    error_caching_minimal = true
  }
}

output "cache_behaviors_summary" {
  description = "Summary of cache behaviors configured"
  value = {
    default_behavior = "ALB origin with 5min cache"
    static_assets   = "S3 origin with 1day cache"
    api_endpoints   = "ALB origin with no cache"
  }
}

# =============================================================================
# VARIABLES
# =============================================================================
variable "create_invalidation" {
  description = "Create CloudFront invalidation for development"
  type        = bool
  default     = false
}

variable "enable_dev_headers" {
  description = "Enable development-specific headers via Lambda@Edge"
  type        = bool
  default     = false
}
EOF
}
