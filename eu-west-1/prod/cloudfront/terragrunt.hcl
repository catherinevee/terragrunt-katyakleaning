# =============================================================================
# CLOUDFRONT TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates a CloudFront distribution for global content delivery
# with SSL termination, caching, and security features.

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
    lb_dns_name = "mock-alb-123456789.eu-west-1.elb.amazonaws.com"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

dependency "s3" {
  config_path = "../s3"
  
  mock_outputs = {
    s3_bucket_bucket_domain_name = "mock-bucket.s3.amazonaws.com"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/cloudfront/aws?version=3.4.0"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC DISTRIBUTION CONFIGURATION
  # =============================================================================
  aliases = [
    local.env_vars.locals.domain_config.primary_domain,
    "www.${local.env_vars.locals.domain_config.primary_domain}",
    local.env_vars.locals.domain_config.cdn_domain,
    local.env_vars.locals.domain_config.media_domain
  ]
  
  comment         = "CloudFront distribution for Katya Cleaning Services"
  enabled         = true
  is_ipv6_enabled = true
  price_class     = "PriceClass_100"  # US, Canada, Europe
  retain_on_delete = false
  wait_for_deployment = false
  
  # =============================================================================
  # ORIGINS CONFIGURATION
  # =============================================================================
  create_origin_access_identity = true
  origin_access_identities = {
    s3_bucket = "CloudFront access to S3 bucket"
  }
  
  origin = {
    # ALB origin for dynamic content
    alb = {
      domain_name = dependency.alb.outputs.lb_dns_name
      custom_origin_config = {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }
      
      custom_header = [
        {
          name  = "X-Forwarded-Host"
          value = local.env_vars.locals.domain_config.primary_domain
        }
      ]
    }
    
    # S3 origin for static content
    s3_static = {
      domain_name = dependency.s3.outputs.s3_bucket_bucket_domain_name
      s3_origin_config = {
        origin_access_identity = "s3_bucket"
      }
    }
  }
  
  # =============================================================================
  # DEFAULT CACHE BEHAVIOR
  # =============================================================================
  default_cache_behavior = {
    target_origin_id       = "alb"
    viewer_protocol_policy = "redirect-to-https"
    
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    compress         = true
    query_string     = true
    
    cookies_forward = "all"
    
    headers = [
      "Accept",
      "Accept-Charset",
      "Accept-Datetime",
      "Accept-Encoding",
      "Accept-Language",
      "Authorization",
      "CloudFront-Forwarded-Proto",
      "CloudFront-Is-Desktop-Viewer",
      "CloudFront-Is-Mobile-Viewer",
      "CloudFront-Is-SmartTV-Viewer",
      "CloudFront-Is-Tablet-Viewer",
      "CloudFront-Viewer-Country",
      "Host",
      "Origin",
      "Referer",
      "User-Agent",
      "X-Forwarded-For",
      "X-Forwarded-Host",
      "X-Forwarded-Proto"
    ]
    
    # TTL settings
    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
    
    # Lambda@Edge functions
    lambda_function_association = [
      {
        event_type   = "viewer-request"
        lambda_arn   = "arn:aws:lambda:us-east-1:${local.aws_account_id}:function:security-headers:1"
        include_body = false
      }
    ]
  }
  
  # =============================================================================
  # ORDERED CACHE BEHAVIORS
  # =============================================================================
  ordered_cache_behavior = [
    # Static assets from S3
    {
      path_pattern     = "/static/*"
      target_origin_id = "s3_static"
      
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD", "OPTIONS"]
      cached_methods         = ["GET", "HEAD"]
      compress               = true
      
      query_string = false
      cookies_forward = "none"
      
      headers = ["Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"]
      
      min_ttl     = 0
      default_ttl = 86400
      max_ttl     = 31536000
    },
    
    # Images and media
    {
      path_pattern     = "/images/*"
      target_origin_id = "s3_static"
      
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["GET", "HEAD", "OPTIONS"]
      cached_methods         = ["GET", "HEAD"]
      compress               = true
      
      query_string = false
      cookies_forward = "none"
      
      min_ttl     = 0
      default_ttl = 86400
      max_ttl     = 31536000
    },
    
    # API endpoints (no caching)
    {
      path_pattern     = "/api/*"
      target_origin_id = "alb"
      
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods         = ["GET", "HEAD"]
      compress               = true
      
      query_string = true
      cookies_forward = "all"
      
      headers = [
        "Accept",
        "Accept-Charset",
        "Accept-Datetime",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Content-Type",
        "Host",
        "Origin",
        "Referer",
        "User-Agent",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto"
      ]
      
      min_ttl     = 0
      default_ttl = 0
      max_ttl     = 0
    },
    
    # Admin interface
    {
      path_pattern     = "/admin/*"
      target_origin_id = "alb"
      
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods         = ["GET", "HEAD"]
      compress               = true
      
      query_string = true
      cookies_forward = "all"
      
      headers = [
        "Accept",
        "Accept-Charset",
        "Accept-Datetime",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Content-Type",
        "Host",
        "Origin",
        "Referer",
        "User-Agent",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto"
      ]
      
      min_ttl     = 0
      default_ttl = 0
      max_ttl     = 300
    }
  ]
  
  # =============================================================================
  # SSL CERTIFICATE
  # =============================================================================
  viewer_certificate = {
    acm_certificate_arn      = "arn:aws:acm:us-east-1:${local.aws_account_id}:certificate/12345678-1234-1234-1234-123456789012"  # Placeholder
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
  
  # =============================================================================
  # GEO RESTRICTIONS
  # =============================================================================
  geo_restriction = {
    restriction_type = "whitelist"
    locations        = ["US", "CA", "GB", "DE", "FR", "IT", "ES", "NL", "IE", "AU", "NZ"]
  }
  
  # =============================================================================
  # LOGGING CONFIGURATION
  # =============================================================================
  logging_config = {
    bucket          = "${local.name_prefix}-cloudfront-logs.s3.amazonaws.com"
    prefix          = "cloudfront-logs/"
    include_cookies = false
  }
  
  # =============================================================================
  # CUSTOM ERROR PAGES
  # =============================================================================
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
      error_caching_min_ttl = 0
    },
    {
      error_code         = 502
      response_code      = 502
      response_page_path = "/error.html"
      error_caching_min_ttl = 0
    },
    {
      error_code         = 503
      response_code      = 503
      response_page_path = "/maintenance.html"
      error_caching_min_ttl = 0
    },
    {
      error_code         = 504
      response_code      = 504
      response_page_path = "/error.html"
      error_caching_min_ttl = 0
    }
  ]
  
  # =============================================================================
  # WEB ACL ASSOCIATION
  # =============================================================================
  web_acl_id = "arn:aws:wafv2:us-east-1:${local.aws_account_id}:global/webacl/katyacleaning-waf/12345678-1234-1234-1234-123456789012"  # Placeholder
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-cloudfront"
      Component      = "CDN"
      Service        = "CloudFront"
      Description    = "Global content delivery network for Katya Cleaning Services"
      PriceClass     = "PriceClass_100"
      Domains        = join(",", [
        local.env_vars.locals.domain_config.primary_domain,
        "www.${local.env_vars.locals.domain_config.primary_domain}",
        local.env_vars.locals.domain_config.cdn_domain,
        local.env_vars.locals.domain_config.media_domain
      ])
      Origins        = "ALB,S3"
      SecurityLevel  = "High"
      Caching        = "Optimized"
      Compression    = "Enabled"
      IPv6           = "Enabled"
    }
  )
}
