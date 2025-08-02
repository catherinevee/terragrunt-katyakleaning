# =============================================================================
# DNS TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================
# This module creates comprehensive DNS infrastructure with Route 53 hosted zones,
# advanced routing policies, health checks, and development-specific DNS features.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# Include region configuration
include "region" {
  path = find_in_parent_folders("region.hcl")
}

# =============================================================================
# DEPENDENCIES - VPC MUST BE CREATED FIRST
# =============================================================================
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id                = "vpc-12345678"
    vpc_cidr_block       = "10.1.0.0/16"
    private_subnets      = ["subnet-11111111", "subnet-22222222"]
    public_subnets       = ["subnet-12345678", "subnet-87654321"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION - USING GITHUB MODULE
# =============================================================================
terraform {
  source = "git::https://github.com/catherinevee/tfm-aws-dns.git//modules/dns?ref=v1.0.0"
}

# =============================================================================
# LOCAL VARIABLES FOR ADVANCED DNS CONFIGURATION
# =============================================================================
locals {
  # Environment-specific configurations
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  # VPC information from dependency
  vpc_id         = dependency.vpc.outputs.vpc_id
  vpc_cidr_block = dependency.vpc.outputs.vpc_cidr_block
  private_subnets = dependency.vpc.outputs.private_subnets
  
  # Domain configuration
  domain_config = local.env_vars.locals.domain_config
  
  # Development-specific DNS settings
  primary_domain = local.domain_config.primary_domain
  api_domain     = local.domain_config.api_domain
  admin_domain   = local.domain_config.admin_domain
  media_domain   = local.domain_config.media_domain
  cdn_domain     = local.domain_config.cdn_domain
  
  # TTL settings for development
  ttl_short  = local.domain_config.ttl_short   # 60 seconds
  ttl_medium = local.domain_config.ttl_medium  # 300 seconds
  ttl_long   = local.domain_config.ttl_long    # 900 seconds
  
  # Development subdomains
  dev_subdomains = [
    "api-dev",
    "admin-dev", 
    "staging-dev",
    "test-dev",
    "preview-dev",
    "docs-dev",
    "monitoring-dev",
    "grafana-dev",
    "kibana-dev",
    "storybook-dev"
  ]
  
  # Advanced tagging for DNS resources
  dns_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component           = "DNS"
      Service            = "Route53"
      DNSProvider        = "Route53"
      Environment        = "Development"
      HealthChecks       = "enabled"
      GeolocationRouting = "disabled"
      WeightedRouting    = "enabled"
      FailoverRouting    = "enabled"
      DevelopmentDNS     = "enabled"
    }
  )
}

# =============================================================================
# MODULE INPUTS WITH ADVANCED DNS CONFIGURATION
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC DNS CONFIGURATION
  # =============================================================================
  
  # Primary domain configuration
  domain_name = local.primary_domain
  
  # Environment and naming
  environment = local.env_vars.locals.environment
  name_prefix = local.env_vars.locals.name_prefix
  
  # =============================================================================
  # HOSTED ZONES CONFIGURATION
  # =============================================================================
  
  # Public hosted zone for external access
  create_public_zone = true
  public_zone_name   = local.primary_domain
  public_zone_comment = "Development environment public DNS zone for ${local.primary_domain}"
  
  # Private hosted zone for internal services
  create_private_zone = true
  private_zone_name   = "dev.internal"
  private_zone_comment = "Development environment private DNS zone for internal services"
  private_zone_vpc_id = local.vpc_id
  
  # Additional VPCs for private zone association (if needed)
  private_zone_vpc_associations = []
  
  # =============================================================================
  # DNS RECORDS CONFIGURATION WITH DEVELOPMENT FEATURES
  # =============================================================================
  
  # A Records for primary services
  a_records = [
    {
      name    = local.primary_domain
      type    = "A"
      ttl     = local.ttl_medium
      records = ["203.0.113.10"]  # Placeholder IP - will be replaced by ALB
      comment = "Primary application endpoint"
      
      # Development-specific settings
      set_identifier = null
      weighted_routing_policy = null
      failover_routing_policy = null
      geolocation_routing_policy = null
      health_check_id = "primary-health-check"
    },
    {
      name    = local.api_domain
      type    = "A"
      ttl     = local.ttl_short  # Shorter TTL for API in dev
      records = ["203.0.113.11"]  # Placeholder IP
      comment = "API endpoint for development"
      
      # Load balancing configuration
      set_identifier = "api-primary"
      weighted_routing_policy = {
        weight = 100
      }
      health_check_id = "api-health-check"
    },
    {
      name    = local.admin_domain
      type    = "A"
      ttl     = local.ttl_medium
      records = ["203.0.113.12"]  # Placeholder IP
      comment = "Admin interface for development"
      
      set_identifier = null
      health_check_id = "admin-health-check"
    }
  ]
  
  # CNAME Records for aliases and services
  cname_records = [
    {
      name    = "www.${local.primary_domain}"
      type    = "CNAME"
      ttl     = local.ttl_medium
      records = [local.primary_domain]
      comment = "WWW alias to primary domain"
    },
    {
      name    = local.media_domain
      type    = "CNAME"
      ttl     = local.ttl_long
      records = ["${local.env_vars.locals.name_prefix}-media.s3.${local.aws_region}.amazonaws.com"]
      comment = "Media assets CDN endpoint"
    },
    {
      name    = local.cdn_domain
      type    = "CNAME"
      ttl     = local.ttl_long
      records = ["d1234567890.cloudfront.net"]  # Placeholder CloudFront domain
      comment = "CDN endpoint for static assets"
    },
    # Development-specific CNAMEs
    {
      name    = "docs-dev.${local.primary_domain}"
      type    = "CNAME"
      ttl     = local.ttl_short
      records = ["docs-dev-alb.${local.aws_region}.elb.amazonaws.com"]
      comment = "Development documentation"
    },
    {
      name    = "storybook-dev.${local.primary_domain}"
      type    = "CNAME"
      ttl     = local.ttl_short
      records = ["storybook-dev-alb.${local.aws_region}.elb.amazonaws.com"]
      comment = "Storybook component library"
    },
    {
      name    = "monitoring-dev.${local.primary_domain}"
      type    = "CNAME"
      ttl     = local.ttl_short
      records = ["monitoring-dev-alb.${local.aws_region}.elb.amazonaws.com"]
      comment = "Development monitoring dashboard"
    }
  ]
  
  # MX Records for email
  mx_records = [
    {
      name    = local.primary_domain
      type    = "MX"
      ttl     = local.ttl_long
      records = [
        "10 mail.${local.primary_domain}",
        "20 mail2.${local.primary_domain}"
      ]
      comment = "Email routing for development domain"
    }
  ]
  
  # TXT Records for verification and SPF
  txt_records = [
    {
      name    = local.primary_domain
      type    = "TXT"
      ttl     = local.ttl_medium
      records = [
        "v=spf1 include:_spf.google.com ~all",
        "google-site-verification=dev-verification-token"
      ]
      comment = "SPF and domain verification records"
    },
    {
      name    = "_dmarc.${local.primary_domain}"
      type    = "TXT"
      ttl     = local.ttl_long
      records = ["v=DMARC1; p=quarantine; rua=mailto:dmarc@${local.primary_domain}"]
      comment = "DMARC policy for email security"
    },
    # Development-specific TXT records
    {
      name    = "dev-env.${local.primary_domain}"
      type    = "TXT"
      ttl     = local.ttl_short
      records = [
        "environment=development",
        "version=${local.env_vars.locals.app_config.app_version}",
        "debug=enabled"
      ]
      comment = "Development environment metadata"
    }
  ]
  
  # SRV Records for service discovery
  srv_records = [
    {
      name    = "_api._tcp.${local.primary_domain}"
      type    = "SRV"
      ttl     = local.ttl_short
      records = ["10 5 8080 ${local.api_domain}"]
      comment = "API service discovery"
    },
    {
      name    = "_metrics._tcp.dev.internal"
      type    = "SRV"
      ttl     = local.ttl_short
      records = ["10 5 9090 monitoring.dev.internal"]
      comment = "Metrics service discovery"
    }
  ]
  
  # =============================================================================
  # HEALTH CHECKS CONFIGURATION
  # =============================================================================
  
  health_checks = [
    {
      id                            = "primary-health-check"
      fqdn                         = local.primary_domain
      port                         = 443
      type                         = "HTTPS"
      resource_path                = "/health"
      failure_threshold            = 3
      request_interval             = 30
      measure_latency              = true
      enable_sni                   = true
      
      # Development-specific health check settings
      search_string                = "healthy"
      invert_healthcheck          = false
      disabled                    = false
      
      # CloudWatch alarm integration
      cloudwatch_alarm_region     = local.aws_region
      cloudwatch_alarm_name       = "${local.env_vars.locals.name_prefix}-primary-health"
      insufficient_data_health_status = "Failure"
      
      tags = {
        Name        = "${local.env_vars.locals.name_prefix}-primary-health"
        Environment = "development"
        Service     = "primary-app"
      }
    },
    {
      id                            = "api-health-check"
      fqdn                         = local.api_domain
      port                         = 443
      type                         = "HTTPS"
      resource_path                = "/api/health"
      failure_threshold            = 2  # More sensitive for API
      request_interval             = 30
      measure_latency              = true
      enable_sni                   = true
      
      # API-specific health check
      search_string                = "\"status\":\"ok\""
      invert_healthcheck          = false
      disabled                    = false
      
      cloudwatch_alarm_region     = local.aws_region
      cloudwatch_alarm_name       = "${local.env_vars.locals.name_prefix}-api-health"
      insufficient_data_health_status = "Failure"
      
      tags = {
        Name        = "${local.env_vars.locals.name_prefix}-api-health"
        Environment = "development"
        Service     = "api"
      }
    },
    {
      id                            = "admin-health-check"
      fqdn                         = local.admin_domain
      port                         = 443
      type                         = "HTTPS"
      resource_path                = "/admin/health"
      failure_threshold            = 3
      request_interval             = 60  # Less frequent for admin
      measure_latency              = true
      enable_sni                   = true
      
      search_string                = "admin_healthy"
      invert_healthcheck          = false
      disabled                    = false
      
      cloudwatch_alarm_region     = local.aws_region
      cloudwatch_alarm_name       = "${local.env_vars.locals.name_prefix}-admin-health"
      insufficient_data_health_status = "Success"  # Less critical
      
      tags = {
        Name        = "${local.env_vars.locals.name_prefix}-admin-health"
        Environment = "development"
        Service     = "admin"
      }
    }
  ]
  
  # =============================================================================
  # ROUTE 53 RESOLVER CONFIGURATION
  # =============================================================================
  
  # Resolver endpoints for hybrid DNS
  create_resolver_endpoints = true
  
  resolver_endpoints = [
    {
      name      = "${local.env_vars.locals.name_prefix}-inbound-resolver"
      direction = "INBOUND"
      
      # Use private subnets for resolver endpoints
      ip_addresses = [
        {
          subnet_id = local.private_subnets[0]
          ip        = cidrhost(local.vpc_cidr_block, 10)
        },
        {
          subnet_id = local.private_subnets[1]
          ip        = cidrhost(local.vpc_cidr_block, 11)
        }
      ]
      
      security_group_ids = []  # Will be created by the module
      
      tags = {
        Name        = "${local.env_vars.locals.name_prefix}-inbound-resolver"
        Direction   = "INBOUND"
        Environment = "development"
        Purpose     = "Hybrid DNS Resolution"
      }
    },
    {
      name      = "${local.env_vars.locals.name_prefix}-outbound-resolver"
      direction = "OUTBOUND"
      
      ip_addresses = [
        {
          subnet_id = local.private_subnets[0]
          ip        = cidrhost(local.vpc_cidr_block, 20)
        },
        {
          subnet_id = local.private_subnets[1]
          ip        = cidrhost(local.vpc_cidr_block, 21)
        }
      ]
      
      security_group_ids = []  # Will be created by the module
      
      tags = {
        Name        = "${local.env_vars.locals.name_prefix}-outbound-resolver"
        Direction   = "OUTBOUND"
        Environment = "development"
        Purpose     = "Forward DNS Queries"
      }
    }
  ]
  
  # Resolver rules for forwarding
  resolver_rules = [
    {
      name                 = "${local.env_vars.locals.name_prefix}-corporate-dns"
      domain_name         = "corp.katyacleaning.com"
      rule_type           = "FORWARD"
      resolver_endpoint_id = null  # Will be set to outbound resolver
      
      target_ips = [
        {
          ip   = "192.168.1.10"  # Corporate DNS server
          port = 53
        },
        {
          ip   = "192.168.1.11"  # Backup corporate DNS
          port = 53
        }
      ]
      
      tags = {
        Name        = "${local.env_vars.locals.name_prefix}-corporate-dns"
        Environment = "development"
        Purpose     = "Corporate Domain Resolution"
      }
    }
  ]
  
  # =============================================================================
  # QUERY LOGGING CONFIGURATION
  # =============================================================================
  
  enable_query_logging = true
  query_log_destination_arn = "arn:aws:logs:${local.aws_region}:${local.aws_account_id}:log-group:/aws/route53/${local.primary_domain}"
  
  # =============================================================================
  # DNSSEC CONFIGURATION (DISABLED FOR DEVELOPMENT)
  # =============================================================================
  
  enable_dnssec = false  # Disabled for development simplicity
  
  # =============================================================================
  # DEVELOPMENT-SPECIFIC FEATURES
  # =============================================================================
  
  # Enable development DNS features
  enable_development_features = true
  
  # Development DNS settings
  development_config = {
    enable_wildcard_records = true
    enable_test_subdomains = true
    short_ttl_override     = true
    enable_debug_records   = true
  }
  
  # Wildcard records for development
  wildcard_records = [
    {
      name    = "*.dev.${local.primary_domain}"
      type    = "A"
      ttl     = local.ttl_short
      records = ["203.0.113.100"]  # Development wildcard IP
      comment = "Wildcard for development subdomains"
    },
    {
      name    = "*.api-dev.${local.primary_domain}"
      type    = "A"
      ttl     = local.ttl_short
      records = ["203.0.113.101"]  # API development wildcard
      comment = "Wildcard for API development endpoints"
    }
  ]
  
  # =============================================================================
  # TAGGING
  # =============================================================================
  tags = local.dns_tags
}

# =============================================================================
# GENERATE ADDITIONAL DEVELOPMENT DNS RESOURCES
# =============================================================================
generate "development_dns_features" {
  path      = "development_dns_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# DEVELOPMENT-SPECIFIC DNS RESOURCES
# =============================================================================

# CloudWatch Log Group for Route 53 Query Logging
resource "aws_cloudwatch_log_group" "route53_query_logs" {
  name              = "/aws/route53/$${local.primary_domain}"
  retention_in_days = 30
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"

  tags = merge(local.dns_tags, {
    Name      = "$${local.env_vars.locals.name_prefix}-route53-query-logs"
    Component = "DNS"
    Service   = "Route53QueryLogs"
    Purpose   = "DNS Query Monitoring"
  })
}

# Route 53 Query Logging Configuration
resource "aws_route53_query_log" "main" {
  depends_on = [aws_cloudwatch_log_group.route53_query_logs]

  destination_arn = aws_cloudwatch_log_group.route53_query_logs.arn
  zone_id        = module.dns.public_zone_id
}

# CloudWatch Metric Filters for DNS Monitoring
resource "aws_cloudwatch_log_metric_filter" "dns_query_count" {
  name           = "$${local.env_vars.locals.name_prefix}-dns-query-count"
  log_group_name = aws_cloudwatch_log_group.route53_query_logs.name
  pattern        = "[timestamp, zone_id, query_timestamp, query_name, query_type, response_code, protocol, edge_location, resolver_ip, client_subnet]"

  metric_transformation {
    name      = "DNSQueryCount"
    namespace = "KatyaCleaning/DNS/Development"
    value     = "1"
    
    default_value = "0"
  }
}

resource "aws_cloudwatch_log_metric_filter" "dns_nxdomain" {
  name           = "$${local.env_vars.locals.name_prefix}-dns-nxdomain"
  log_group_name = aws_cloudwatch_log_group.route53_query_logs.name
  pattern        = "[timestamp, zone_id, query_timestamp, query_name, query_type, response_code=\"NXDOMAIN\", protocol, edge_location, resolver_ip, client_subnet]"

  metric_transformation {
    name      = "DNSNXDomainCount"
    namespace = "KatyaCleaning/DNS/Development"
    value     = "1"
    
    default_value = "0"
  }
}

# Development DNS Dashboard
resource "aws_cloudwatch_dashboard" "dns_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-dns-development"

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
            ["KatyaCleaning/DNS/Development", "DNSQueryCount"],
            [".", "DNSNXDomainCount"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "DNS Query Metrics"
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
            ["AWS/Route53", "QueryCount", "HostedZoneId", module.dns.public_zone_id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Route 53 Query Count"
          period  = 300
        }
      }
    ]
  })
}

# Development-specific Route 53 Records for testing
resource "aws_route53_record" "development_test_records" {
  for_each = toset([
    "test1", "test2", "test3", "staging", "preview", "feature-branch"
  ])

  zone_id = module.dns.public_zone_id
  name    = "$${each.key}.dev.$${local.primary_domain}"
  type    = "A"
  ttl     = 60

  records = ["203.0.113.200"]  # Test IP address

  lifecycle {
    ignore_changes = [records]  # Allow manual updates during development
  }
}

# Internal service discovery records
resource "aws_route53_record" "internal_services" {
  for_each = {
    "database"    = "10.1.21.10"
    "cache"       = "10.1.21.20"
    "monitoring"  = "10.1.11.30"
    "logging"     = "10.1.11.31"
    "metrics"     = "10.1.11.32"
  }

  zone_id = module.dns.private_zone_id
  name    = "$${each.key}.dev.internal"
  type    = "A"
  ttl     = 300

  records = [each.value]
}

# Development environment metadata record
resource "aws_route53_record" "environment_metadata" {
  zone_id = module.dns.public_zone_id
  name    = "_env.$${local.primary_domain}"
  type    = "TXT"
  ttl     = 60

  records = [
    "environment=development",
    "region=$${local.aws_region}",
    "version=$${local.env_vars.locals.app_config.app_version}",
    "debug=enabled",
    "created=$${formatdate("YYYY-MM-DD", timestamp())}"
  ]

  lifecycle {
    ignore_changes = [records]
  }
}

# =============================================================================
# OUTPUTS FOR DEPENDENCY MANAGEMENT
# =============================================================================
output "public_zone_id" {
  description = "The hosted zone ID of the public zone"
  value       = module.dns.public_zone_id
}

output "private_zone_id" {
  description = "The hosted zone ID of the private zone"
  value       = module.dns.private_zone_id
}

output "public_zone_name_servers" {
  description = "The name servers for the public hosted zone"
  value       = module.dns.public_zone_name_servers
}

output "resolver_endpoint_inbound_id" {
  description = "The ID of the inbound resolver endpoint"
  value       = try(module.dns.resolver_endpoint_inbound_id, null)
}

output "resolver_endpoint_outbound_id" {
  description = "The ID of the outbound resolver endpoint"
  value       = try(module.dns.resolver_endpoint_outbound_id, null)
}

output "health_check_ids" {
  description = "Map of health check IDs"
  value       = module.dns.health_check_ids
}

output "query_log_group_name" {
  description = "The name of the CloudWatch Log Group for DNS query logs"
  value       = aws_cloudwatch_log_group.route53_query_logs.name
}

output "dns_dashboard_url" {
  description = "URL to the DNS CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.dns_development.dashboard_name}"
}

# Development-specific outputs
output "development_domains" {
  description = "List of development domains configured"
  value = {
    primary = local.primary_domain
    api     = local.api_domain
    admin   = local.admin_domain
    media   = local.media_domain
    cdn     = local.cdn_domain
  }
}

output "test_subdomains" {
  description = "List of test subdomains for development"
  value = [for record in aws_route53_record.development_test_records : record.name]
}

output "internal_service_records" {
  description = "Internal service discovery records"
  value = {for k, v in aws_route53_record.internal_services : k => v.name}
}
EOF
}
