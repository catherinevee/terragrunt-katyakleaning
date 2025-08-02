# =============================================================================
# DNS TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates Route 53 hosted zones and DNS records for the production
# environment using the comprehensive DNS module from GitHub.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# VPC dependency for private DNS
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id = "vpc-mock"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "git::https://github.com/catherinevee/tfm-aws-dns.git?ref=v1.0.0"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # PUBLIC DNS ZONE CONFIGURATION
  # =============================================================================
  create_public_zone = true
  public_zone_name   = local.env_vars.locals.domain_config.primary_domain
  
  # Public DNS Records
  public_records = [
    # Root domain A record (will point to ALB)
    {
      name    = ""
      type    = "A"
      ttl     = 300
      records = ["203.0.113.10"]  # Placeholder - will be updated with ALB IP
    },
    
    # WWW CNAME record
    {
      name    = "www"
      type    = "CNAME"
      ttl     = 300
      records = [local.env_vars.locals.domain_config.primary_domain]
    },
    
    # API subdomain
    {
      name    = "api"
      type    = "A"
      ttl     = 300
      records = ["203.0.113.10"]  # Placeholder - will be updated with ALB IP
    },
    
    # Admin subdomain
    {
      name    = "admin"
      type    = "A"
      ttl     = 300
      records = ["203.0.113.10"]  # Placeholder - will be updated with ALB IP
    },
    
    # Media subdomain for static assets
    {
      name    = "media"
      type    = "CNAME"
      ttl     = 300
      records = ["d123456789.cloudfront.net"]  # Placeholder - will be updated with CloudFront
    },
    
    # CDN subdomain
    {
      name    = "cdn"
      type    = "CNAME"
      ttl     = 300
      records = ["d123456789.cloudfront.net"]  # Placeholder - will be updated with CloudFront
    },
    
    # Email MX records
    {
      name    = ""
      type    = "MX"
      ttl     = 3600
      records = [
        "10 mail.katyacleaning.com",
        "20 mail2.katyacleaning.com"
      ]
    },
    
    # SPF record for email security
    {
      name    = ""
      type    = "TXT"
      ttl     = 3600
      records = ["v=spf1 include:_spf.google.com ~all"]
    },
    
    # DMARC record for email security
    {
      name    = "_dmarc"
      type    = "TXT"
      ttl     = 3600
      records = ["v=DMARC1; p=quarantine; rua=mailto:dmarc@katyacleaning.com"]
    },
    
    # Domain verification for various services
    {
      name    = "_verification"
      type    = "TXT"
      ttl     = 300
      records = ["google-site-verification=abcd1234"]  # Placeholder
    }
  ]
  
  # Health checks for critical endpoints
  health_checks = [
    {
      fqdn                            = local.env_vars.locals.domain_config.primary_domain
      port                           = 443
      type                           = "HTTPS"
      resource_path                  = "/health"
      failure_threshold              = 3
      request_interval               = 30
      cloudwatch_alarm_region        = local.aws_region
      cloudwatch_alarm_name          = "dns-health-check-main"
      insufficient_data_health_status = "Failure"
    },
    {
      fqdn                            = local.env_vars.locals.domain_config.api_domain
      port                           = 443
      type                           = "HTTPS"
      resource_path                  = "/health"
      failure_threshold              = 3
      request_interval               = 30
      cloudwatch_alarm_region        = local.aws_region
      cloudwatch_alarm_name          = "dns-health-check-api"
      insufficient_data_health_status = "Failure"
    }
  ]
  
  # =============================================================================
  # PRIVATE DNS ZONE CONFIGURATION
  # =============================================================================
  create_private_zone = true
  private_zone_name   = "internal.katyacleaning.local"
  
  # VPC associations for private zone
  private_zone_vpc_associations = [
    {
      vpc_id = dependency.vpc.outputs.vpc_id
    }
  ]
  
  # Private DNS Records for internal services
  private_records = [
    # Database endpoint
    {
      name    = "db"
      type    = "CNAME"
      ttl     = 300
      records = ["katyacleaning-prod-db.cluster-xyz.eu-west-1.rds.amazonaws.com"]  # Placeholder
    },
    
    # Cache endpoint
    {
      name    = "cache"
      type    = "CNAME"
      ttl     = 300
      records = ["katyacleaning-prod-cache.xyz.cache.amazonaws.com"]  # Placeholder
    },
    
    # Internal API endpoint
    {
      name    = "internal-api"
      type    = "A"
      ttl     = 300
      records = ["10.0.11.100"]  # Internal load balancer IP
    },
    
    # Monitoring services
    {
      name    = "monitoring"
      type    = "A"
      ttl     = 300
      records = ["10.0.11.200"]
    },
    
    # Log aggregation
    {
      name    = "logs"
      type    = "A"
      ttl     = 300
      records = ["10.0.11.201"]
    }
  ]
  
  # =============================================================================
  # ROUTE 53 RESOLVER CONFIGURATION
  # =============================================================================
  create_resolver_endpoints = true
  
  # Inbound resolver for on-premises to AWS DNS queries
  inbound_resolver_config = {
    name               = "${local.name_prefix}-inbound-resolver"
    security_group_ids = [dependency.vpc.outputs.default_security_group_id]
    ip_addresses = [
      {
        subnet_id = dependency.vpc.outputs.private_subnets[0]
        ip        = "10.0.11.253"
      },
      {
        subnet_id = dependency.vpc.outputs.private_subnets[1]
        ip        = "10.0.12.253"
      }
    ]
  }
  
  # Outbound resolver for AWS to on-premises DNS queries
  outbound_resolver_config = {
    name               = "${local.name_prefix}-outbound-resolver"
    security_group_ids = [dependency.vpc.outputs.default_security_group_id]
    ip_addresses = [
      {
        subnet_id = dependency.vpc.outputs.private_subnets[0]
        ip        = "10.0.11.254"
      },
      {
        subnet_id = dependency.vpc.outputs.private_subnets[1]
        ip        = "10.0.12.254"
      }
    ]
  }
  
  # Forwarding rules for hybrid DNS
  forwarding_rules = [
    {
      name                 = "corporate-dns"
      domain_name         = "corp.katyacleaning.com"
      rule_type           = "FORWARD"
      target_ips = [
        {
          ip   = "192.168.1.10"  # On-premises DNS server
          port = 53
        },
        {
          ip   = "192.168.1.11"  # Backup on-premises DNS server
          port = 53
        }
      ]
    }
  ]
  
  # =============================================================================
  # ADVANCED ROUTING POLICIES
  # =============================================================================
  enable_advanced_routing = true
  
  # Weighted routing for A/B testing
  weighted_records = [
    {
      name           = "beta"
      type           = "A"
      set_identifier = "beta-v1"
      weight         = 90
      ttl            = 60
      records        = ["203.0.113.20"]
    },
    {
      name           = "beta"
      type           = "A"
      set_identifier = "beta-v2"
      weight         = 10
      ttl            = 60
      records        = ["203.0.113.21"]
    }
  ]
  
  # Latency-based routing for global performance
  latency_records = [
    {
      name           = "global"
      type           = "A"
      set_identifier = "eu-west-1"
      region         = "eu-west-1"
      ttl            = 60
      records        = ["203.0.113.10"]
    }
  ]
  
  # Failover routing for high availability
  failover_records = [
    {
      name           = "app"
      type           = "A"
      set_identifier = "primary"
      failover       = "PRIMARY"
      ttl            = 60
      records        = ["203.0.113.10"]
      health_check_id = "primary-health-check"
    },
    {
      name           = "app"
      type           = "A"
      set_identifier = "secondary"
      failover       = "SECONDARY"
      ttl            = 60
      records        = ["203.0.113.30"]  # DR region
    }
  ]
  
  # =============================================================================
  # SECURITY AND COMPLIANCE
  # =============================================================================
  enable_query_logging = true
  query_log_config = {
    destination_arn = "arn:aws:logs:${local.aws_region}:${local.aws_account_id}:log-group:/aws/route53/queries"
  }
  
  # DNSSEC for enhanced security
  enable_dnssec = false  # Requires careful planning and key management
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name        = "${local.name_prefix}-dns"
      Component   = "DNS"
      Service     = "Route53"
      Description = "DNS infrastructure for Katya Cleaning Services"
      Domain      = local.env_vars.locals.domain_config.primary_domain
      DNSType     = "Hybrid"
      Features    = "Public,Private,Resolver,HealthChecks"
    }
  )
}
