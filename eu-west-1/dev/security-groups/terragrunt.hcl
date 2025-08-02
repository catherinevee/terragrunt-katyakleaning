# =============================================================================
# SECURITY GROUPS TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================
# This module creates comprehensive security groups with layered security,
# advanced rule management, and development-specific access patterns.

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
    public_subnets       = ["subnet-12345678", "subnet-87654321"]
    private_subnets      = ["subnet-11111111", "subnet-22222222"]
    database_subnets     = ["subnet-33333333", "subnet-44444444"]
    intra_subnets        = ["subnet-55555555", "subnet-66666666"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/security-group/aws?version=5.1.2"
}

# =============================================================================
# LOCAL VARIABLES FOR ADVANCED SECURITY CONFIGURATION
# =============================================================================
locals {
  # Environment-specific configurations
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  # VPC information from dependency
  vpc_id         = dependency.vpc.outputs.vpc_id
  vpc_cidr_block = dependency.vpc.outputs.vpc_cidr_block
  
  # Development-specific security configuration
  security_config = local.env_vars.locals.security_config
  
  # Office IP ranges for development access
  office_cidrs = local.security_config.allowed_cidr_blocks
  ssh_allowed_cidrs = local.security_config.ssh_allowed_cidrs
  
  # Common ports for development
  common_ports = {
    http          = 80
    https         = 443
    ssh           = 22
    postgresql    = 5432
    redis         = 6379
    app_port      = 8080
    debug_port    = 9229
    metrics_port  = 9090
    health_port   = 8081
  }
  
  # Development-specific ports
  dev_ports = {
    webpack_dev   = 3000
    api_dev       = 3001
    storybook     = 6006
    docs_port     = 4000
    test_port     = 8888
    profiler_port = 9999
  }
  
  # Advanced tagging for security groups
  security_group_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component           = "Security"
      Service            = "SecurityGroups"
      SecurityLayer      = "NetworkLevel"
      ComplianceFramework = "SOC2,PCI-DSS"
      DevelopmentAccess  = "enabled"
      TestingSupport     = "full"
    }
  )
}

# =============================================================================
# MULTIPLE SECURITY GROUP CONFIGURATIONS
# =============================================================================

# This configuration creates multiple security groups using the for_each pattern
inputs = {
  # We'll use multiple configurations to create different security groups
  create = false  # We'll create individual security groups using generate blocks
}

# =============================================================================
# GENERATE COMPREHENSIVE SECURITY GROUPS
# =============================================================================
generate "security_groups" {
  path      = "security_groups.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# APPLICATION LOAD BALANCER SECURITY GROUP
# =============================================================================
module "alb_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-alb-sg"
  description = "Security group for Application Load Balancer with development features"
  vpc_id      = local.vpc_id

  # Ingress rules for ALB
  ingress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "HTTP from anywhere"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS from anywhere"
      cidr_blocks = "0.0.0.0/0"
    },
    # Development-specific ports
    {
      from_port   = 8080
      to_port     = 8080
      protocol    = "tcp"
      description = "Development app port from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 3000
      to_port     = 3000
      protocol    = "tcp"
      description = "Webpack dev server from office"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # Egress to web servers
  egress_with_source_security_group_id = [
    {
      from_port                = 80
      to_port                  = 80
      protocol                 = "tcp"
      description              = "HTTP to web servers"
      source_security_group_id = module.web_server_security_group.security_group_id
    },
    {
      from_port                = 443
      to_port                  = 443
      protocol                 = "tcp"
      description              = "HTTPS to web servers"
      source_security_group_id = module.web_server_security_group.security_group_id
    },
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "App port to web servers"
      source_security_group_id = module.web_server_security_group.security_group_id
    }
  ]

  # Health check egress
  egress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "Health check HTTP"
      cidr_blocks = local.vpc_cidr_block
    },
    {
      from_port   = 8081
      to_port     = 8081
      protocol    = "tcp"
      description = "Health check endpoint"
      cidr_blocks = local.vpc_cidr_block
    }
  ]

  tags = merge(local.security_group_tags, {
    Name        = "$${local.env_vars.locals.name_prefix}-alb-sg"
    Purpose     = "Load Balancer"
    Tier        = "Web"
    ExposedToInternet = "true"
  })
}

# =============================================================================
# WEB SERVER SECURITY GROUP
# =============================================================================
module "web_server_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-web-sg"
  description = "Security group for web servers with development debugging"
  vpc_id      = local.vpc_id

  # Ingress from ALB
  ingress_with_source_security_group_id = [
    {
      from_port                = 80
      to_port                  = 80
      protocol                 = "tcp"
      description              = "HTTP from ALB"
      source_security_group_id = module.alb_security_group.security_group_id
    },
    {
      from_port                = 443
      to_port                  = 443
      protocol                 = "tcp"
      description              = "HTTPS from ALB"
      source_security_group_id = module.alb_security_group.security_group_id
    },
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "App port from ALB"
      source_security_group_id = module.alb_security_group.security_group_id
    },
    {
      from_port                = 8081
      to_port                  = 8081
      protocol                 = "tcp"
      description              = "Health check from ALB"
      source_security_group_id = module.alb_security_group.security_group_id
    }
  ]

  # Development access from office
  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "SSH from office"
      cidr_blocks = join(",", local.ssh_allowed_cidrs)
    },
    {
      from_port   = 9229
      to_port     = 9229
      protocol    = "tcp"
      description = "Node.js debugger from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 9090
      to_port     = 9090
      protocol    = "tcp"
      description = "Metrics endpoint from office"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # Egress to app servers
  egress_with_source_security_group_id = [
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "App communication to app servers"
      source_security_group_id = module.app_server_security_group.security_group_id
    },
    {
      from_port                = 3001
      to_port                  = 3001
      protocol                 = "tcp"
      description              = "API communication to app servers"
      source_security_group_id = module.app_server_security_group.security_group_id
    }
  ]

  # Internet access for updates and external APIs
  egress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "HTTP to internet"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS to internet"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      description = "DNS resolution"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      description = "NTP synchronization"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.security_group_tags, {
    Name        = "$${local.env_vars.locals.name_prefix}-web-sg"
    Purpose     = "Web Servers"
    Tier        = "Web"
    DebugAccess = "enabled"
  })
}

# =============================================================================
# APPLICATION SERVER SECURITY GROUP
# =============================================================================
module "app_server_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-app-sg"
  description = "Security group for application servers with comprehensive development access"
  vpc_id      = local.vpc_id

  # Ingress from web servers
  ingress_with_source_security_group_id = [
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "App port from web servers"
      source_security_group_id = module.web_server_security_group.security_group_id
    },
    {
      from_port                = 3001
      to_port                  = 3001
      protocol                 = "tcp"
      description              = "API port from web servers"
      source_security_group_id = module.web_server_security_group.security_group_id
    }
  ]

  # Development and debugging access
  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "SSH from office"
      cidr_blocks = join(",", local.ssh_allowed_cidrs)
    },
    {
      from_port   = 9229
      to_port     = 9229
      protocol    = "tcp"
      description = "Node.js debugger from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 9090
      to_port     = 9090
      protocol    = "tcp"
      description = "Metrics from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 8888
      to_port     = 8888
      protocol    = "tcp"
      description = "Test runner from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 9999
      to_port     = 9999
      protocol    = "tcp"
      description = "Profiler from office"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # Egress to database
  egress_with_source_security_group_id = [
    {
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      description              = "PostgreSQL to database"
      source_security_group_id = module.database_security_group.security_group_id
    },
    {
      from_port                = 6379
      to_port                  = 6379
      protocol                 = "tcp"
      description              = "Redis to cache"
      source_security_group_id = module.cache_security_group.security_group_id
    }
  ]

  # Internet access for external services
  egress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "HTTP to internet"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS to internet"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      description = "DNS resolution"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 25
      to_port     = 25
      protocol    = "tcp"
      description = "SMTP for email"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 587
      to_port     = 587
      protocol    = "tcp"
      description = "SMTP TLS for email"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.security_group_tags, {
    Name           = "$${local.env_vars.locals.name_prefix}-app-sg"
    Purpose        = "Application Servers"
    Tier           = "Application"
    DatabaseAccess = "enabled"
    CacheAccess    = "enabled"
    ExternalAPIs   = "enabled"
  })
}

# =============================================================================
# DATABASE SECURITY GROUP
# =============================================================================
module "database_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-db-sg"
  description = "Security group for database with development access and monitoring"
  vpc_id      = local.vpc_id

  # Ingress from app servers
  ingress_with_source_security_group_id = [
    {
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      description              = "PostgreSQL from app servers"
      source_security_group_id = module.app_server_security_group.security_group_id
    }
  ]

  # Development database access from office (restricted)
  ingress_with_cidr_blocks = [
    {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      description = "PostgreSQL from office (development only)"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # No egress rules - database should not initiate connections
  egress_with_cidr_blocks = []

  tags = merge(local.security_group_tags, {
    Name              = "$${local.env_vars.locals.name_prefix}-db-sg"
    Purpose           = "Database"
    Tier              = "Data"
    EncryptionRequired = "true"
    BackupEnabled     = "true"
    DevelopmentAccess = "limited"
  })
}

# =============================================================================
# CACHE SECURITY GROUP (REDIS/ELASTICACHE)
# =============================================================================
module "cache_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-cache-sg"
  description = "Security group for cache layer with development monitoring"
  vpc_id      = local.vpc_id

  # Ingress from app servers
  ingress_with_source_security_group_id = [
    {
      from_port                = 6379
      to_port                  = 6379
      protocol                 = "tcp"
      description              = "Redis from app servers"
      source_security_group_id = module.app_server_security_group.security_group_id
    }
  ]

  # Development cache access from office (for debugging)
  ingress_with_cidr_blocks = [
    {
      from_port   = 6379
      to_port     = 6379
      protocol    = "tcp"
      description = "Redis from office (development debugging)"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # No egress rules - cache should not initiate connections
  egress_with_cidr_blocks = []

  tags = merge(local.security_group_tags, {
    Name              = "$${local.env_vars.locals.name_prefix}-cache-sg"
    Purpose           = "Cache"
    Tier              = "Data"
    EncryptionRequired = "true"
    DevelopmentAccess = "debugging"
  })
}

# =============================================================================
# BASTION HOST SECURITY GROUP
# =============================================================================
module "bastion_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-bastion-sg"
  description = "Security group for bastion host with strict access control"
  vpc_id      = local.vpc_id

  # SSH access from office only
  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "SSH from office"
      cidr_blocks = join(",", local.ssh_allowed_cidrs)
    }
  ]

  # Egress to private subnets for SSH
  egress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "SSH to private instances"
      cidr_blocks = local.vpc_cidr_block
    },
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "HTTP for updates"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS for updates"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      description = "DNS resolution"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.security_group_tags, {
    Name        = "$${local.env_vars.locals.name_prefix}-bastion-sg"
    Purpose     = "Bastion Host"
    Tier        = "Management"
    AccessLevel = "Restricted"
    SSHGateway  = "true"
  })
}

# =============================================================================
# DEVELOPMENT TOOLS SECURITY GROUP
# =============================================================================
module "dev_tools_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-devtools-sg"
  description = "Security group for development tools and services"
  vpc_id      = local.vpc_id

  # Development tools access from office
  ingress_with_cidr_blocks = [
    {
      from_port   = 3000
      to_port     = 3000
      protocol    = "tcp"
      description = "Webpack dev server"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 6006
      to_port     = 6006
      protocol    = "tcp"
      description = "Storybook"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 4000
      to_port     = 4000
      protocol    = "tcp"
      description = "Documentation server"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 8888
      to_port     = 8888
      protocol    = "tcp"
      description = "Test runner"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 9090
      to_port     = 9090
      protocol    = "tcp"
      description = "Prometheus metrics"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 3001
      to_port     = 3010
      protocol    = "tcp"
      description = "Development API range"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # Full internet access for development tools
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      description = "All traffic for development tools"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.security_group_tags, {
    Name        = "$${local.env_vars.locals.name_prefix}-devtools-sg"
    Purpose     = "Development Tools"
    Tier        = "Development"
    ToolsAccess = "full"
    InternetAccess = "unrestricted"
  })
}

# =============================================================================
# MONITORING AND LOGGING SECURITY GROUP
# =============================================================================
module "monitoring_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.env_vars.locals.name_prefix}-monitoring-sg"
  description = "Security group for monitoring and logging services"
  vpc_id      = local.vpc_id

  # Monitoring access from all application tiers
  ingress_with_source_security_group_id = [
    {
      from_port                = 9090
      to_port                  = 9090
      protocol                 = "tcp"
      description              = "Prometheus from web servers"
      source_security_group_id = module.web_server_security_group.security_group_id
    },
    {
      from_port                = 9090
      to_port                  = 9090
      protocol                 = "tcp"
      description              = "Prometheus from app servers"
      source_security_group_id = module.app_server_security_group.security_group_id
    }
  ]

  # Monitoring dashboard access from office
  ingress_with_cidr_blocks = [
    {
      from_port   = 3000
      to_port     = 3000
      protocol    = "tcp"
      description = "Grafana dashboard from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 9090
      to_port     = 9090
      protocol    = "tcp"
      description = "Prometheus UI from office"
      cidr_blocks = join(",", local.office_cidrs)
    },
    {
      from_port   = 5601
      to_port     = 5601
      protocol    = "tcp"
      description = "Kibana from office"
      cidr_blocks = join(",", local.office_cidrs)
    }
  ]

  # Internet access for external monitoring services
  egress_with_cidr_blocks = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS to external monitoring"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 53
      to_port     = 53
      protocol    = "udp"
      description = "DNS resolution"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.security_group_tags, {
    Name        = "$${local.env_vars.locals.name_prefix}-monitoring-sg"
    Purpose     = "Monitoring"
    Tier        = "Operations"
    Dashboard   = "enabled"
    Alerting    = "enabled"
  })
}

# =============================================================================
# OUTPUTS FOR DEPENDENCY MANAGEMENT
# =============================================================================
output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = module.alb_security_group.security_group_id
}

output "web_server_security_group_id" {
  description = "ID of the web server security group"
  value       = module.web_server_security_group.security_group_id
}

output "app_server_security_group_id" {
  description = "ID of the app server security group"
  value       = module.app_server_security_group.security_group_id
}

output "database_security_group_id" {
  description = "ID of the database security group"
  value       = module.database_security_group.security_group_id
}

output "cache_security_group_id" {
  description = "ID of the cache security group"
  value       = module.cache_security_group.security_group_id
}

output "bastion_security_group_id" {
  description = "ID of the bastion security group"
  value       = module.bastion_security_group.security_group_id
}

output "dev_tools_security_group_id" {
  description = "ID of the development tools security group"
  value       = module.dev_tools_security_group.security_group_id
}

output "monitoring_security_group_id" {
  description = "ID of the monitoring security group"
  value       = module.monitoring_security_group.security_group_id
}

# Development-specific outputs
output "security_group_mapping" {
  description = "Mapping of security groups to their purposes"
  value = {
    alb         = module.alb_security_group.security_group_id
    web_server  = module.web_server_security_group.security_group_id
    app_server  = module.app_server_security_group.security_group_id
    database    = module.database_security_group.security_group_id
    cache       = module.cache_security_group.security_group_id
    bastion     = module.bastion_security_group.security_group_id
    dev_tools   = module.dev_tools_security_group.security_group_id
    monitoring  = module.monitoring_security_group.security_group_id
  }
}

output "development_access_enabled" {
  description = "Development access features enabled"
  value = {
    ssh_access      = true
    debug_ports     = true
    office_access   = true
    dev_tools       = true
    monitoring_ui   = true
  }
}
EOF
}
