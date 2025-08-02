# =============================================================================
# SECURITY GROUPS TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates security groups for different tiers of the application
# following the principle of least privilege and defense in depth.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# VPC dependency
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
  source = "tfr:///terraform-aws-modules/security-group/aws?version=5.1.2"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # Create multiple security groups for different tiers
  create_sg = false  # We'll create individual security groups
  
  # We'll use the module multiple times via generate blocks
}

# =============================================================================
# GENERATE SECURITY GROUPS
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

  name        = "$${local.name_prefix}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = "$${dependency.vpc.outputs.vpc_id}"

  # HTTP and HTTPS ingress from internet
  ingress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "HTTP from internet"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS from internet"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  # Egress to web servers
  egress_with_source_security_group_id = [
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "HTTP to web servers"
      source_security_group_id = module.web_security_group.security_group_id
    }
  ]

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-alb-sg"
    Component = "LoadBalancer"
    Tier      = "Web"
  })
}

# =============================================================================
# WEB SERVERS SECURITY GROUP
# =============================================================================
module "web_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.name_prefix}-web-sg"
  description = "Security group for web servers"
  vpc_id      = "$${dependency.vpc.outputs.vpc_id}"

  # HTTP from ALB
  ingress_with_source_security_group_id = [
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "HTTP from ALB"
      source_security_group_id = module.alb_security_group.security_group_id
    },
    {
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      description              = "SSH from bastion"
      source_security_group_id = module.bastion_security_group.security_group_id
    }
  ]

  # Egress to app servers and external services
  egress_with_source_security_group_id = [
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "HTTP to app servers"
      source_security_group_id = module.app_security_group.security_group_id
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS to internet"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "HTTP to internet"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-web-sg"
    Component = "WebServer"
    Tier      = "Web"
  })
}

# =============================================================================
# APPLICATION SERVERS SECURITY GROUP
# =============================================================================
module "app_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.name_prefix}-app-sg"
  description = "Security group for application servers"
  vpc_id      = "$${dependency.vpc.outputs.vpc_id}"

  # HTTP from web servers
  ingress_with_source_security_group_id = [
    {
      from_port                = 8080
      to_port                  = 8080
      protocol                 = "tcp"
      description              = "HTTP from web servers"
      source_security_group_id = module.web_security_group.security_group_id
    },
    {
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      description              = "SSH from bastion"
      source_security_group_id = module.bastion_security_group.security_group_id
    }
  ]

  # Egress to database and external services
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

  egress_with_cidr_blocks = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS to internet"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-app-sg"
    Component = "AppServer"
    Tier      = "Application"
  })
}

# =============================================================================
# DATABASE SECURITY GROUP
# =============================================================================
module "database_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.name_prefix}-db-sg"
  description = "Security group for database servers"
  vpc_id      = "$${dependency.vpc.outputs.vpc_id}"

  # PostgreSQL from app servers
  ingress_with_source_security_group_id = [
    {
      from_port                = 5432
      to_port                  = 5432
      protocol                 = "tcp"
      description              = "PostgreSQL from app servers"
      source_security_group_id = module.app_security_group.security_group_id
    }
  ]

  # No egress rules - database should not initiate outbound connections

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-db-sg"
    Component = "Database"
    Tier      = "Data"
  })
}

# =============================================================================
# CACHE SECURITY GROUP
# =============================================================================
module "cache_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.name_prefix}-cache-sg"
  description = "Security group for cache servers"
  vpc_id      = "$${dependency.vpc.outputs.vpc_id}"

  # Redis from app servers
  ingress_with_source_security_group_id = [
    {
      from_port                = 6379
      to_port                  = 6379
      protocol                 = "tcp"
      description              = "Redis from app servers"
      source_security_group_id = module.app_security_group.security_group_id
    }
  ]

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-cache-sg"
    Component = "Cache"
    Tier      = "Data"
  })
}

# =============================================================================
# BASTION HOST SECURITY GROUP
# =============================================================================
module "bastion_security_group" {
  source = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name        = "$${local.name_prefix}-bastion-sg"
  description = "Security group for bastion host"
  vpc_id      = "$${dependency.vpc.outputs.vpc_id}"

  # SSH from specific IP ranges (office/VPN)
  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "SSH from office"
      cidr_blocks = "203.0.113.0/24"  # Replace with actual office IP
    }
  ]

  # SSH to private instances
  egress_with_source_security_group_id = [
    {
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      description              = "SSH to web servers"
      source_security_group_id = module.web_security_group.security_group_id
    },
    {
      from_port                = 22
      to_port                  = 22
      protocol                 = "tcp"
      description              = "SSH to app servers"
      source_security_group_id = module.app_security_group.security_group_id
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "HTTPS to internet"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-bastion-sg"
    Component = "Bastion"
    Tier      = "Management"
  })
}
EOF
}
