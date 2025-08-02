# =============================================================================
# VPC TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates the foundational VPC infrastructure including subnets,
# route tables, NAT gateways, and security groups for the production environment.

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
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/vpc/aws?version=5.8.1"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # Basic VPC Configuration
  name = "${local.env_vars.locals.environment}-katyacleaning-vpc"
  cidr = local.region_vars.locals.vpc_cidr
  
  # Availability Zones
  azs = local.region_vars.locals.availability_zones
  
  # Subnet Configuration
  public_subnets   = local.region_vars.locals.public_subnet_cidrs
  private_subnets  = local.region_vars.locals.private_subnet_cidrs
  database_subnets = local.region_vars.locals.database_subnet_cidrs
  intra_subnets    = local.region_vars.locals.intra_subnet_cidrs
  
  # Subnet Groups
  create_database_subnet_group       = true
  create_database_subnet_route_table = true
  create_database_internet_gateway_route = false
  create_database_nat_gateway_route = true
  
  # DNS Configuration
  enable_dns_hostnames = local.region_vars.locals.enable_dns_hostnames
  enable_dns_support   = local.region_vars.locals.enable_dns_support
  
  # NAT Gateway Configuration
  enable_nat_gateway     = local.region_vars.locals.enable_nat_gateway
  single_nat_gateway     = local.region_vars.locals.single_nat_gateway
  one_nat_gateway_per_az = local.region_vars.locals.one_nat_gateway_per_az
  
  # Internet Gateway
  create_igw = true
  
  # VPC Flow Logs
  enable_flow_log                      = local.region_vars.locals.enable_flow_log
  flow_log_destination_type           = local.region_vars.locals.flow_log_destination_type
  flow_log_log_format                 = local.region_vars.locals.flow_log_log_format
  flow_log_max_aggregation_interval   = local.region_vars.locals.flow_log_max_aggregation_interval
  
  # Security Groups
  manage_default_security_group     = local.region_vars.locals.manage_default_security_group
  default_security_group_ingress    = local.region_vars.locals.default_security_group_ingress
  default_security_group_egress     = local.region_vars.locals.default_security_group_egress
  
  # DHCP Options
  enable_dhcp_options              = local.region_vars.locals.enable_dhcp_options
  dhcp_options_domain_name         = local.region_vars.locals.dhcp_options_domain_name
  dhcp_options_domain_name_servers = local.region_vars.locals.dhcp_options_domain_name_servers
  
  # VPC Endpoints for cost optimization and security
  enable_s3_endpoint       = true
  enable_dynamodb_endpoint = true
  
  # Additional VPC Endpoints for AWS services
  enable_ec2_endpoint               = true
  enable_ec2messages_endpoint       = true
  enable_ssm_endpoint              = true
  enable_ssmmessages_endpoint      = true
  enable_logs_endpoint             = true
  enable_monitoring_endpoint       = true
  enable_events_endpoint           = true
  enable_secretsmanager_endpoint   = true
  enable_kms_endpoint              = true
  
  # VPC Endpoint Security Groups
  vpc_endpoint_security_group_ids = []
  
  # Public Subnet Configuration
  public_subnet_suffix = "public"
  public_subnet_tags = {
    Type = "Public"
    Tier = "Web"
    "kubernetes.io/role/elb" = "1"
  }
  
  # Private Subnet Configuration
  private_subnet_suffix = "private"
  private_subnet_tags = {
    Type = "Private"
    Tier = "Application"
    "kubernetes.io/role/internal-elb" = "1"
  }
  
  # Database Subnet Configuration
  database_subnet_suffix = "database"
  database_subnet_tags = {
    Type = "Database"
    Tier = "Data"
  }
  
  # Intra Subnet Configuration (for internal services)
  intra_subnet_suffix = "intra"
  intra_subnet_tags = {
    Type = "Intra"
    Tier = "Internal"
  }
  
  # Route Table Tags
  public_route_table_tags = {
    Name = "${local.env_vars.locals.environment}-katyacleaning-public-rt"
    Type = "Public"
  }
  
  private_route_table_tags = {
    Name = "${local.env_vars.locals.environment}-katyacleaning-private-rt"
    Type = "Private"
  }
  
  database_route_table_tags = {
    Name = "${local.env_vars.locals.environment}-katyacleaning-database-rt"
    Type = "Database"
  }
  
  intra_route_table_tags = {
    Name = "${local.env_vars.locals.environment}-katyacleaning-intra-rt"
    Type = "Intra"
  }
  
  # NAT Gateway Tags
  nat_gateway_tags = {
    Name = "${local.env_vars.locals.environment}-katyacleaning-nat"
    Type = "NAT Gateway"
  }
  
  # Internet Gateway Tags
  igw_tags = {
    Name = "${local.env_vars.locals.environment}-katyacleaning-igw"
    Type = "Internet Gateway"
  }
  
  # VPC Tags
  tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Name        = "${local.env_vars.locals.environment}-katyacleaning-vpc"
      Component   = "Networking"
      Service     = "VPC"
      Description = "Production VPC for Katya Cleaning Services"
      CIDR        = local.region_vars.locals.vpc_cidr
      AZs         = join(",", local.region_vars.locals.availability_zones)
    }
  )
}
