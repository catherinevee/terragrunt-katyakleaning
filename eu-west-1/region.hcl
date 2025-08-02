# =============================================================================
# REGION-LEVEL CONFIGURATION
# =============================================================================
# This file contains region-specific configuration for eu-west-1 that applies
# to all environments within this region.

locals {
  # AWS Region Configuration
  aws_region      = "eu-west-1"
  aws_region_name = "Europe (Ireland)"
  
  # Availability Zones
  availability_zones = [
    "eu-west-1a",
    "eu-west-1b", 
    "eu-west-1c"
  ]
  
  # Network Configuration
  vpc_cidr = "10.0.0.0/16"
  
  # Subnet Configuration (3 AZs, 4 subnet types)
  public_subnet_cidrs = [
    "10.0.1.0/24",   # eu-west-1a
    "10.0.2.0/24",   # eu-west-1b
    "10.0.3.0/24"    # eu-west-1c
  ]
  
  private_subnet_cidrs = [
    "10.0.11.0/24",  # eu-west-1a
    "10.0.12.0/24",  # eu-west-1b
    "10.0.13.0/24"   # eu-west-1c
  ]
  
  database_subnet_cidrs = [
    "10.0.21.0/24",  # eu-west-1a
    "10.0.22.0/24",  # eu-west-1b
    "10.0.23.0/24"   # eu-west-1c
  ]
  
  intra_subnet_cidrs = [
    "10.0.31.0/24",  # eu-west-1a
    "10.0.32.0/24",  # eu-west-1b
    "10.0.33.0/24"   # eu-west-1c
  ]
  
  # DNS Configuration
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # NAT Gateway Configuration
  enable_nat_gateway     = true
  single_nat_gateway     = false  # Multi-AZ for HA
  one_nat_gateway_per_az = true
  
  # VPC Flow Logs
  enable_flow_log                      = true
  flow_log_destination_type           = "cloud-watch-logs"
  flow_log_log_format                 = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus}"
  flow_log_max_aggregation_interval   = 60
  
  # Security Configuration
  default_security_group_ingress = []
  default_security_group_egress  = []
  manage_default_security_group  = true
  
  # DHCP Options
  enable_dhcp_options              = true
  dhcp_options_domain_name         = "eu-west-1.compute.internal"
  dhcp_options_domain_name_servers = ["AmazonProvidedDNS"]
  
  # Region-specific settings
  region_settings = {
    # Data residency and compliance
    data_residency = "EU"
    gdpr_compliant = true
    
    # Disaster recovery
    primary_region = true
    dr_region     = "eu-west-2"
    
    # Cost optimization
    reserved_instance_region = "eu-west-1"
    spot_instance_enabled    = true
    
    # Performance
    enhanced_networking = true
    placement_tenancy   = "default"
    
    # Monitoring and logging
    cloudwatch_region = "eu-west-1"
    log_retention_days = 30
  }
  
  # Region-specific tags
  region_tags = {
    Region           = "eu-west-1"
    RegionName       = "Europe (Ireland)"
    DataResidency    = "EU"
    GDPRCompliant    = "true"
    PrimaryRegion    = "true"
    DRRegion         = "eu-west-2"
    TimeZone         = "GMT"
    ComplianceZone   = "EU"
  }
}
