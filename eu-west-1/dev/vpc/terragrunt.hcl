# =============================================================================
# VPC TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================
# This module creates the foundational VPC infrastructure with enhanced
# development-specific features, advanced networking, and comprehensive
# monitoring for the development environment.

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
# LOCAL VARIABLES FOR ADVANCED CONFIGURATION
# =============================================================================
locals {
  # Environment-specific configurations
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  # Advanced networking calculations
  vpc_cidr = local.env_vars.locals.network_config.vpc_cidr
  
  # Calculate subnet CIDRs dynamically
  public_subnets   = local.env_vars.locals.network_config.public_subnet_cidrs
  private_subnets  = local.env_vars.locals.network_config.private_subnet_cidrs
  database_subnets = local.env_vars.locals.network_config.database_subnet_cidrs
  intra_subnets    = local.env_vars.locals.network_config.intra_subnet_cidrs
  
  # Availability zones with advanced distribution
  azs = local.region_vars.locals.availability_zones
  
  # Development-specific features
  enable_development_features = local.env_vars.locals.environment == "dev"
  
  # Advanced tagging strategy
  vpc_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Name                    = "${local.env_vars.locals.name_prefix}-vpc"
      Component              = "Networking"
      Service                = "VPC"
      Description            = "Development VPC with advanced networking features"
      CIDR                   = local.vpc_cidr
      AZs                    = join(",", local.azs)
      SubnetTiers           = "Public,Private,Database,Intra"
      NATGatewayStrategy    = local.env_vars.locals.network_config.single_nat_gateway ? "Single" : "Multi-AZ"
      FlowLogsEnabled       = local.env_vars.locals.network_config.enable_flow_log ? "true" : "false"
      VPCEndpointsEnabled   = "true"
      DevelopmentFeatures   = "enabled"
      NetworkSegmentation   = "4-tier"
      SecurityGroups        = "layered"
      DNSResolution         = "enabled"
      DHCPOptions          = "custom"
    }
  )
}

# =============================================================================
# MODULE INPUTS WITH ADVANCED CONFIGURATION
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC VPC CONFIGURATION
  # =============================================================================
  name = "${local.env_vars.locals.name_prefix}-vpc"
  cidr = local.vpc_cidr
  
  # Availability Zones with enhanced distribution
  azs = local.azs
  
  # =============================================================================
  # SUBNET CONFIGURATION WITH ADVANCED FEATURES
  # =============================================================================
  public_subnets   = local.public_subnets
  private_subnets  = local.private_subnets
  database_subnets = local.database_subnets
  intra_subnets    = local.intra_subnets
  
  # Advanced subnet configuration
  create_database_subnet_group       = true
  create_database_subnet_route_table = true
  create_database_internet_gateway_route = false
  create_database_nat_gateway_route = true
  
  # Intra subnets configuration (for internal services)
  create_intra_subnet_route_table = true
  
  # =============================================================================
  # DNS CONFIGURATION WITH ENHANCED FEATURES
  # =============================================================================
  enable_dns_hostnames = local.env_vars.locals.network_config.enable_dns_hostnames
  enable_dns_support   = local.env_vars.locals.network_config.enable_dns_support
  
  # =============================================================================
  # NAT GATEWAY CONFIGURATION - COST OPTIMIZED FOR DEV
  # =============================================================================
  enable_nat_gateway     = local.env_vars.locals.network_config.enable_nat_gateway
  single_nat_gateway     = local.env_vars.locals.network_config.single_nat_gateway
  one_nat_gateway_per_az = local.env_vars.locals.network_config.one_nat_gateway_per_az
  
  # NAT Gateway placement optimization
  external_nat_ip_ids = []  # Use Elastic IPs if needed
  
  # =============================================================================
  # INTERNET GATEWAY CONFIGURATION
  # =============================================================================
  create_igw = true
  
  # =============================================================================
  # VPC FLOW LOGS WITH ADVANCED CONFIGURATION
  # =============================================================================
  enable_flow_log                      = local.env_vars.locals.network_config.enable_flow_log
  flow_log_destination_type           = local.env_vars.locals.network_config.flow_log_destination_type
  flow_log_log_format                 = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr} $${region} $${az-id}"
  flow_log_max_aggregation_interval   = local.env_vars.locals.network_config.flow_log_max_aggregation_interval
  
  # Advanced flow log configuration
  flow_log_traffic_type = "ALL"
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_cloudwatch_log_group_retention_in_days = 30
  flow_log_cloudwatch_log_group_kms_key_id = "alias/cloudwatch-logs-key"
  
  # =============================================================================
  # SECURITY GROUPS - DEFAULT CONFIGURATION
  # =============================================================================
  manage_default_security_group     = true
  default_security_group_ingress    = []  # No ingress by default
  default_security_group_egress     = []  # No egress by default
  
  # =============================================================================
  # DHCP OPTIONS WITH CUSTOM CONFIGURATION
  # =============================================================================
  enable_dhcp_options              = true
  dhcp_options_domain_name         = "${local.aws_region}.compute.internal"
  dhcp_options_domain_name_servers = ["AmazonProvidedDNS"]
  dhcp_options_ntp_servers         = ["169.254.169.123"]
  dhcp_options_netbios_name_servers = []
  dhcp_options_netbios_node_type   = 2
  
  # =============================================================================
  # VPC ENDPOINTS FOR COST OPTIMIZATION AND SECURITY
  # =============================================================================
  
  # Gateway endpoints (no additional cost)
  enable_s3_endpoint       = true
  enable_dynamodb_endpoint = true
  
  # Interface endpoints for AWS services (development-focused)
  enable_ec2_endpoint               = true
  enable_ec2messages_endpoint       = true
  enable_ssm_endpoint              = true
  enable_ssmmessages_endpoint      = true
  enable_logs_endpoint             = true
  enable_monitoring_endpoint       = true
  enable_events_endpoint           = true
  enable_secretsmanager_endpoint   = true
  enable_kms_endpoint              = true
  
  # Additional endpoints for development
  enable_ecs_endpoint              = true
  enable_ecs_agent_endpoint        = true
  enable_ecs_telemetry_endpoint    = true
  enable_ecr_api_endpoint          = true
  enable_ecr_dkr_endpoint          = true
  enable_lambda_endpoint           = true
  enable_codebuild_endpoint        = true
  enable_codecommit_endpoint       = true
  enable_codepipeline_endpoint     = true
  enable_sns_endpoint              = true
  enable_sqs_endpoint              = true
  
  # Development-specific endpoints
  enable_rds_endpoint              = true
  enable_elasticache_endpoint      = true
  enable_redshift_endpoint         = false  # Not needed for dev
  enable_glue_endpoint             = false  # Not needed for dev
  
  # VPC Endpoint Security Groups
  vpc_endpoint_security_group_ids = []
  
  # =============================================================================
  # ADVANCED SUBNET TAGGING STRATEGY
  # =============================================================================
  
  # Public subnet configuration with advanced tagging
  public_subnet_suffix = "public"
  public_subnet_tags = {
    Type                     = "Public"
    Tier                     = "Web"
    InternetAccess          = "Direct"
    NATGateway              = "Hosted"
    LoadBalancer            = "Allowed"
    "kubernetes.io/role/elb" = "1"
    
    # Development-specific tags
    DevelopmentAccess       = "enabled"
    TestingAllowed         = "true"
    ExternalConnectivity   = "full"
  }
  
  # Private subnet configuration with advanced tagging
  private_subnet_suffix = "private"
  private_subnet_tags = {
    Type                             = "Private"
    Tier                             = "Application"
    InternetAccess                  = "NAT"
    DatabaseAccess                  = "Allowed"
    "kubernetes.io/role/internal-elb" = "1"
    
    # Development-specific tags
    ApplicationTier                 = "backend"
    DatabaseConnectivity           = "enabled"
    CacheAccess                    = "enabled"
    InternalServices               = "hosted"
  }
  
  # Database subnet configuration with advanced tagging
  database_subnet_suffix = "database"
  database_subnet_tags = {
    Type                    = "Database"
    Tier                    = "Data"
    InternetAccess         = "None"
    Encryption             = "Required"
    BackupSchedule         = "Daily"
    
    # Development-specific tags
    DatabaseType           = "PostgreSQL,Redis"
    PerformanceInsights    = "disabled"
    MultiAZ                = "false"
    TestDataAllowed        = "true"
  }
  
  # Intra subnet configuration with advanced tagging
  intra_subnet_suffix = "intra"
  intra_subnet_tags = {
    Type                   = "Intra"
    Tier                   = "Internal"
    InternetAccess        = "None"
    Purpose               = "InternalServices"
    
    # Development-specific tags
    ServiceMesh           = "enabled"
    InternalLoadBalancer  = "allowed"
    MonitoringServices    = "hosted"
    LoggingServices       = "hosted"
  }
  
  # =============================================================================
  # ADVANCED ROUTE TABLE TAGGING
  # =============================================================================
  
  public_route_table_tags = {
    Name                  = "${local.env_vars.locals.name_prefix}-public-rt"
    Type                  = "Public"
    InternetGateway      = "Attached"
    DefaultRoute         = "0.0.0.0/0"
    
    # Development-specific tags
    DevelopmentRouting   = "enabled"
    TestTrafficAllowed   = "true"
  }
  
  private_route_table_tags = {
    Name                 = "${local.env_vars.locals.name_prefix}-private-rt"
    Type                 = "Private"
    NATGateway          = "Attached"
    DefaultRoute        = "NAT"
    
    # Development-specific tags
    ApplicationRouting  = "backend"
    DatabaseRouting     = "enabled"
  }
  
  database_route_table_tags = {
    Name                = "${local.env_vars.locals.name_prefix}-database-rt"
    Type                = "Database"
    InternetAccess     = "None"
    
    # Development-specific tags
    DatabaseIsolation  = "enabled"
    BackupRouting      = "configured"
  }
  
  intra_route_table_tags = {
    Name               = "${local.env_vars.locals.name_prefix}-intra-rt"
    Type               = "Intra"
    Isolation         = "Complete"
    
    # Development-specific tags
    InternalServices  = "isolated"
    ServiceDiscovery  = "enabled"
  }
  
  # =============================================================================
  # GATEWAY TAGGING WITH ADVANCED METADATA
  # =============================================================================
  
  # NAT Gateway tags with cost tracking
  nat_gateway_tags = {
    Name                = "${local.env_vars.locals.name_prefix}-nat"
    Type                = "NAT Gateway"
    CostOptimization   = "SingleGateway"
    
    # Development-specific tags
    DevelopmentAccess  = "enabled"
    CostSaving         = "optimized"
    Usage              = "development-only"
  }
  
  # Internet Gateway tags
  igw_tags = {
    Name               = "${local.env_vars.locals.name_prefix}-igw"
    Type               = "Internet Gateway"
    PublicAccess      = "Enabled"
    
    # Development-specific tags
    DevelopmentAccess = "full"
    TestingSupport    = "enabled"
  }
  
  # =============================================================================
  # VPC ENDPOINT TAGGING
  # =============================================================================
  
  vpc_endpoint_tags = {
    Environment        = local.env_vars.locals.environment
    CostOptimization  = "InterfaceEndpoints"
    SecurityBenefit   = "PrivateConnectivity"
    
    # Development-specific tags
    DevelopmentTools  = "enabled"
    APIAccess         = "private"
  }
  
  # =============================================================================
  # MAIN VPC TAGS WITH COMPREHENSIVE METADATA
  # =============================================================================
  tags = local.vpc_tags
}

# =============================================================================
# GENERATE ADDITIONAL DEVELOPMENT-SPECIFIC RESOURCES
# =============================================================================
generate "development_networking" {
  path      = "development_networking.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# DEVELOPMENT-SPECIFIC NETWORKING RESOURCES
# =============================================================================

# Network ACLs for additional security layers
resource "aws_network_acl" "development_nacl" {
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Allow HTTP/HTTPS inbound
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow SSH for development
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "10.1.0.0/16"
    from_port  = 22
    to_port    = 22
  }

  # Allow application ports
  ingress {
    protocol   = "tcp"
    rule_no    = 130
    action     = "allow"
    cidr_block = "10.1.0.0/16"
    from_port  = 8000
    to_port    = 8999
  }

  # Allow database ports within VPC
  ingress {
    protocol   = "tcp"
    rule_no    = 140
    action     = "allow"
    cidr_block = "10.1.0.0/16"
    from_port  = 5432
    to_port    = 5432
  }

  # Allow Redis within VPC
  ingress {
    protocol   = "tcp"
    rule_no    = 150
    action     = "allow"
    cidr_block = "10.1.0.0/16"
    from_port  = 6379
    to_port    = 6379
  }

  # Allow ephemeral ports
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow all outbound
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.env_vars.locals.name_prefix}-dev-nacl"
    Component = "Networking"
    Service   = "NetworkACL"
    Purpose   = "Development Security"
  })
}

# VPC Peering for cross-environment connectivity (if needed)
resource "aws_vpc_peering_connection" "dev_to_shared_services" {
  count = var.enable_shared_services_peering ? 1 : 0
  
  vpc_id      = module.vpc.vpc_id
  peer_vpc_id = var.shared_services_vpc_id
  peer_region = local.aws_region
  auto_accept = true

  accepter {
    allow_remote_vpc_dns_resolution = true
  }

  requester {
    allow_remote_vpc_dns_resolution = true
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.env_vars.locals.name_prefix}-to-shared-services"
    Component = "Networking"
    Service   = "VPCPeering"
    Purpose   = "Shared Services Access"
  })
}

# Route53 Resolver Rules for hybrid DNS (development-specific)
resource "aws_route53_resolver_rule" "development_dns_forwarding" {
  count = var.enable_development_dns_forwarding ? 1 : 0
  
  domain_name          = "dev.internal"
  name                 = "$${local.env_vars.locals.name_prefix}-dev-dns-forwarding"
  rule_type           = "FORWARD"
  resolver_endpoint_id = var.resolver_endpoint_id

  target_ip {
    ip   = "10.1.0.2"
    port = 53
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.env_vars.locals.name_prefix}-dev-dns-forwarding"
    Component = "Networking"
    Service   = "Route53Resolver"
    Purpose   = "Development DNS"
  })
}

# CloudWatch Log Group for VPC Flow Logs with custom retention
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flowlogs/$${local.env_vars.locals.name_prefix}"
  retention_in_days = 30
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"

  tags = merge(local.common_tags, {
    Name      = "$${local.env_vars.locals.name_prefix}-vpc-flow-logs"
    Component = "Monitoring"
    Service   = "CloudWatch"
    Purpose   = "VPC Flow Logs"
  })
}

# VPC Flow Logs metric filters for development monitoring
resource "aws_cloudwatch_log_metric_filter" "vpc_rejected_traffic" {
  name           = "$${local.env_vars.locals.name_prefix}-vpc-rejected-traffic"
  log_group_name = aws_cloudwatch_log_group.vpc_flow_logs.name
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"

  metric_transformation {
    name      = "VPCRejectedTraffic"
    namespace = "KatyaCleaning/VPC/Development"
    value     = "1"
  }
}

# Development-specific security group for debugging
resource "aws_security_group" "development_debug" {
  name_prefix = "$${local.env_vars.locals.name_prefix}-debug-"
  vpc_id      = module.vpc.vpc_id
  description = "Security group for development debugging and testing"

  # Allow all traffic within VPC for debugging
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
    description = "All TCP traffic within VPC for debugging"
  }

  # Allow ICMP for network debugging
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [local.vpc_cidr]
    description = "ICMP for network debugging"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name      = "$${local.env_vars.locals.name_prefix}-debug-sg"
    Component = "Security"
    Service   = "SecurityGroup"
    Purpose   = "Development Debugging"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# OUTPUTS FOR DEPENDENCY MANAGEMENT
# =============================================================================
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "database_subnets" {
  description = "List of IDs of database subnets"
  value       = module.vpc.database_subnets
}

output "intra_subnets" {
  description = "List of IDs of intra subnets"
  value       = module.vpc.intra_subnets
}

output "database_subnet_group" {
  description = "ID of the database subnet group"
  value       = module.vpc.database_subnet_group
}

output "nat_gateway_ids" {
  description = "List of IDs of the NAT Gateways"
  value       = module.vpc.natgw_ids
}

output "internet_gateway_id" {
  description = "The ID of the Internet Gateway"
  value       = module.vpc.igw_id
}

output "vpc_endpoint_s3_id" {
  description = "The ID of VPC endpoint for S3"
  value       = module.vpc.vpc_endpoint_s3_id
}

output "vpc_endpoint_dynamodb_id" {
  description = "The ID of VPC endpoint for DynamoDB"
  value       = module.vpc.vpc_endpoint_dynamodb_id
}

output "default_security_group_id" {
  description = "The ID of the security group created by default on VPC creation"
  value       = module.vpc.default_security_group_id
}

output "development_debug_security_group_id" {
  description = "The ID of the development debug security group"
  value       = aws_security_group.development_debug.id
}

output "vpc_flow_logs_log_group_name" {
  description = "The name of the CloudWatch Log Group for VPC Flow Logs"
  value       = aws_cloudwatch_log_group.vpc_flow_logs.name
}

# Development-specific outputs
output "development_features_enabled" {
  description = "Whether development features are enabled"
  value       = local.enable_development_features
}

output "cost_optimization_features" {
  description = "Cost optimization features enabled for development"
  value = {
    single_nat_gateway = local.env_vars.locals.network_config.single_nat_gateway
    flow_log_retention = 30
    endpoint_optimization = "enabled"
  }
}

# =============================================================================
# VARIABLES FOR ADVANCED CONFIGURATION
# =============================================================================
variable "enable_shared_services_peering" {
  description = "Enable VPC peering to shared services VPC"
  type        = bool
  default     = false
}

variable "shared_services_vpc_id" {
  description = "VPC ID of shared services VPC for peering"
  type        = string
  default     = ""
}

variable "enable_development_dns_forwarding" {
  description = "Enable DNS forwarding for development domains"
  type        = bool
  default     = false
}

variable "resolver_endpoint_id" {
  description = "Route53 Resolver endpoint ID for DNS forwarding"
  type        = string
  default     = ""
}
EOF
}
