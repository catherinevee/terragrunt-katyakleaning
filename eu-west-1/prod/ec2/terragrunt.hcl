# =============================================================================
# EC2 TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates EC2 instances for web and application servers using the
# comprehensive EC2 module from GitHub with maximum customizability.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# Dependencies
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id          = "vpc-mock"
    private_subnets = ["subnet-mock-1", "subnet-mock-2"]
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    web_security_group_id = "sg-mock-web"
    app_security_group_id = "sg-mock-app"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "git::https://github.com/catherinevee/ec2.git?ref=v1.0.0"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC INSTANCE CONFIGURATION
  # =============================================================================
  name = "${local.name_prefix}-web-server"
  
  # Instance specifications
  instance_type = local.env_vars.locals.instance_types.web_server
  ami           = "ami-0c02fb55956c7d316"  # Amazon Linux 2023 AMI
  
  # Key pair for SSH access
  key_name = "${local.name_prefix}-keypair"
  
  # Network configuration
  vpc_security_group_ids = [dependency.security_groups.outputs.web_security_group_id]
  subnet_id             = dependency.vpc.outputs.private_subnets[0]
  
  # Public IP configuration
  associate_public_ip_address = false  # Private subnet, no public IP
  
  # =============================================================================
  # ADVANCED INSTANCE CONFIGURATION
  # =============================================================================
  
  # Instance metadata service configuration (IMDSv2 enforcement)
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                = "required"  # Enforce IMDSv2
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  # CPU configuration for performance optimization
  cpu_options = {
    core_count       = 1
    threads_per_core = 2
  }
  
  # Credit specification for burstable instances
  credit_specification = {
    cpu_credits = "standard"
  }
  
  # Nitro Enclaves for enhanced security (if supported)
  enclave_options = {
    enabled = false  # Enable if needed for sensitive workloads
  }
  
  # Maintenance options
  maintenance_options = {
    auto_recovery = "default"
  }
  
  # Private DNS name options
  private_dns_name_options = {
    enable_resource_name_dns_aaaa_record = false
    enable_resource_name_dns_a_record    = true
    hostname_type                        = "ip-name"
  }
  
  # =============================================================================
  # STORAGE CONFIGURATION
  # =============================================================================
  
  # Root volume configuration
  root_block_device = [
    {
      volume_type           = "gp3"
      volume_size          = 20
      iops                 = 3000
      throughput           = 125
      encrypted            = true
      kms_key_id          = "alias/ebs-encryption-key"
      delete_on_termination = true
      
      tags = {
        Name = "${local.name_prefix}-web-root-volume"
        Type = "Root"
      }
    }
  ]
  
  # Additional EBS volumes
  ebs_block_device = [
    {
      device_name          = "/dev/sdf"
      volume_type          = "gp3"
      volume_size          = 50
      iops                 = 3000
      throughput           = 125
      encrypted            = true
      kms_key_id          = "alias/ebs-encryption-key"
      delete_on_termination = false
      
      tags = {
        Name = "${local.name_prefix}-web-data-volume"
        Type = "Data"
      }
    }
  ]
  
  # =============================================================================
  # NETWORKING CONFIGURATION
  # =============================================================================
  
  # IPv6 support
  ipv6_address_count = 0
  ipv6_addresses     = []
  
  # Secondary private IP addresses
  secondary_private_ips = []
  
  # Source/destination check
  source_dest_check = true
  
  # =============================================================================
  # MONITORING AND PERFORMANCE
  # =============================================================================
  
  # Detailed monitoring
  monitoring = true
  
  # EBS optimization
  ebs_optimized = true
  
  # Placement configuration
  placement_group                = ""
  placement_partition_number     = null
  placement_affinity            = null
  placement_availability_zone   = null
  placement_group_name          = null
  placement_host_id             = null
  placement_host_resource_group_arn = null
  placement_spread_domain       = null
  placement_tenancy             = "default"
  
  # =============================================================================
  # SECURITY CONFIGURATION
  # =============================================================================
  
  # Disable API termination for production
  disable_api_termination = local.environment == "prod" ? true : false
  
  # Instance initiated shutdown behavior
  instance_initiated_shutdown_behavior = "stop"
  
  # User data for instance initialization
  user_data_base64 = base64encode(templatefile("${path.module}/user_data.sh", {
    environment    = local.environment
    app_name      = local.env_vars.locals.app_config.app_name
    app_version   = local.env_vars.locals.app_config.app_version
    region        = local.aws_region
  }))
  
  # =============================================================================
  # HIBERNATION AND POWER MANAGEMENT
  # =============================================================================
  
  # Hibernation support (for supported instance types)
  hibernation = false
  
  # =============================================================================
  # CAPACITY RESERVATIONS
  # =============================================================================
  
  # Capacity reservation specification
  capacity_reservation_specification = {
    capacity_reservation_preference = "open"
  }
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-web-server"
      Component      = "WebServer"
      Service        = "EC2"
      Tier           = "Web"
      Description    = "Production web server for Katya Cleaning Services"
      InstanceType   = local.env_vars.locals.instance_types.web_server
      Role           = "WebServer"
      Backup         = "Daily"
      Monitoring     = "Enhanced"
      SecurityLevel  = "High"
      PatchGroup     = "WebServers"
      MaintenanceWindow = "Sunday 04:00-05:00 GMT"
    }
  )
  
  # Volume tags
  volume_tags = merge(
    local.common_tags,
    {
      Component = "Storage"
      Service   = "EBS"
      Backup    = "Daily"
    }
  )
}

# =============================================================================
# GENERATE USER DATA SCRIPT
# =============================================================================
generate "user_data" {
  path      = "user_data.sh"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
#!/bin/bash
# =============================================================================
# USER DATA SCRIPT FOR WEB SERVERS
# =============================================================================

# Update system
yum update -y

# Install required packages
yum install -y \
    httpd \
    php \
    php-mysql \
    wget \
    curl \
    unzip \
    git \
    htop \
    awscli \
    amazon-cloudwatch-agent \
    amazon-ssm-agent

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CWEOF'
{
  "metrics": {
    "namespace": "KatyaCleaning/EC2",
    "metrics_collected": {
      "cpu": {
        "measurement": [
          "cpu_usage_idle",
          "cpu_usage_iowait",
          "cpu_usage_user",
          "cpu_usage_system"
        ],
        "metrics_collection_interval": 60
      },
      "disk": {
        "measurement": [
          "used_percent"
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "*"
        ]
      },
      "diskio": {
        "measurement": [
          "io_time"
        ],
        "metrics_collection_interval": 60,
        "resources": [
          "*"
        ]
      },
      "mem": {
        "measurement": [
          "mem_used_percent"
        ],
        "metrics_collection_interval": 60
      },
      "netstat": {
        "measurement": [
          "tcp_established",
          "tcp_time_wait"
        ],
        "metrics_collection_interval": 60
      },
      "swap": {
        "measurement": [
          "swap_used_percent"
        ],
        "metrics_collection_interval": 60
      }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/httpd/access_log",
            "log_group_name": "/aws/ec2/httpd/access",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/httpd/error_log",
            "log_group_name": "/aws/ec2/httpd/error",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
CWEOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

# Configure Apache
systemctl enable httpd
systemctl start httpd

# Create a simple health check endpoint
cat > /var/www/html/health << 'HEALTHEOF'
{
  "status": "healthy",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "${app_version}",
  "environment": "${environment}",
  "region": "${region}"
}
HEALTHEOF

# Set proper permissions
chown apache:apache /var/www/html/health
chmod 644 /var/www/html/health

# Configure log rotation
cat > /etc/logrotate.d/httpd << 'LOGEOF'
/var/log/httpd/*log {
    daily
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 640 apache apache
    postrotate
        /bin/systemctl reload httpd.service > /dev/null 2>/dev/null || true
    endscript
}
LOGEOF

# Mount additional EBS volume
mkdir -p /data
echo '/dev/nvme1n1 /data ext4 defaults,nofail 0 2' >> /etc/fstab

# Format and mount if not already formatted
if ! blkid /dev/nvme1n1; then
    mkfs.ext4 /dev/nvme1n1
fi
mount -a

# Set ownership for data directory
chown apache:apache /data
chmod 755 /data

# Enable and start SSM agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Signal completion
/opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource AutoScalingGroup --region ${AWS::Region}

echo "Web server initialization completed at $(date)" >> /var/log/user-data.log
EOF
}
