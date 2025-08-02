# =============================================================================
# EC2 TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================
# This module creates EC2 instances with advanced development features,
# comprehensive monitoring, and enhanced security configurations.

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
# DEPENDENCIES
# =============================================================================
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id           = "vpc-12345678"
    private_subnets  = ["subnet-11111111", "subnet-22222222"]
    public_subnets   = ["subnet-12345678", "subnet-87654321"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    web_server_security_group_id = "sg-12345678"
    app_server_security_group_id = "sg-87654321"
    bastion_security_group_id    = "sg-11111111"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION - USING GITHUB MODULE
# =============================================================================
terraform {
  source = "git::https://github.com/catherinevee/ec2.git//modules/ec2?ref=v1.0.0"
}

# =============================================================================
# LOCAL VARIABLES FOR ADVANCED EC2 CONFIGURATION
# =============================================================================
locals {
  # Environment-specific configurations
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  # VPC and security group information from dependencies
  vpc_id           = dependency.vpc.outputs.vpc_id
  private_subnets  = dependency.vpc.outputs.private_subnets
  public_subnets   = dependency.vpc.outputs.public_subnets
  
  web_sg_id     = dependency.security_groups.outputs.web_server_security_group_id
  app_sg_id     = dependency.security_groups.outputs.app_server_security_group_id
  bastion_sg_id = dependency.security_groups.outputs.bastion_security_group_id
  
  # Instance configuration
  instance_types = local.env_vars.locals.instance_types
  
  # Development-specific settings
  enable_development_features = true
  
  # Advanced tagging
  ec2_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component         = "Compute"
      Service          = "EC2"
      InstancePurpose  = "ApplicationServer"
      DevelopmentMode  = "enabled"
      AutoShutdown     = "enabled"
      MonitoringLevel  = "enhanced"
    }
  )
}

# =============================================================================
# MODULE INPUTS WITH ADVANCED CONFIGURATION
# =============================================================================
inputs = {
  # Basic configuration
  name_prefix = local.env_vars.locals.name_prefix
  environment = local.env_vars.locals.environment
  
  # Instance configuration
  instance_type = local.instance_types.app_server
  ami_id       = ""  # Will use latest Amazon Linux 2
  key_name     = local.env_vars.locals.security_config.ssh_key_name
  
  # Network configuration
  vpc_id              = local.vpc_id
  subnet_ids          = local.private_subnets
  security_group_ids  = [local.app_sg_id]
  
  # Storage configuration
  root_volume_size = 30
  root_volume_type = "gp3"
  root_volume_encrypted = true
  
  # Additional EBS volumes
  additional_volumes = [
    {
      device_name = "/dev/sdf"
      volume_size = 50
      volume_type = "gp3"
      encrypted   = true
      iops        = 3000
      throughput  = 125
    }
  ]
  
  # Metadata options (IMDSv2)
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags     = "enabled"
  }
  
  # Monitoring
  enable_detailed_monitoring = true
  
  # User data script
  user_data_base64 = base64encode(templatefile("${path.module}/user_data.sh", {
    environment     = local.env_vars.locals.environment
    app_name       = local.env_vars.locals.app_config.app_name
    log_group      = "/aws/ec2/${local.env_vars.locals.name_prefix}"
    debug_mode     = local.env_vars.locals.app_config.debug_mode
  }))
  
  # Tags
  tags = local.ec2_tags
}

# =============================================================================
# GENERATE ADVANCED EC2 RESOURCES
# =============================================================================
generate "advanced_ec2_features" {
  path      = "advanced_ec2_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# DEVELOPMENT-SPECIFIC EC2 RESOURCES
# =============================================================================

# Launch Template for development instances
resource "aws_launch_template" "development" {
  name_prefix   = "$${local.env_vars.locals.name_prefix}-dev-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = local.instance_types.app_server
  key_name      = local.env_vars.locals.security_config.ssh_key_name

  vpc_security_group_ids = [local.app_sg_id]

  # Advanced instance configuration
  instance_initiated_shutdown_behavior = "terminate"
  
  # Metadata options (IMDSv2 enforcement)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags     = "enabled"
  }

  # Block device mappings
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 30
      volume_type          = "gp3"
      encrypted            = true
      delete_on_termination = true
      iops                 = 3000
      throughput           = 125
    }
  }

  # Additional development volume
  block_device_mappings {
    device_name = "/dev/sdf"
    ebs {
      volume_size           = 50
      volume_type          = "gp3"
      encrypted            = true
      delete_on_termination = true
      iops                 = 3000
      throughput           = 125
    }
  }

  # User data for development setup
  user_data = base64encode(templatefile("$${path.module}/user_data_dev.sh", {
    environment     = local.env_vars.locals.environment
    app_name       = local.env_vars.locals.app_config.app_name
    log_group      = "/aws/ec2/$${local.env_vars.locals.name_prefix}"
    debug_mode     = local.env_vars.locals.app_config.debug_mode
    enable_profiling = local.env_vars.locals.app_config.enable_profiling
    dev_tools      = local.env_vars.locals.dev_tools_config
  }))

  # IAM instance profile
  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_development.name
  }

  # Network interface configuration
  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination      = true
    security_groups           = [local.app_sg_id]
  }

  # Credit specification for burstable instances
  credit_specification {
    cpu_credits = "standard"
  }

  # Monitoring
  monitoring {
    enabled = true
  }

  # Placement configuration
  placement {
    availability_zone = local.region_vars.locals.availability_zones[0]
    tenancy          = "default"
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.ec2_tags, {
      Name = "$${local.env_vars.locals.name_prefix}-dev-instance"
      LaunchTemplate = "development"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.ec2_tags, {
      Name = "$${local.env_vars.locals.name_prefix}-dev-volume"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# IAM role for EC2 instances
resource "aws_iam_role" "ec2_development" {
  name = "$${local.env_vars.locals.name_prefix}-ec2-dev-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.ec2_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-dev-role"
    Purpose = "EC2DevelopmentAccess"
  })
}

# IAM policy for development features
resource "aws_iam_role_policy" "ec2_development_policy" {
  name = "$${local.env_vars.locals.name_prefix}-ec2-dev-policy"
  role = aws_iam_role.ec2_development.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:$${local.aws_region}:$${local.aws_account_id}:log-group:/aws/ec2/$${local.env_vars.locals.name_prefix}*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:$${local.aws_region}:$${local.aws_account_id}:parameter/$${local.env_vars.locals.name_prefix}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "arn:aws:secretsmanager:$${local.aws_region}:$${local.aws_account_id}:secret:$${local.env_vars.locals.name_prefix}/*"
      }
    ]
  })
}

# Attach AWS managed policies
resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  role       = aws_iam_role.ec2_development.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.ec2_development.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_development" {
  name = "$${local.env_vars.locals.name_prefix}-ec2-dev-profile"
  role = aws_iam_role.ec2_development.name

  tags = merge(local.ec2_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-dev-profile"
  })
}

# Data source for latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Development instance
resource "aws_instance" "development" {
  count = 1

  launch_template {
    id      = aws_launch_template.development.id
    version = "$$Latest"
  }

  subnet_id = local.private_subnets[count.index % length(local.private_subnets)]

  tags = merge(local.ec2_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-dev-$${count.index + 1}"
    Index = count.index + 1
  })

  lifecycle {
    create_before_destroy = true
    ignore_changes       = [ami]
  }
}

# CloudWatch Log Group for EC2 logs
resource "aws_cloudwatch_log_group" "ec2_development" {
  name              = "/aws/ec2/$${local.env_vars.locals.name_prefix}"
  retention_in_days = 30
  kms_key_id       = "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:alias/cloudwatch-logs-key"

  tags = merge(local.ec2_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-logs"
    Purpose = "EC2Logging"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "instance_ids" {
  description = "List of EC2 instance IDs"
  value       = aws_instance.development[*].id
}

output "private_ips" {
  description = "List of private IP addresses"
  value       = aws_instance.development[*].private_ip
}

output "launch_template_id" {
  description = "ID of the launch template"
  value       = aws_launch_template.development.id
}

output "iam_role_arn" {
  description = "ARN of the IAM role"
  value       = aws_iam_role.ec2_development.arn
}

output "log_group_name" {
  description = "Name of the CloudWatch log group"
  value       = aws_cloudwatch_log_group.ec2_development.name
}
EOF
}

# =============================================================================
# GENERATE USER DATA SCRIPT
# =============================================================================
generate "user_data_script" {
  path      = "user_data_dev.sh"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
#!/bin/bash
# =============================================================================
# DEVELOPMENT EC2 USER DATA SCRIPT
# =============================================================================

set -e

# Variables
ENVIRONMENT="${environment}"
APP_NAME="${app_name}"
LOG_GROUP="${log_group}"
DEBUG_MODE="${debug_mode}"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a /var/log/user-data.log
}

log "Starting development instance setup..."

# Update system
log "Updating system packages..."
yum update -y

# Install development tools
log "Installing development tools..."
yum groupinstall -y "Development Tools"
yum install -y \
    git \
    curl \
    wget \
    htop \
    tree \
    jq \
    unzip \
    vim \
    tmux \
    docker \
    nodejs \
    npm \
    python3 \
    python3-pip

# Install AWS CLI v2
log "Installing AWS CLI v2..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install
rm -rf awscliv2.zip aws/

# Install CloudWatch agent
log "Installing CloudWatch agent..."
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
rpm -U ./amazon-cloudwatch-agent.rpm
rm -f ./amazon-cloudwatch-agent.rpm

# Configure CloudWatch agent
log "Configuring CloudWatch agent..."
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOL'
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "cwagent"
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/messages",
                        "log_group_name": "${log_group}",
                        "log_stream_name": "{instance_id}/messages"
                    },
                    {
                        "file_path": "/var/log/user-data.log",
                        "log_group_name": "${log_group}",
                        "log_stream_name": "{instance_id}/user-data"
                    },
                    {
                        "file_path": "/var/log/application.log",
                        "log_group_name": "${log_group}",
                        "log_stream_name": "{instance_id}/application"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "KatyaCleaning/EC2/Development",
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
            }
        }
    }
}
EOL

# Start CloudWatch agent
log "Starting CloudWatch agent..."
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Start and enable Docker
log "Starting Docker service..."
systemctl start docker
systemctl enable docker
usermod -a -G docker ec2-user

# Install Docker Compose
log "Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create application directory
log "Creating application directory..."
mkdir -p /opt/app
chown ec2-user:ec2-user /opt/app

# Mount additional EBS volume
log "Mounting additional EBS volume..."
mkfs -t xfs /dev/nvme1n1
mkdir -p /opt/data
mount /dev/nvme1n1 /opt/data
chown ec2-user:ec2-user /opt/data
echo '/dev/nvme1n1 /opt/data xfs defaults,nofail 0 2' >> /etc/fstab

# Install Node.js development tools
log "Installing Node.js development tools..."
npm install -g \
    nodemon \
    pm2 \
    eslint \
    prettier \
    @storybook/cli

# Create development user
log "Creating development user..."
useradd -m -s /bin/bash developer
usermod -a -G docker developer
echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up SSH keys for developer user
mkdir -p /home/developer/.ssh
cp /home/ec2-user/.ssh/authorized_keys /home/developer/.ssh/
chown -R developer:developer /home/developer/.ssh
chmod 700 /home/developer/.ssh
chmod 600 /home/developer/.ssh/authorized_keys

# Create development environment file
log "Creating development environment file..."
cat > /opt/app/.env.development << EOL
NODE_ENV=development
DEBUG=true
LOG_LEVEL=debug
APP_NAME=${app_name}
ENVIRONMENT=${environment}
AWS_REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
EOL

chown ec2-user:ec2-user /opt/app/.env.development

# Install development monitoring tools
log "Installing development monitoring tools..."
pip3 install \
    awscli \
    boto3 \
    psutil \
    requests

# Create health check script
log "Creating health check script..."
cat > /opt/app/health-check.sh << 'EOL'
#!/bin/bash
# Health check script for development instance

HEALTH_FILE="/tmp/health-status"
LOG_FILE="/var/log/application.log"

# Check system resources
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.2f", $3/$2 * 100.0)}')
DISK_USAGE=$(df -h / | awk 'NR==2{printf "%s", $5}' | sed 's/%//')

# Log health metrics
echo "$(date): CPU: ${CPU_USAGE}%, Memory: ${MEMORY_USAGE}%, Disk: ${DISK_USAGE}%" >> $LOG_FILE

# Determine health status
if (( $(echo "$CPU_USAGE < 80" | bc -l) )) && \
   (( $(echo "$MEMORY_USAGE < 80" | bc -l) )) && \
   (( $DISK_USAGE < 80 )); then
    echo "healthy" > $HEALTH_FILE
    echo "$(date): System healthy" >> $LOG_FILE
else
    echo "unhealthy" > $HEALTH_FILE
    echo "$(date): System unhealthy - CPU: ${CPU_USAGE}%, Memory: ${MEMORY_USAGE}%, Disk: ${DISK_USAGE}%" >> $LOG_FILE
fi
EOL

chmod +x /opt/app/health-check.sh

# Set up cron job for health checks
log "Setting up health check cron job..."
echo "*/5 * * * * /opt/app/health-check.sh" | crontab -u ec2-user -

# Create development startup script
log "Creating development startup script..."
cat > /opt/app/start-dev.sh << 'EOL'
#!/bin/bash
# Development startup script

source /opt/app/.env.development

echo "Starting development environment..."
echo "Environment: $ENVIRONMENT"
echo "Debug mode: $DEBUG_MODE"

# Start application in development mode
cd /opt/app
if [ -f "package.json" ]; then
    npm run dev &
fi

echo "Development environment started"
EOL

chmod +x /opt/app/start-dev.sh

log "Development instance setup completed successfully!"

# Signal completion
/opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource AutoScalingGroup --region ${AWS::Region} || true
EOF
}
