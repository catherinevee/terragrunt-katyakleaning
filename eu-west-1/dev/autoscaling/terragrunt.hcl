# =============================================================================
# AUTO SCALING GROUP TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================

include "root" {
  path = find_in_parent_folders("root.hcl")
}

include "env" {
  path = find_in_parent_folders("env.hcl")
}

include "region" {
  path = find_in_parent_folders("region.hcl")
}

# =============================================================================
# DEPENDENCIES
# =============================================================================
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    vpc_id          = "vpc-12345678"
    private_subnets = ["subnet-11111111", "subnet-22222222"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    web_server_security_group_id = "sg-12345678"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "alb" {
  config_path = "../alb"
  
  mock_outputs = {
    target_group_arns = ["arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/test/1234567890123456"]
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/autoscaling/aws?version=7.4.1"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  vpc_id          = dependency.vpc.outputs.vpc_id
  private_subnets = dependency.vpc.outputs.private_subnets
  web_sg_id       = dependency.security_groups.outputs.web_server_security_group_id
  target_group_arns = dependency.alb.outputs.target_group_arns
  
  instance_types = local.env_vars.locals.instance_types
  min_capacity   = local.env_vars.locals.min_capacity
  max_capacity   = local.env_vars.locals.max_capacity
  desired_capacity = local.env_vars.locals.desired_capacity
  
  asg_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component         = "AutoScaling"
      Service          = "ASG"
      InstanceType     = local.instance_types.web_server
      DevelopmentASG   = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # Basic configuration
  name = "${local.env_vars.locals.name_prefix}-web-asg"
  
  # Capacity configuration
  min_size         = local.min_capacity.web_server
  max_size         = local.max_capacity.web_server
  desired_capacity = local.desired_capacity.web_server
  
  # Network configuration
  vpc_zone_identifier = local.private_subnets
  
  # Health checks
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  # Target group integration
  target_group_arns = local.target_group_arns
  
  # Launch template configuration
  launch_template_name        = "${local.env_vars.locals.name_prefix}-web-lt"
  launch_template_description = "Development launch template for web servers"
  
  # Instance configuration
  image_id      = ""  # Will use latest Amazon Linux 2
  instance_type = local.instance_types.web_server
  key_name      = local.env_vars.locals.security_config.ssh_key_name
  
  # Security groups
  security_groups = [local.web_sg_id]
  
  # Storage configuration
  block_device_mappings = [
    {
      device_name = "/dev/xvda"
      ebs = {
        volume_size           = 20
        volume_type          = "gp3"
        encrypted            = true
        delete_on_termination = true
      }
    }
  ]
  
  # Metadata options
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags     = "enabled"
  }
  
  # Monitoring
  enable_monitoring = true
  
  # User data
  user_data = base64encode(templatefile("${path.module}/user_data_asg.sh", {
    environment = local.env_vars.locals.environment
    app_name   = local.env_vars.locals.app_config.app_name
    log_group  = "/aws/ec2/${local.env_vars.locals.name_prefix}-asg"
  }))
  
  # Scaling policies
  scaling_policies = {
    scale_up = {
      policy_type               = "TargetTrackingScaling"
      estimated_instance_warmup = 300
      target_tracking_configuration = {
        predefined_metric_specification = {
          predefined_metric_type = "ASGAverageCPUUtilization"
        }
        target_value = 70.0
      }
    }
  }
  
  # Instance refresh
  instance_refresh = {
    strategy = "Rolling"
    preferences = {
      checkpoint_delay       = 600
      checkpoint_percentages = [35, 70, 100]
      instance_warmup       = 300
      min_healthy_percentage = 50
    }
    triggers = ["tag"]
  }
  
  # Tags
  tags = local.asg_tags
}

# =============================================================================
# GENERATE ADDITIONAL ASG RESOURCES
# =============================================================================
generate "asg_development_features" {
  path      = "asg_development_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
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

# IAM role for ASG instances
resource "aws_iam_role" "asg_instance_role" {
  name = "$${local.env_vars.locals.name_prefix}-asg-instance-role"

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

  tags = merge(local.asg_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-asg-instance-role"
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "asg_instance_profile" {
  name = "$${local.env_vars.locals.name_prefix}-asg-instance-profile"
  role = aws_iam_role.asg_instance_role.name

  tags = merge(local.asg_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-asg-instance-profile"
  })
}

# Attach necessary policies
resource "aws_iam_role_policy_attachment" "ssm_managed_instance" {
  role       = aws_iam_role.asg_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.asg_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# CloudWatch Log Group for ASG instances
resource "aws_cloudwatch_log_group" "asg_logs" {
  name              = "/aws/ec2/$${local.env_vars.locals.name_prefix}-asg"
  retention_in_days = 30

  tags = merge(local.asg_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-asg-logs"
  })
}

# CloudWatch Dashboard for ASG monitoring
resource "aws_cloudwatch_dashboard" "asg_development" {
  dashboard_name = "$${local.env_vars.locals.name_prefix}-asg-dev"

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
            ["AWS/AutoScaling", "GroupDesiredCapacity", "AutoScalingGroupName", module.asg.autoscaling_group_name],
            [".", "GroupInServiceInstances", ".", "."],
            [".", "GroupTotalInstances", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "Auto Scaling Group Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Development-specific scheduled actions for cost optimization
resource "aws_autoscaling_schedule" "scale_down_evening" {
  scheduled_action_name  = "$${local.env_vars.locals.name_prefix}-scale-down-evening"
  min_size              = 0
  max_size              = local.max_capacity.web_server
  desired_capacity      = 0
  recurrence            = "0 19 * * MON-FRI"  # 7 PM weekdays
  auto_scaling_group_name = module.asg.autoscaling_group_name
}

resource "aws_autoscaling_schedule" "scale_up_morning" {
  scheduled_action_name  = "$${local.env_vars.locals.name_prefix}-scale-up-morning"
  min_size              = local.min_capacity.web_server
  max_size              = local.max_capacity.web_server
  desired_capacity      = local.desired_capacity.web_server
  recurrence            = "0 8 * * MON-FRI"   # 8 AM weekdays
  auto_scaling_group_name = module.asg.autoscaling_group_name
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "autoscaling_group_id" {
  description = "The autoscaling group id"
  value       = module.asg.autoscaling_group_id
}

output "autoscaling_group_name" {
  description = "The autoscaling group name"
  value       = module.asg.autoscaling_group_name
}

output "autoscaling_group_arn" {
  description = "The ARN for this AutoScaling Group"
  value       = module.asg.autoscaling_group_arn
}

output "launch_template_id" {
  description = "The ID of the launch template"
  value       = module.asg.launch_template_id
}

output "launch_template_arn" {
  description = "The ARN of the launch template"
  value       = module.asg.launch_template_arn
}

output "iam_role_arn" {
  description = "The ARN of the IAM role"
  value       = aws_iam_role.asg_instance_role.arn
}

output "dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.asg_development.dashboard_name}"
}
EOF
}

# =============================================================================
# GENERATE USER DATA SCRIPT FOR ASG
# =============================================================================
generate "user_data_asg_script" {
  path      = "user_data_asg.sh"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
#!/bin/bash
# =============================================================================
# AUTO SCALING GROUP USER DATA SCRIPT - DEVELOPMENT
# =============================================================================

set -e

# Variables
ENVIRONMENT="${environment}"
APP_NAME="${app_name}"
LOG_GROUP="${log_group}"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a /var/log/user-data.log
}

log "Starting ASG instance setup for development..."

# Update system
log "Updating system packages..."
yum update -y

# Install basic tools
log "Installing basic tools..."
yum install -y \
    curl \
    wget \
    htop \
    git \
    docker \
    nginx \
    nodejs \
    npm

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
                        "file_path": "/var/log/nginx/access.log",
                        "log_group_name": "${log_group}",
                        "log_stream_name": "{instance_id}/nginx-access"
                    },
                    {
                        "file_path": "/var/log/nginx/error.log",
                        "log_group_name": "${log_group}",
                        "log_stream_name": "{instance_id}/nginx-error"
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
        "namespace": "KatyaCleaning/ASG/Development",
        "metrics_collected": {
            "cpu": {
                "measurement": ["cpu_usage_idle", "cpu_usage_user", "cpu_usage_system"],
                "metrics_collection_interval": 60
            },
            "disk": {
                "measurement": ["used_percent"],
                "metrics_collection_interval": 60,
                "resources": ["*"]
            },
            "mem": {
                "measurement": ["mem_used_percent"],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOL

# Start CloudWatch agent
log "Starting CloudWatch agent..."
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/nginx.conf << 'EOL'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    server {
        listen 8080 default_server;
        listen [::]:8080 default_server;
        server_name _;
        root /var/www/html;

        location / {
            try_files $uri $uri/ =404;
        }

        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
EOL

# Create simple health check page
log "Creating health check page..."
mkdir -p /var/www/html
cat > /var/www/html/index.html << EOL
<!DOCTYPE html>
<html>
<head>
    <title>Development Server - ${app_name}</title>
</head>
<body>
    <h1>Development Environment</h1>
    <p>Application: ${app_name}</p>
    <p>Environment: ${environment}</p>
    <p>Instance ID: $(curl -s http://169.254.169.254/latest/meta-data/instance-id)</p>
    <p>Status: Running</p>
</body>
</html>
EOL

# Start services
log "Starting services..."
systemctl start nginx
systemctl enable nginx
systemctl start docker
systemctl enable docker

# Create application directory
mkdir -p /opt/app
chown nginx:nginx /opt/app

log "ASG instance setup completed successfully!"

# Signal completion to CloudFormation (if applicable)
/opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource AutoScalingGroup --region ${AWS::Region} || true
EOF
}
