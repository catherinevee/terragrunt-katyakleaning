# =============================================================================
# AUTO SCALING GROUP TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates Auto Scaling Groups for web and application servers
# with launch templates and scaling policies for the production environment.

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

dependency "alb" {
  config_path = "../alb"
  
  mock_outputs = {
    target_group_arns = ["arn:aws:elasticloadbalancing:eu-west-1:123456789012:targetgroup/mock/1234567890123456"]
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/autoscaling/aws?version=7.4.1"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # AUTO SCALING GROUP CONFIGURATION
  # =============================================================================
  name = "${local.name_prefix}-web-asg"
  
  # Capacity configuration
  min_size         = local.env_vars.locals.min_capacity.web_server
  max_size         = local.env_vars.locals.max_capacity.web_server
  desired_capacity = local.env_vars.locals.desired_capacity.web_server
  
  # Network configuration
  vpc_zone_identifier = dependency.vpc.outputs.private_subnets
  
  # Health check configuration
  health_check_type         = "ELB"
  health_check_grace_period = 300
  default_cooldown         = 300
  
  # Target group attachment
  target_group_arns = dependency.alb.outputs.target_group_arns
  
  # =============================================================================
  # LAUNCH TEMPLATE CONFIGURATION
  # =============================================================================
  create_launch_template = true
  launch_template_name   = "${local.name_prefix}-web-lt"
  
  # Instance configuration
  image_id      = "ami-0c02fb55956c7d316"  # Amazon Linux 2023 AMI
  instance_type = local.env_vars.locals.instance_types.web_server
  key_name      = "${local.name_prefix}-keypair"
  
  # Security groups
  vpc_security_group_ids = [dependency.security_groups.outputs.web_security_group_id]
  
  # Instance metadata service configuration (IMDSv2 enforcement)
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  # Monitoring
  enable_monitoring = true
  
  # EBS optimization
  ebs_optimized = true
  
  # Block device mappings
  block_device_mappings = [
    {
      device_name = "/dev/xvda"
      ebs = {
        volume_size           = 20
        volume_type          = "gp3"
        iops                 = 3000
        throughput           = 125
        encrypted            = true
        kms_key_id          = "alias/ebs-encryption-key"
        delete_on_termination = true
      }
    },
    {
      device_name = "/dev/sdf"
      ebs = {
        volume_size           = 50
        volume_type          = "gp3"
        iops                 = 3000
        throughput           = 125
        encrypted            = true
        kms_key_id          = "alias/ebs-encryption-key"
        delete_on_termination = false
      }
    }
  ]
  
  # User data for instance initialization
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment    = local.environment
    app_name      = local.env_vars.locals.app_config.app_name
    app_version   = local.env_vars.locals.app_config.app_version
    region        = local.aws_region
  }))
  
  # =============================================================================
  # SCALING POLICIES
  # =============================================================================
  scaling_policies = {
    # Scale up policy
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
    
    # Scale down policy
    scale_down = {
      policy_type               = "TargetTrackingScaling"
      estimated_instance_warmup = 300
      target_tracking_configuration = {
        predefined_metric_specification = {
          predefined_metric_type = "ALBRequestCountPerTarget"
          resource_label = dependency.alb.outputs.arn_suffix
        }
        target_value = 1000.0
      }
    }
  }
  
  # =============================================================================
  # INSTANCE REFRESH
  # =============================================================================
  instance_refresh = {
    strategy = "Rolling"
    preferences = {
      checkpoint_delay       = 600
      checkpoint_percentages = [20, 50, 100]
      instance_warmup       = 300
      min_healthy_percentage = 50
    }
    triggers = ["tag"]
  }
  
  # =============================================================================
  # WARM POOL CONFIGURATION
  # =============================================================================
  warm_pool = {
    pool_state                  = "Stopped"
    min_size                   = 1
    max_group_prepared_capacity = 2
    
    instance_reuse_policy = {
      reuse_on_scale_in = true
    }
  }
  
  # =============================================================================
  # TERMINATION POLICIES
  # =============================================================================
  termination_policies = ["OldestInstance", "Default"]
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-web-asg"
      Component      = "AutoScaling"
      Service        = "ASG"
      Tier           = "Web"
      Description    = "Production Auto Scaling Group for web servers"
      InstanceType   = local.env_vars.locals.instance_types.web_server
      MinSize        = local.env_vars.locals.min_capacity.web_server
      MaxSize        = local.env_vars.locals.max_capacity.web_server
      DesiredCapacity = local.env_vars.locals.desired_capacity.web_server
      HealthCheckType = "ELB"
      ScalingPolicy   = "TargetTracking"
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
# USER DATA SCRIPT FOR AUTO SCALING WEB SERVERS
# =============================================================================

# Set error handling
set -e

# Log all output
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "Starting user data script execution at $(date)"

# Update system
yum update -y

# Install required packages
yum install -y \
    httpd \
    php \
    php-mysql \
    php-redis \
    wget \
    curl \
    unzip \
    git \
    htop \
    awscli \
    amazon-cloudwatch-agent \
    amazon-ssm-agent \
    collectd

# Install additional monitoring tools
yum install -y \
    sysstat \
    iotop \
    nethogs \
    tcpdump

# Configure CloudWatch agent
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CWEOF'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
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
        "metrics_collection_interval": 60,
        "totalcpu": false
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
          "io_time",
          "read_bytes",
          "write_bytes",
          "reads",
          "writes"
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
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/httpd/error_log",
            "log_group_name": "/aws/ec2/httpd/error",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
          },
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/ec2/system",
            "log_stream_name": "{instance_id}",
            "timezone": "UTC"
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

# Configure PHP
cat > /etc/php.d/99-custom.ini << 'PHPEOF'
; Custom PHP configuration for production
memory_limit = 256M
max_execution_time = 30
max_input_time = 60
upload_max_filesize = 10M
post_max_size = 10M
session.gc_maxlifetime = 3600
session.cookie_secure = 1
session.cookie_httponly = 1
expose_php = Off
PHPEOF

# Create application directory structure
mkdir -p /var/www/html/{public,logs,tmp}
mkdir -p /data/{uploads,cache,sessions}

# Set proper permissions
chown -R apache:apache /var/www/html
chown -R apache:apache /data
chmod -R 755 /var/www/html
chmod -R 755 /data

# Create health check endpoint
cat > /var/www/html/health << 'HEALTHEOF'
<?php
header('Content-Type: application/json');

$health = [
    'status' => 'healthy',
    'timestamp' => date('c'),
    'version' => '${app_version}',
    'environment' => '${environment}',
    'region' => '${region}',
    'instance_id' => file_get_contents('http://169.254.169.254/latest/meta-data/instance-id'),
    'checks' => []
];

// Database connectivity check
try {
    $pdo = new PDO('pgsql:host=db.internal.katyacleaning.local;dbname=katyacleaning', 'app_user', 'password');
    $health['checks']['database'] = 'healthy';
} catch (Exception $e) {
    $health['checks']['database'] = 'unhealthy';
    $health['status'] = 'degraded';
}

// Redis connectivity check
try {
    $redis = new Redis();
    $redis->connect('cache.internal.katyacleaning.local', 6379);
    $redis->ping();
    $health['checks']['cache'] = 'healthy';
} catch (Exception $e) {
    $health['checks']['cache'] = 'unhealthy';
    $health['status'] = 'degraded';
}

// Disk space check
$disk_free = disk_free_space('/');
$disk_total = disk_total_space('/');
$disk_usage = (($disk_total - $disk_free) / $disk_total) * 100;

if ($disk_usage > 90) {
    $health['checks']['disk'] = 'critical';
    $health['status'] = 'unhealthy';
} elseif ($disk_usage > 80) {
    $health['checks']['disk'] = 'warning';
    if ($health['status'] === 'healthy') {
        $health['status'] = 'degraded';
    }
} else {
    $health['checks']['disk'] = 'healthy';
}

$health['checks']['disk_usage_percent'] = round($disk_usage, 2);

echo json_encode($health, JSON_PRETTY_PRINT);
?>
HEALTHEOF

# Set proper permissions for health check
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

# Configure automatic security updates
yum install -y yum-cron
systemctl enable yum-cron
systemctl start yum-cron

# Enable and start SSM agent
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent

# Configure collectd for additional metrics
cat > /etc/collectd.conf << 'COLLECTDEOF'
Hostname "$(curl -s http://169.254.169.254/latest/meta-data/instance-id)"
FQDNLookup true
BaseDir "/var/lib/collectd"
PIDFile "/var/run/collectd.pid"
PluginDir "/usr/lib64/collectd"
TypesDB "/usr/share/collectd/types.db"

LoadPlugin syslog
LoadPlugin cpu
LoadPlugin interface
LoadPlugin load
LoadPlugin memory
LoadPlugin network
LoadPlugin processes
LoadPlugin apache
LoadPlugin df

<Plugin syslog>
    LogLevel info
</Plugin>

<Plugin cpu>
    ReportByCpu true
    ReportByState true
    ValuesPercentage true
</Plugin>

<Plugin df>
    MountPoint "/"
    MountPoint "/data"
    ReportByDevice false
    ReportReserved false
    ReportInodes false
    ValuesAbsolute true
    ValuesPercentage true
</Plugin>

<Plugin apache>
    <Instance "localhost">
        URL "http://localhost/server-status?auto"
    </Instance>
</Plugin>
COLLECTDEOF

systemctl enable collectd
systemctl start collectd

# Configure Apache server status
cat >> /etc/httpd/conf/httpd.conf << 'STATUSEOF'

# Server status configuration
<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1
    Require ip 10.0.0.0/8
</Location>

ExtendedStatus On
STATUSEOF

# Restart Apache to apply configuration
systemctl restart httpd

# Create startup script for application deployment
cat > /opt/deploy-app.sh << 'DEPLOYEOF'
#!/bin/bash
# Application deployment script

echo "Starting application deployment at $(date)"

# Pull latest application code from S3 or CodeDeploy
# This would be customized based on your deployment strategy

echo "Application deployment completed at $(date)"
DEPLOYEOF

chmod +x /opt/deploy-app.sh

# Signal completion to CloudFormation/Auto Scaling
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
REGION=$(curl -s http://169.254.169.254/latest/meta-data/placement/region)

# Send success signal
aws autoscaling complete-lifecycle-action \
    --lifecycle-hook-name "launch-hook" \
    --auto-scaling-group-name "${local.name_prefix}-web-asg" \
    --lifecycle-action-result CONTINUE \
    --instance-id $INSTANCE_ID \
    --region $REGION || true

echo "Web server initialization completed at $(date)" >> /var/log/user-data.log
EOF
}
