# =============================================================================
# RDS TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
# =============================================================================
# This module creates RDS Aurora PostgreSQL cluster with development-optimized
# settings, enhanced monitoring, and comprehensive backup strategies.

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
    vpc_id                = "vpc-12345678"
    database_subnets      = ["subnet-33333333", "subnet-44444444"]
    database_subnet_group = "default-db-subnet-group"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    database_security_group_id = "sg-33333333"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

dependency "kms" {
  config_path = "../kms"
  
  mock_outputs = {
    rds_key_arn = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
  
  mock_outputs_allowed_terraform_commands = ["validate", "plan", "show"]
  mock_outputs_merge_strategy_with_state  = "shallow"
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/rds-aurora/aws?version=8.5.0"
}

# =============================================================================
# LOCAL VARIABLES FOR ADVANCED RDS CONFIGURATION
# =============================================================================
locals {
  # Environment-specific configurations
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  # Dependencies
  vpc_id                = dependency.vpc.outputs.vpc_id
  database_subnets      = dependency.vpc.outputs.database_subnets
  database_subnet_group = dependency.vpc.outputs.database_subnet_group
  database_sg_id        = dependency.security_groups.outputs.database_security_group_id
  kms_key_arn          = dependency.kms.outputs.rds_key_arn
  
  # Database configuration
  db_config = local.env_vars.locals.database_config
  
  # Development-specific settings
  cluster_identifier = "${local.env_vars.locals.name_prefix}-aurora-dev"
  
  # Advanced tagging
  rds_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component           = "Database"
      Service            = "RDS Aurora"
      Engine             = "aurora-postgresql"
      EngineVersion      = local.db_config.engine_version
      MultiAZ            = tostring(local.db_config.multi_az)
      BackupRetention    = tostring(local.db_config.backup_retention_period)
      DeletionProtection = tostring(local.db_config.deletion_protection)
      DevelopmentDB      = "true"
      TestDataAllowed    = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS WITH ADVANCED CONFIGURATION
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC CLUSTER CONFIGURATION
  # =============================================================================
  name           = local.cluster_identifier
  engine         = "aurora-postgresql"
  engine_version = local.db_config.engine_version
  
  # Instance configuration
  instances = {
    1 = {
      identifier     = "${local.cluster_identifier}-instance-1"
      instance_class = local.db_config.instance_class
      
      # Development-specific instance settings
      publicly_accessible                = false
      db_parameter_group_name           = aws_db_parameter_group.development.name
      performance_insights_enabled      = local.db_config.performance_insights_enabled
      performance_insights_kms_key_id   = local.kms_key_arn
      performance_insights_retention_period = 7
      monitoring_interval               = local.db_config.monitoring_interval
      monitoring_role_arn              = local.db_config.monitoring_interval > 0 ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
      
      # Development tags
      tags = merge(local.rds_tags, {
        Name = "${local.cluster_identifier}-instance-1"
        Role = "Primary"
      })
    }
  }
  
  # =============================================================================
  # NETWORK CONFIGURATION
  # =============================================================================
  vpc_id               = local.vpc_id
  subnets             = local.database_subnets
  db_subnet_group_name = local.database_subnet_group
  
  # Security
  vpc_security_group_ids = [local.database_sg_id]
  
  # =============================================================================
  # DATABASE CONFIGURATION
  # =============================================================================
  database_name   = "katyacleaning_dev"
  master_username = "postgres"
  manage_master_user_password = true
  master_user_secret_kms_key_id = local.kms_key_arn
  
  port = 5432
  
  # =============================================================================
  # STORAGE AND ENCRYPTION
  # =============================================================================
  storage_encrypted   = local.db_config.storage_encrypted
  kms_key_id         = local.kms_key_arn
  storage_type       = "aurora-iopt1"
  allocated_storage  = local.db_config.allocated_storage
  
  # =============================================================================
  # BACKUP AND MAINTENANCE
  # =============================================================================
  backup_retention_period = local.db_config.backup_retention_period
  preferred_backup_window = local.db_config.backup_window
  preferred_maintenance_window = local.db_config.maintenance_window
  
  # Development-specific backup settings
  copy_tags_to_snapshot     = true
  deletion_protection       = local.db_config.deletion_protection
  skip_final_snapshot      = local.db_config.skip_final_snapshot
  final_snapshot_identifier = local.db_config.skip_final_snapshot ? null : "${local.cluster_identifier}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  # =============================================================================
  # CLUSTER PARAMETER GROUP
  # =============================================================================
  create_db_cluster_parameter_group = true
  db_cluster_parameter_group_name   = "${local.cluster_identifier}-cluster-params"
  db_cluster_parameter_group_family = "aurora-postgresql15"
  db_cluster_parameter_group_description = "Development Aurora PostgreSQL cluster parameter group"
  
  db_cluster_parameter_group_parameters = [
    {
      name  = "shared_preload_libraries"
      value = local.db_config.parameter_group_parameters.shared_preload_libraries
    },
    {
      name  = "log_statement"
      value = local.db_config.parameter_group_parameters.log_statement
    },
    {
      name  = "log_min_duration_statement"
      value = local.db_config.parameter_group_parameters.log_min_duration_statement
    },
    {
      name  = "auto_explain.log_min_duration"
      value = local.db_config.parameter_group_parameters.auto_explain_log_min_duration
    },
    {
      name  = "auto_explain.log_analyze"
      value = local.db_config.parameter_group_parameters.auto_explain_log_analyze
    },
    {
      name  = "auto_explain.log_buffers"
      value = local.db_config.parameter_group_parameters.auto_explain_log_buffers
    },
    {
      name  = "random_page_cost"
      value = local.db_config.parameter_group_parameters.random_page_cost
    },
    {
      name  = "seq_page_cost"
      value = local.db_config.parameter_group_parameters.seq_page_cost
    }
  ]
  
  # =============================================================================
  # MONITORING AND LOGGING
  # =============================================================================
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  # CloudWatch monitoring
  create_monitoring_role = local.db_config.monitoring_interval > 0
  monitoring_interval   = local.db_config.monitoring_interval
  monitoring_role_name  = "${local.cluster_identifier}-monitoring-role"
  
  # =============================================================================
  # ADVANCED FEATURES
  # =============================================================================
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = local.db_config.auto_minor_version_upgrade
  
  # Development-specific features
  apply_immediately = true  # Apply changes immediately in dev
  
  # =============================================================================
  # TAGGING
  # =============================================================================
  tags = local.rds_tags
}

# =============================================================================
# GENERATE ADDITIONAL RDS RESOURCES
# =============================================================================
generate "rds_development_features" {
  path      = "rds_development_features.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# DEVELOPMENT-SPECIFIC RDS RESOURCES
# =============================================================================

# DB Parameter Group for instances
resource "aws_db_parameter_group" "development" {
  family = "aurora-postgresql15"
  name   = "$${local.cluster_identifier}-instance-params"
  description = "Development Aurora PostgreSQL instance parameter group"

  # Development-optimized parameters
  parameter {
    name  = "max_connections"
    value = local.db_config.parameter_group_parameters.max_connections
  }

  parameter {
    name  = "work_mem"
    value = local.db_config.parameter_group_parameters.work_mem
  }

  parameter {
    name  = "maintenance_work_mem"
    value = local.db_config.parameter_group_parameters.maintenance_work_mem
  }

  parameter {
    name  = "effective_cache_size"
    value = local.db_config.parameter_group_parameters.effective_cache_size
  }

  # Development debugging parameters
  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  parameter {
    name  = "log_lock_waits"
    value = "1"
  }

  parameter {
    name  = "log_temp_files"
    value = "0"
  }

  parameter {
    name  = "log_checkpoints"
    value = "1"
  }

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-instance-params"
    Type = "InstanceParameterGroup"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Enhanced monitoring IAM role
resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = local.db_config.monitoring_interval > 0 ? 1 : 0
  
  name = "$${local.cluster_identifier}-enhanced-monitoring"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-enhanced-monitoring"
    Purpose = "RDSEnhancedMonitoring"
  })
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count = local.db_config.monitoring_interval > 0 ? 1 : 0
  
  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# CloudWatch Log Group for PostgreSQL logs
resource "aws_cloudwatch_log_group" "postgresql" {
  name              = "/aws/rds/cluster/$${local.cluster_identifier}/postgresql"
  retention_in_days = 30
  kms_key_id       = local.kms_key_arn

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-postgresql-logs"
    Purpose = "DatabaseLogging"
  })
}

# CloudWatch Dashboard for RDS monitoring
resource "aws_cloudwatch_dashboard" "rds_development" {
  dashboard_name = "$${local.cluster_identifier}-development"

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
            ["AWS/RDS", "CPUUtilization", "DBClusterIdentifier", local.cluster_identifier],
            [".", "DatabaseConnections", ".", "."],
            [".", "FreeableMemory", ".", "."],
            [".", "ReadLatency", ".", "."],
            [".", "WriteLatency", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "RDS Cluster Metrics"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "ReadIOPS", "DBClusterIdentifier", local.cluster_identifier],
            [".", "WriteIOPS", ".", "."],
            [".", "ReadThroughput", ".", "."],
            [".", "WriteThroughput", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = local.aws_region
          title   = "RDS I/O Metrics"
          period  = 300
        }
      }
    ]
  })
}

# CloudWatch Alarms for development monitoring
resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "$${local.cluster_identifier}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS CPU utilization"
  alarm_actions       = []  # No actions in development

  dimensions = {
    DBClusterIdentifier = local.cluster_identifier
  }

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-high-cpu-alarm"
    Purpose = "DatabaseMonitoring"
  })
}

resource "aws_cloudwatch_metric_alarm" "database_connections" {
  alarm_name          = "$${local.cluster_identifier}-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS connection count"
  alarm_actions       = []  # No actions in development

  dimensions = {
    DBClusterIdentifier = local.cluster_identifier
  }

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-high-connections-alarm"
    Purpose = "DatabaseMonitoring"
  })
}

# Development database initialization script
resource "aws_ssm_parameter" "db_init_script" {
  name  = "/$${local.env_vars.locals.name_prefix}/database/init-script"
  type  = "String"
  value = base64encode(templatefile("$${path.module}/db_init.sql", {
    environment = local.env_vars.locals.environment
    app_name   = local.env_vars.locals.app_config.app_name
  }))
  description = "Database initialization script for development"

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-init-script"
    Purpose = "DatabaseInitialization"
  })
}

# Database connection parameters
resource "aws_ssm_parameter" "db_host" {
  name  = "/$${local.env_vars.locals.name_prefix}/database/host"
  type  = "String"
  value = module.aurora.cluster_endpoint
  description = "Database cluster endpoint"

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-host-parameter"
    Purpose = "DatabaseConnection"
  })
}

resource "aws_ssm_parameter" "db_port" {
  name  = "/$${local.env_vars.locals.name_prefix}/database/port"
  type  = "String"
  value = tostring(module.aurora.cluster_port)
  description = "Database port"

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-port-parameter"
    Purpose = "DatabaseConnection"
  })
}

resource "aws_ssm_parameter" "db_name" {
  name  = "/$${local.env_vars.locals.name_prefix}/database/name"
  type  = "String"
  value = module.aurora.cluster_database_name
  description = "Database name"

  tags = merge(local.rds_tags, {
    Name = "$${local.cluster_identifier}-name-parameter"
    Purpose = "DatabaseConnection"
  })
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "cluster_endpoint" {
  description = "RDS Aurora cluster endpoint"
  value       = module.aurora.cluster_endpoint
}

output "cluster_reader_endpoint" {
  description = "RDS Aurora cluster reader endpoint"
  value       = module.aurora.cluster_reader_endpoint
}

output "cluster_port" {
  description = "RDS Aurora cluster port"
  value       = module.aurora.cluster_port
}

output "cluster_database_name" {
  description = "RDS Aurora cluster database name"
  value       = module.aurora.cluster_database_name
}

output "cluster_master_username" {
  description = "RDS Aurora cluster master username"
  value       = module.aurora.cluster_master_username
  sensitive   = true
}

output "cluster_master_user_secret" {
  description = "RDS Aurora cluster master user secret"
  value       = module.aurora.cluster_master_user_secret
  sensitive   = true
}

output "cluster_id" {
  description = "RDS Aurora cluster ID"
  value       = module.aurora.cluster_id
}

output "cluster_arn" {
  description = "RDS Aurora cluster ARN"
  value       = module.aurora.cluster_arn
}

output "enhanced_monitoring_iam_role_arn" {
  description = "The Amazon Resource Name (ARN) specifying the monitoring role"
  value       = try(aws_iam_role.rds_enhanced_monitoring[0].arn, null)
}

output "db_parameter_group_name" {
  description = "The name of the DB parameter group"
  value       = aws_db_parameter_group.development.name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for PostgreSQL logs"
  value       = aws_cloudwatch_log_group.postgresql.name
}

output "dashboard_url" {
  description = "URL to the RDS CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=$${local.aws_region}#dashboards:name=$${aws_cloudwatch_dashboard.rds_development.dashboard_name}"
}

# Development-specific outputs
output "development_features" {
  description = "Development features enabled"
  value = {
    performance_insights = local.db_config.performance_insights_enabled
    enhanced_monitoring = local.db_config.monitoring_interval > 0
    query_logging      = true
    parameter_logging  = true
    connection_logging = true
  }
}

output "connection_parameters" {
  description = "Database connection parameters stored in SSM"
  value = {
    host_parameter = aws_ssm_parameter.db_host.name
    port_parameter = aws_ssm_parameter.db_port.name
    name_parameter = aws_ssm_parameter.db_name.name
  }
}
EOF
}

# =============================================================================
# GENERATE DATABASE INITIALIZATION SCRIPT
# =============================================================================
generate "db_init_script" {
  path      = "db_init.sql"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
-- =============================================================================
-- DATABASE INITIALIZATION SCRIPT - DEVELOPMENT ENVIRONMENT
-- =============================================================================

-- Create application database if it doesn't exist
CREATE DATABASE IF NOT EXISTS katyacleaning_dev;

-- Connect to the application database
\c katyacleaning_dev;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create application schema
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS monitoring;

-- Create development user
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
      CREATE ROLE app_user LOGIN PASSWORD 'dev_password_change_me';
   END IF;
END
$$;

-- Grant permissions
GRANT USAGE ON SCHEMA app TO app_user;
GRANT USAGE ON SCHEMA audit TO app_user;
GRANT USAGE ON SCHEMA monitoring TO app_user;
GRANT CREATE ON SCHEMA app TO app_user;

-- Create sample tables for development
CREATE TABLE IF NOT EXISTS app.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app.bookings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES app.users(id),
    service_type VARCHAR(100) NOT NULL,
    booking_date DATE NOT NULL,
    booking_time TIME NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    address TEXT,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create audit table
CREATE TABLE IF NOT EXISTS audit.user_activity (
    id SERIAL PRIMARY KEY,
    user_id UUID,
    action VARCHAR(100) NOT NULL,
    table_name VARCHAR(100),
    record_id UUID,
    old_values JSONB,
    new_values JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create monitoring table
CREATE TABLE IF NOT EXISTS monitoring.health_checks (
    id SERIAL PRIMARY KEY,
    check_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL,
    response_time_ms INTEGER,
    error_message TEXT,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_email ON app.users(email);
CREATE INDEX IF NOT EXISTS idx_bookings_user_id ON app.bookings(user_id);
CREATE INDEX IF NOT EXISTS idx_bookings_date ON app.bookings(booking_date);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON app.bookings(status);
CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit.user_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit.user_activity(created_at);

-- Create triggers for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON app.users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_bookings_updated_at BEFORE UPDATE ON app.bookings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data for development
INSERT INTO app.users (email, password_hash, first_name, last_name) VALUES
    ('john.doe@example.com', crypt('password123', gen_salt('bf')), 'John', 'Doe'),
    ('jane.smith@example.com', crypt('password123', gen_salt('bf')), 'Jane', 'Smith'),
    ('test.user@example.com', crypt('password123', gen_salt('bf')), 'Test', 'User')
ON CONFLICT (email) DO NOTHING;

-- Insert sample bookings
INSERT INTO app.bookings (user_id, service_type, booking_date, booking_time, address, notes) 
SELECT 
    u.id,
    'House Cleaning',
    CURRENT_DATE + INTERVAL '1 day',
    '10:00:00',
    '123 Test Street, Test City',
    'Sample booking for development'
FROM app.users u 
WHERE u.email = 'john.doe@example.com'
ON CONFLICT DO NOTHING;

-- Create development views
CREATE OR REPLACE VIEW app.user_bookings AS
SELECT 
    u.id as user_id,
    u.email,
    u.first_name,
    u.last_name,
    b.id as booking_id,
    b.service_type,
    b.booking_date,
    b.booking_time,
    b.status,
    b.address
FROM app.users u
LEFT JOIN app.bookings b ON u.id = b.user_id;

-- Grant permissions on new objects
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO app_user;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA monitoring TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA monitoring TO app_user;

-- Create development-specific functions
CREATE OR REPLACE FUNCTION monitoring.record_health_check(
    p_check_name VARCHAR(100),
    p_status VARCHAR(20),
    p_response_time_ms INTEGER DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO monitoring.health_checks (check_name, status, response_time_ms, error_message)
    VALUES (p_check_name, p_status, p_response_time_ms, p_error_message);
END;
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON FUNCTION monitoring.record_health_check TO app_user;

-- Log initialization completion
INSERT INTO monitoring.health_checks (check_name, status, response_time_ms)
VALUES ('database_initialization', 'success', 0);

-- Development environment marker
COMMENT ON DATABASE katyacleaning_dev IS 'Development database for ${app_name} - Environment: ${environment}';
EOF
}
