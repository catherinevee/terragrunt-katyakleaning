# =============================================================================
# RDS TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates a PostgreSQL RDS cluster with high availability,
# encryption, and automated backups for the production environment.

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
    vpc_id                = "vpc-mock"
    database_subnets      = ["subnet-mock-1", "subnet-mock-2"]
    database_subnet_group = "db-subnet-group-mock"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

dependency "security_groups" {
  config_path = "../security-groups"
  
  mock_outputs = {
    database_security_group_id = "sg-mock-db"
  }
  mock_outputs_allowed_terraform_commands = ["validate", "plan"]
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/rds-aurora/aws?version=9.9.1"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # =============================================================================
  # BASIC CLUSTER CONFIGURATION
  # =============================================================================
  name           = "${local.name_prefix}-postgres-cluster"
  engine         = "aurora-postgresql"
  engine_version = local.env_vars.locals.database_config.engine_version
  
  # Instance configuration
  instance_class = local.env_vars.locals.database_config.instance_class
  instances = {
    1 = {
      instance_class      = local.env_vars.locals.database_config.instance_class
      publicly_accessible = false
    }
    2 = {
      instance_class      = local.env_vars.locals.database_config.instance_class
      publicly_accessible = false
    }
  }
  
  # =============================================================================
  # NETWORK CONFIGURATION
  # =============================================================================
  vpc_id               = dependency.vpc.outputs.vpc_id
  db_subnet_group_name = dependency.vpc.outputs.database_subnet_group
  vpc_security_group_ids = [dependency.security_groups.outputs.database_security_group_id]
  
  # =============================================================================
  # STORAGE CONFIGURATION
  # =============================================================================
  allocated_storage     = local.env_vars.locals.database_config.allocated_storage
  max_allocated_storage = local.env_vars.locals.database_config.max_allocated_storage
  storage_encrypted     = local.env_vars.locals.database_config.storage_encrypted
  kms_key_id           = "alias/rds-encryption-key"
  storage_type         = "gp3"
  
  # =============================================================================
  # DATABASE CONFIGURATION
  # =============================================================================
  database_name   = "katyacleaning"
  master_username = "dbadmin"
  port           = 5432
  
  # Password management via AWS Secrets Manager
  manage_master_user_password = true
  master_user_secret_kms_key_id = "alias/rds-encryption-key"
  
  # =============================================================================
  # BACKUP AND MAINTENANCE
  # =============================================================================
  backup_retention_period = local.env_vars.locals.database_config.backup_retention_period
  preferred_backup_window = local.env_vars.locals.database_config.backup_window
  preferred_maintenance_window = local.env_vars.locals.database_config.maintenance_window
  
  # Point-in-time recovery
  copy_tags_to_snapshot = true
  skip_final_snapshot   = false
  final_snapshot_identifier = "${local.name_prefix}-postgres-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  # =============================================================================
  # HIGH AVAILABILITY AND DISASTER RECOVERY
  # =============================================================================
  deletion_protection = local.env_vars.locals.database_config.deletion_protection
  
  # Aurora Global Database for DR (optional)
  global_cluster_identifier = local.environment == "prod" ? "${local.name_prefix}-global-cluster" : null
  
  # =============================================================================
  # PERFORMANCE AND MONITORING
  # =============================================================================
  
  # Performance Insights
  performance_insights_enabled          = true
  performance_insights_kms_key_id      = "alias/rds-encryption-key"
  performance_insights_retention_period = 7
  
  # Enhanced monitoring
  monitoring_interval = 60
  monitoring_role_arn = "arn:aws:iam::${local.aws_account_id}:role/rds-monitoring-role"
  
  # CloudWatch log exports
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  # =============================================================================
  # SECURITY CONFIGURATION
  # =============================================================================
  
  # IAM database authentication
  iam_database_authentication_enabled = true
  
  # Certificate authority
  ca_cert_identifier = "rds-ca-rsa2048-g1"
  
  # =============================================================================
  # PARAMETER GROUPS
  # =============================================================================
  
  # DB cluster parameter group
  db_cluster_parameter_group_name = "${local.name_prefix}-cluster-params"
  db_cluster_parameter_group_family = "aurora-postgresql15"
  db_cluster_parameter_group_description = "Custom cluster parameter group for ${local.name_prefix}"
  
  db_cluster_parameter_group_parameters = [
    {
      name  = "log_statement"
      value = "all"
    },
    {
      name  = "log_min_duration_statement"
      value = "1000"  # Log queries taking longer than 1 second
    },
    {
      name  = "shared_preload_libraries"
      value = "pg_stat_statements"
    },
    {
      name  = "max_connections"
      value = "200"
    },
    {
      name  = "work_mem"
      value = "16384"  # 16MB
    }
  ]
  
  # DB parameter group for instances
  db_parameter_group_name = "${local.name_prefix}-instance-params"
  db_parameter_group_family = "aurora-postgresql15"
  db_parameter_group_description = "Custom instance parameter group for ${local.name_prefix}"
  
  db_parameter_group_parameters = [
    {
      name  = "log_rotation_age"
      value = "1440"  # 24 hours
    },
    {
      name  = "log_rotation_size"
      value = "102400"  # 100MB
    }
  ]
  
  # =============================================================================
  # SCALING CONFIGURATION
  # =============================================================================
  
  # Auto scaling for Aurora Serverless v2 (if using serverless)
  serverlessv2_scaling_configuration = {
    max_capacity = 16
    min_capacity = 0.5
  }
  
  # =============================================================================
  # CROSS-REGION BACKUP
  # =============================================================================
  
  # Automated backups to another region
  backup_cross_region_enabled = local.env_vars.locals.backup_config.cross_region_backup
  backup_cross_region_kms_key_id = "alias/rds-backup-key"
  
  # =============================================================================
  # TAGS
  # =============================================================================
  tags = merge(
    local.common_tags,
    local.env_vars.locals.environment_tags,
    {
      Name           = "${local.name_prefix}-postgres-cluster"
      Component      = "Database"
      Service        = "RDS"
      Engine         = "PostgreSQL"
      EngineVersion  = local.env_vars.locals.database_config.engine_version
      Description    = "Production PostgreSQL cluster for Katya Cleaning Services"
      BackupSchedule = local.env_vars.locals.database_config.backup_window
      MaintenanceWindow = local.env_vars.locals.database_config.maintenance_window
      HighAvailability = "Multi-AZ"
      Encryption     = "Enabled"
      Monitoring     = "Enhanced"
      PerformanceInsights = "Enabled"
    }
  )
}

# =============================================================================
# GENERATE DATABASE INITIALIZATION SCRIPT
# =============================================================================
generate "db_init" {
  path      = "db_init.sql"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
-- =============================================================================
-- DATABASE INITIALIZATION SCRIPT
-- =============================================================================
-- This script sets up the initial database schema and users for the
-- Katya Cleaning Services application.

-- Create application database (if not exists)
CREATE DATABASE IF NOT EXISTS katyacleaning;

-- Connect to the application database
\c katyacleaning;

-- Create application schema
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS reporting;

-- Create application user
CREATE USER app_user WITH PASSWORD 'CHANGE_ME_IN_PRODUCTION';

-- Grant permissions
GRANT CONNECT ON DATABASE katyacleaning TO app_user;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT CREATE ON SCHEMA app TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO app_user;

-- Create read-only user for reporting
CREATE USER readonly_user WITH PASSWORD 'CHANGE_ME_IN_PRODUCTION';
GRANT CONNECT ON DATABASE katyacleaning TO readonly_user;
GRANT USAGE ON SCHEMA app TO readonly_user;
GRANT USAGE ON SCHEMA reporting TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO readonly_user;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create audit trigger function
CREATE OR REPLACE FUNCTION audit.audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO audit.audit_log (
            table_name, operation, old_values, changed_by, changed_at
        ) VALUES (
            TG_TABLE_NAME, TG_OP, row_to_json(OLD), current_user, now()
        );
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit.audit_log (
            table_name, operation, old_values, new_values, changed_by, changed_at
        ) VALUES (
            TG_TABLE_NAME, TG_OP, row_to_json(OLD), row_to_json(NEW), current_user, now()
        );
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit.audit_log (
            table_name, operation, new_values, changed_by, changed_at
        ) VALUES (
            TG_TABLE_NAME, TG_OP, row_to_json(NEW), current_user, now()
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.audit_log (
    id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    old_values JSONB,
    new_values JSONB,
    changed_by TEXT NOT NULL DEFAULT current_user,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create index on audit log for performance
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit.audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_at ON audit.audit_log(changed_at);

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT USAGE, SELECT ON SEQUENCES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO readonly_user;

COMMIT;
EOF
}
