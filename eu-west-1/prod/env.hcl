# =============================================================================
# ENVIRONMENT-LEVEL CONFIGURATION - PRODUCTION
# =============================================================================
# This file contains production environment-specific configuration that applies
# to all services within the production environment in eu-west-1.

locals {
  # Environment Configuration
  environment      = "prod"
  environment_name = "Production"
  
  # Service Configuration
  instance_types = {
    web_server    = "t3.medium"
    app_server    = "t3.large"
    database      = "db.t3.medium"
    cache         = "cache.t3.micro"
    worker        = "t3.small"
  }
  
  # Scaling Configuration
  min_capacity = {
    web_server = 2
    app_server = 2
    worker     = 1
  }
  
  max_capacity = {
    web_server = 10
    app_server = 20
    worker     = 5
  }
  
  desired_capacity = {
    web_server = 3
    app_server = 3
    worker     = 2
  }
  
  # Database Configuration
  database_config = {
    engine_version           = "15.4"
    instance_class          = "db.t3.medium"
    allocated_storage       = 100
    max_allocated_storage   = 1000
    backup_retention_period = 30
    backup_window          = "03:00-04:00"
    maintenance_window     = "sun:04:00-sun:05:00"
    deletion_protection    = true
    multi_az              = true
    storage_encrypted     = true
  }
  
  # Security Configuration
  security_config = {
    enable_waf                = true
    enable_shield_advanced    = false  # Cost consideration
    enable_guardduty         = true
    enable_config            = true
    enable_cloudtrail        = true
    enable_security_hub      = true
    ssl_policy              = "ELBSecurityPolicy-TLS-1-2-2017-01"
    force_ssl               = true
  }
  
  # Monitoring and Alerting
  monitoring_config = {
    enable_detailed_monitoring = true
    log_retention_days        = 90
    enable_xray              = true
    enable_insights          = true
    alert_email              = "alerts@katyacleaning.com"
    slack_webhook            = ""  # Add if needed
  }
  
  # Backup and DR Configuration
  backup_config = {
    backup_schedule         = "cron(0 2 * * ? *)"  # Daily at 2 AM
    backup_retention_days   = 30
    cross_region_backup     = true
    backup_destination      = "eu-west-2"
    point_in_time_recovery  = true
  }
  
  # Cost Optimization
  cost_config = {
    enable_spot_instances     = false  # Production stability
    enable_reserved_instances = true
    enable_savings_plans     = true
    enable_lifecycle_policies = true
    storage_class_transition = {
      standard_to_ia = 30
      ia_to_glacier  = 90
      glacier_to_deep_archive = 180
    }
  }
  
  # Domain and DNS Configuration
  domain_config = {
    primary_domain   = "katyacleaning.com"
    api_domain      = "api.katyacleaning.com"
    admin_domain    = "admin.katyacleaning.com"
    media_domain    = "media.katyacleaning.com"
    cdn_domain      = "cdn.katyacleaning.com"
    enable_https    = true
    certificate_arn = ""  # Will be created by ACM module
  }
  
  # Application Configuration
  app_config = {
    app_name           = "katyacleaning"
    app_version        = "1.0.0"
    container_port     = 8080
    health_check_path  = "/health"
    session_timeout    = 3600
    max_file_size      = "10MB"
    allowed_origins    = ["https://katyacleaning.com", "https://www.katyacleaning.com"]
  }
  
  # Environment-specific tags
  environment_tags = {
    Environment     = "prod"
    EnvironmentName = "Production"
    Criticality     = "High"
    SLA            = "99.9%"
    MaintenanceWindow = "Sunday 04:00-05:00 GMT"
    BackupSchedule    = "Daily 02:00 GMT"
    MonitoringLevel   = "Enhanced"
    CostOptimization  = "Reserved"
    SecurityLevel     = "High"
    ComplianceLevel   = "SOC2"
    DataClassification = "Confidential"
    DisasterRecovery   = "Multi-AZ"
  }
}
