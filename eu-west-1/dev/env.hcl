# =============================================================================
# ENVIRONMENT-LEVEL CONFIGURATION - DEVELOPMENT
# =============================================================================
# This file contains development environment-specific configuration that applies
# to all services within the development environment in eu-west-1.

locals {
  # Environment Configuration
  environment      = "dev"
  environment_name = "Development"
  
  # Development-specific naming convention
  name_prefix = "katyacleaning-dev"
  
  # Service Configuration - Optimized for development
  instance_types = {
    web_server    = "t3.micro"    # Smaller for dev
    app_server    = "t3.small"    # Smaller for dev
    database      = "db.t3.micro" # Smaller for dev
    cache         = "cache.t3.micro"
    worker        = "t3.micro"
    bastion       = "t3.nano"     # Minimal for dev
  }
  
  # Scaling Configuration - Reduced for development
  min_capacity = {
    web_server = 1
    app_server = 1
    worker     = 1
  }
  
  max_capacity = {
    web_server = 3
    app_server = 5
    worker     = 2
  }
  
  desired_capacity = {
    web_server = 1
    app_server = 1
    worker     = 1
  }
  
  # Database Configuration - Development optimized
  database_config = {
    engine_version           = "15.4"
    instance_class          = "db.t3.micro"
    allocated_storage       = 20
    max_allocated_storage   = 100
    backup_retention_period = 7   # Shorter retention for dev
    backup_window          = "03:00-04:00"
    maintenance_window     = "sun:04:00-sun:05:00"
    deletion_protection    = false  # Allow deletion in dev
    multi_az              = false   # Single AZ for cost savings
    storage_encrypted     = true
    skip_final_snapshot   = true    # Skip final snapshot in dev
    
    # Development-specific parameters
    performance_insights_enabled = false  # Disable for cost savings
    monitoring_interval         = 0       # Disable enhanced monitoring
    auto_minor_version_upgrade  = true
    
    # Parameter group settings for development
    parameter_group_parameters = {
      shared_preload_libraries = "pg_stat_statements,auto_explain"
      log_statement           = "all"
      log_min_duration_statement = "100"  # Log queries > 100ms
      auto_explain_log_min_duration = "1000"
      auto_explain_log_analyze = "on"
      auto_explain_log_buffers = "on"
      max_connections         = "100"
      work_mem               = "8192"    # 8MB
      maintenance_work_mem   = "65536"   # 64MB
      effective_cache_size   = "256MB"
      random_page_cost       = "1.1"
      seq_page_cost         = "1.0"
    }
  }
  
  # ElastiCache Configuration - Development optimized
  cache_config = {
    node_type                = "cache.t3.micro"
    num_cache_clusters      = 1  # Single node for dev
    engine_version          = "7.0"
    port                    = 6379
    parameter_group_family  = "redis7"
    
    # Development-specific settings
    multi_az_enabled           = false
    automatic_failover_enabled = false
    at_rest_encryption_enabled = true
    transit_encryption_enabled = true
    auth_token_enabled         = false  # Simplified for dev
    
    # Backup settings
    snapshot_retention_limit = 1
    snapshot_window         = "03:00-05:00"
    maintenance_window      = "sun:05:00-sun:07:00"
    
    # Parameter group settings
    parameters = {
      maxmemory_policy = "allkeys-lru"
      timeout         = "300"
      tcp_keepalive   = "300"
      maxclients      = "500"
      save            = "900 1 300 10 60 10000"  # More frequent saves for dev
    }
  }
  
  # Security Configuration - Relaxed for development
  security_config = {
    enable_waf                = true
    enable_shield_advanced    = false
    enable_guardduty         = false  # Disabled for cost savings
    enable_config            = false  # Disabled for cost savings
    enable_cloudtrail        = true
    enable_security_hub      = false  # Disabled for cost savings
    ssl_policy              = "ELBSecurityPolicy-TLS-1-2-2017-01"
    force_ssl               = true
    
    # Development-specific security settings
    allowed_cidr_blocks = [
      "10.0.0.0/8",     # Private networks
      "172.16.0.0/12",  # Private networks
      "192.168.0.0/16", # Private networks
      "203.0.113.0/24"  # Office IP (example)
    ]
    
    # SSH access configuration
    ssh_key_name = "katyacleaning-dev-keypair"
    enable_ssh_access = true
    ssh_allowed_cidrs = ["203.0.113.0/24"]  # Office IP range
  }
  
  # Monitoring and Alerting - Simplified for development
  monitoring_config = {
    enable_detailed_monitoring = false  # Basic monitoring for dev
    log_retention_days        = 30      # Shorter retention
    enable_xray              = true
    enable_insights          = false    # Disabled for cost savings
    alert_email              = "dev-alerts@katyacleaning.com"
    slack_webhook            = "https://hooks.slack.com/services/dev-channel"
    
    # Development-specific monitoring
    enable_debug_logging     = true
    log_level               = "DEBUG"
    enable_performance_logs = true
    
    # Alarm thresholds - More lenient for dev
    cpu_alarm_threshold     = 90
    memory_alarm_threshold  = 90
    disk_alarm_threshold    = 95
    response_time_threshold = 5.0
    error_rate_threshold    = 20
  }
  
  # Backup and DR Configuration - Simplified for development
  backup_config = {
    backup_schedule         = "cron(0 6 * * ? *)"  # Daily at 6 AM
    backup_retention_days   = 7                    # Shorter retention
    cross_region_backup     = false                # Disabled for cost savings
    backup_destination      = "eu-west-2"
    point_in_time_recovery  = false                # Disabled for cost savings
    
    # Development-specific backup settings
    enable_automated_backups = true
    backup_window           = "06:00-07:00"
    maintenance_window      = "sun:07:00-sun:08:00"
  }
  
  # Cost Optimization - Aggressive for development
  cost_config = {
    enable_spot_instances     = true   # Use spot instances for cost savings
    enable_reserved_instances = false  # No reserved instances for dev
    enable_savings_plans     = false   # No savings plans for dev
    enable_lifecycle_policies = true
    
    # S3 lifecycle transitions - Faster for dev
    storage_class_transition = {
      standard_to_ia = 7      # Faster transition
      ia_to_glacier  = 30     # Faster transition
      glacier_to_deep_archive = 90
    }
    
    # Development-specific cost optimizations
    enable_scheduled_scaling = true
    scale_down_schedule     = "cron(0 19 * * MON-FRI)"  # Scale down at 7 PM weekdays
    scale_up_schedule       = "cron(0 8 * * MON-FRI)"   # Scale up at 8 AM weekdays
    weekend_scale_down      = true                       # Scale down on weekends
  }
  
  # Domain and DNS Configuration - Development domains
  domain_config = {
    primary_domain   = "dev.katyacleaning.com"
    api_domain      = "api-dev.katyacleaning.com"
    admin_domain    = "admin-dev.katyacleaning.com"
    media_domain    = "media-dev.katyacleaning.com"
    cdn_domain      = "cdn-dev.katyacleaning.com"
    enable_https    = true
    certificate_arn = ""  # Will be created by ACM module
    
    # Development-specific DNS settings
    ttl_short       = 60   # Short TTL for dev
    ttl_medium      = 300  # Medium TTL for dev
    ttl_long        = 900  # Long TTL for dev
    enable_dnssec   = false # Disabled for simplicity
  }
  
  # Application Configuration - Development settings
  app_config = {
    app_name           = "katyacleaning-dev"
    app_version        = "dev-latest"
    container_port     = 8080
    health_check_path  = "/health"
    session_timeout    = 1800  # Shorter timeout for dev
    max_file_size      = "50MB" # Larger for testing
    allowed_origins    = [
      "https://dev.katyacleaning.com",
      "https://localhost:3000",
      "https://127.0.0.1:3000",
      "http://localhost:3000",   # Allow HTTP for local dev
      "http://127.0.0.1:3000"
    ]
    
    # Development-specific app settings
    debug_mode          = true
    enable_hot_reload   = true
    enable_profiling    = true
    log_sql_queries     = true
    enable_test_routes  = true
    mock_external_apis  = true
    
    # Feature flags for development
    feature_flags = {
      new_ui_components    = true
      experimental_api     = true
      advanced_analytics   = true
      beta_features       = true
    }
  }
  
  # Network Configuration - Development specific
  network_config = {
    # VPC CIDR - Different from production
    vpc_cidr = "10.1.0.0/16"
    
    # Subnet CIDRs
    public_subnet_cidrs = [
      "10.1.1.0/24",   # eu-west-1a
      "10.1.2.0/24",   # eu-west-1b
      "10.1.3.0/24"    # eu-west-1c
    ]
    
    private_subnet_cidrs = [
      "10.1.11.0/24",  # eu-west-1a
      "10.1.12.0/24",  # eu-west-1b
      "10.1.13.0/24"   # eu-west-1c
    ]
    
    database_subnet_cidrs = [
      "10.1.21.0/24",  # eu-west-1a
      "10.1.22.0/24",  # eu-west-1b
      "10.1.23.0/24"   # eu-west-1c
    ]
    
    intra_subnet_cidrs = [
      "10.1.31.0/24",  # eu-west-1a
      "10.1.32.0/24",  # eu-west-1b
      "10.1.33.0/24"   # eu-west-1c
    ]
    
    # Development-specific network settings
    enable_nat_gateway     = true
    single_nat_gateway     = true   # Single NAT for cost savings
    one_nat_gateway_per_az = false  # Cost optimization
    enable_vpn_gateway     = false  # Not needed for dev
    enable_dns_hostnames   = true
    enable_dns_support     = true
    
    # VPC Flow Logs
    enable_flow_log                      = true
    flow_log_destination_type           = "cloud-watch-logs"
    flow_log_max_aggregation_interval   = 600  # 10 minutes
  }
  
  # Testing Configuration - Development specific
  testing_config = {
    enable_load_testing     = true
    enable_chaos_engineering = true
    enable_integration_tests = true
    enable_e2e_tests        = true
    
    # Test data configuration
    enable_test_data_seeding = true
    test_data_refresh_schedule = "cron(0 2 * * SUN)"  # Weekly refresh
    
    # Performance testing
    load_test_schedule = "cron(0 1 * * SAT)"  # Weekly load tests
    max_test_users     = 100
    test_duration_minutes = 30
  }
  
  # Development Tools Configuration
  dev_tools_config = {
    enable_swagger_ui       = true
    enable_graphql_playground = true
    enable_debug_toolbar    = true
    enable_profiler        = true
    enable_query_analyzer  = true
    
    # Code quality tools
    enable_code_coverage   = true
    enable_static_analysis = true
    enable_security_scan   = true
    
    # Development databases
    enable_test_database   = true
    enable_seed_data      = true
    reset_db_on_deploy    = true
  }
  
  # Environment-specific tags
  environment_tags = {
    Environment     = "dev"
    EnvironmentName = "Development"
    Criticality     = "Low"
    SLA            = "95%"
    MaintenanceWindow = "Sunday 07:00-08:00 GMT"
    BackupSchedule    = "Daily 06:00 GMT"
    MonitoringLevel   = "Basic"
    CostOptimization  = "Aggressive"
    SecurityLevel     = "Standard"
    ComplianceLevel   = "Basic"
    DataClassification = "Internal"
    DisasterRecovery   = "Single-AZ"
    AutoShutdown      = "Enabled"
    Owner             = "Development Team"
    Purpose           = "Development and Testing"
    
    # Development-specific tags
    AutoStart         = "08:00-MON-FRI"
    AutoStop          = "19:00-MON-FRI"
    WeekendShutdown   = "true"
    TestEnvironment   = "true"
    ExperimentalFeatures = "enabled"
  }
}
