# =============================================================================
# SECURITY CONFIGURATION FOR TERRAGRUNT-KATYAKLEANING
# =============================================================================
# This file contains comprehensive security controls, compliance settings,
# and monitoring configurations for the infrastructure.

locals {
  # Security configuration
  security_config = {
    # Encryption settings
    encryption_at_rest = {
      enabled = true
      algorithm = "AES256"
      kms_key_rotation = true
      rotation_days = 365
    }
    
    encryption_in_transit = {
      enabled = true
      minimum_tls_version = "TLSv1.2"
      ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
      force_ssl = true
    }
    
    # Access controls
    access_controls = {
      principle_of_least_privilege = true
      role_based_access_control = true
      session_timeout_minutes = 60
      max_session_duration_hours = 12
      require_mfa = true
    }
    
    # Network security
    network_security = {
      enable_vpc_flow_logs = true
      enable_network_acl = true
      enable_security_groups = true
      enable_waf = true
      enable_shield = false  # Cost consideration
      enable_guardduty = true
      enable_config = true
      enable_cloudtrail = true
      enable_security_hub = true
    }
    
    # Monitoring and alerting
    monitoring = {
      enable_cloudwatch_logs = true
      log_retention_days = 90
      enable_metric_alarms = true
      enable_dashboards = true
      enable_xray = true
      enable_insights = true
    }
    
    # Compliance settings
    compliance = {
      soc2_type_ii = true
      pci_dss_level_1 = true
      gdpr_compliant = true
      data_residency = "EU"
      audit_logging = true
      backup_encryption = true
    }
    
    # Backup and disaster recovery
    backup_dr = {
      enable_automated_backups = true
      backup_retention_days = 30
      cross_region_backup = true
      point_in_time_recovery = true
      enable_replication = true
      dr_region = "eu-west-2"
    }
    
    # Cost controls
    cost_controls = {
      enable_budget_alerts = true
      monthly_budget_limit = 1000
      alert_thresholds = [500, 750, 900]
      enable_cost_optimization = true
      enable_savings_plans = false  # For dev environment
      enable_reserved_instances = false  # For dev environment
    }
  }
  
  # Security policies
  security_policies = {
    # Password policy
    password_policy = {
      minimum_length = 12
      require_uppercase = true
      require_lowercase = true
      require_numbers = true
      require_symbols = true
      prevent_reuse = 24
      max_age_days = 90
    }
    
    # Account lockout policy
    account_lockout = {
      max_failed_attempts = 5
      lockout_duration_minutes = 30
      reset_after_hours = 24
    }
    
    # Session policy
    session_policy = {
      max_session_duration = 43200  # 12 hours in seconds
      idle_timeout_minutes = 60
      require_mfa = true
    }
  }
  
  # Compliance controls
  compliance_controls = {
    # SOC2 Type II Controls
    soc2_controls = {
      cc1_control_environment = {
        access_controls = true
        change_management = true
        risk_assessment = true
        monitoring = true
      }
      cc2_communication = {
        security_awareness = true
        incident_response = true
        vendor_management = true
      }
      cc3_risk_assessment = {
        risk_identification = true
        risk_analysis = true
        risk_response = true
      }
      cc4_monitoring_activities = {
        continuous_monitoring = true
        periodic_assessments = true
        remediation = true
      }
      cc5_control_activities = {
        access_management = true
        system_operations = true
        change_management = true
        logical_access = true
      }
      cc6_logical_access = {
        access_authorization = true
        access_removal = true
        access_review = true
      }
      cc7_system_operations = {
        capacity_planning = true
        system_monitoring = true
        backup_recovery = true
        incident_response = true
      }
      cc8_change_management = {
        change_authorization = true
        change_testing = true
        change_documentation = true
      }
      cc9_risk_mitigation = {
        risk_identification = true
        risk_assessment = true
        risk_response = true
      }
    }
    
    # PCI-DSS Level 1 Controls
    pci_dss_controls = {
      requirement_1 = {
        firewall_configuration = true
        network_segmentation = true
        traffic_monitoring = true
      }
      requirement_2 = {
        vendor_defaults = false
        secure_configuration = true
        system_hardening = true
      }
      requirement_3 = {
        data_encryption = true
        key_management = true
        encryption_standards = true
      }
      requirement_4 = {
        transmission_encryption = true
        secure_protocols = true
        wireless_encryption = true
      }
      requirement_5 = {
        antivirus_software = true
        malware_protection = true
        signature_updates = true
      }
      requirement_6 = {
        security_patches = true
        change_management = true
        secure_development = true
      }
      requirement_7 = {
        access_control = true
        role_based_access = true
        least_privilege = true
      }
      requirement_8 = {
        user_identification = true
        authentication = true
        session_management = true
      }
      requirement_9 = {
        physical_access = true
        media_handling = true
        asset_inventory = true
      }
      requirement_10 = {
        audit_logging = true
        log_monitoring = true
        log_retention = true
      }
      requirement_11 = {
        vulnerability_scanning = true
        penetration_testing = true
        intrusion_detection = true
      }
      requirement_12 = {
        security_policy = true
        risk_assessment = true
        incident_response = true
      }
    }
  }
  
  # Monitoring and alerting configuration
  monitoring_config = {
    # CloudWatch alarms
    cloudwatch_alarms = {
      cpu_utilization = {
        threshold = 80
        period = 300
        evaluation_periods = 2
        comparison_operator = "GreaterThanThreshold"
      }
      memory_utilization = {
        threshold = 85
        period = 300
        evaluation_periods = 2
        comparison_operator = "GreaterThanThreshold"
      }
      disk_utilization = {
        threshold = 90
        period = 300
        evaluation_periods = 2
        comparison_operator = "GreaterThanThreshold"
      }
      network_errors = {
        threshold = 5
        period = 300
        evaluation_periods = 1
        comparison_operator = "GreaterThanThreshold"
      }
      response_time = {
        threshold = 5.0
        period = 300
        evaluation_periods = 2
        comparison_operator = "GreaterThanThreshold"
      }
    }
    
    # Security monitoring
    security_monitoring = {
      failed_login_attempts = {
        threshold = 10
        period = 300
        evaluation_periods = 1
      }
      unauthorized_access = {
        threshold = 1
        period = 300
        evaluation_periods = 1
      }
      configuration_changes = {
        threshold = 5
        period = 3600
        evaluation_periods = 1
      }
      encryption_events = {
        threshold = 1
        period = 300
        evaluation_periods = 1
      }
    }
    
    # Compliance monitoring
    compliance_monitoring = {
      backup_failures = {
        threshold = 1
        period = 86400
        evaluation_periods = 1
      }
      patch_compliance = {
        threshold = 95
        period = 86400
        evaluation_periods = 1
        comparison_operator = "LessThanThreshold"
      }
      security_scan_failures = {
        threshold = 1
        period = 86400
        evaluation_periods = 1
      }
      audit_log_failures = {
        threshold = 1
        period = 3600
        evaluation_periods = 1
      }
    }
  }
  
  # Incident response configuration
  incident_response = {
    # Severity levels
    severity_levels = {
      critical = {
        response_time_minutes = 15
        escalation_time_minutes = 30
        notification_channels = ["pagerduty", "slack", "email"]
      }
      high = {
        response_time_minutes = 60
        escalation_time_minutes = 120
        notification_channels = ["slack", "email"]
      }
      medium = {
        response_time_minutes = 240
        escalation_time_minutes = 480
        notification_channels = ["slack", "email"]
      }
      low = {
        response_time_minutes = 1440
        escalation_time_minutes = 2880
        notification_channels = ["email"]
      }
    }
    
    # Notification channels
    notification_channels = {
      email = {
        recipients = ["security@katyacleaning.com", "infrastructure@katyacleaning.com"]
        subject_prefix = "[SECURITY ALERT]"
      }
      slack = {
        webhook_url = "https://hooks.slack.com/services/security-channel"
        channel = "#security-alerts"
        username = "Security Bot"
      }
      pagerduty = {
        service_key = "pagerduty-service-key"
        escalation_policy = "security-team"
      }
    }
  }
  
  # Security tools configuration
  security_tools = {
    # Vulnerability scanning
    vulnerability_scanning = {
      enable_automated_scanning = true
      scan_frequency = "weekly"
      scan_schedule = "cron(0 2 * * SUN)"  # Sunday 2 AM
      tools = ["tfsec", "checkov", "trivy", "snyk"]
    }
    
    # Penetration testing
    penetration_testing = {
      enable_automated_testing = true
      test_frequency = "quarterly"
      external_testing = true
      internal_testing = true
    }
    
    # Security monitoring tools
    security_monitoring = {
      enable_guardduty = true
      enable_security_hub = true
      enable_config = true
      enable_cloudtrail = true
      enable_vpc_flow_logs = true
      enable_network_firewall = false  # Cost consideration
    }
  }
}

# =============================================================================
# SECURITY VALIDATION FUNCTIONS
# =============================================================================

# Function to validate security configuration
locals {
  validate_security_config = {
    encryption_valid = local.security_config.encryption_at_rest.enabled && local.security_config.encryption_in_transit.enabled
    access_controls_valid = local.security_config.access_controls.principle_of_least_privilege && local.security_config.access_controls.require_mfa
    monitoring_valid = local.security_config.monitoring.enable_cloudwatch_logs && local.security_config.monitoring.enable_metric_alarms
    compliance_valid = local.security_config.compliance.soc2_type_ii && local.security_config.compliance.audit_logging
    backup_valid = local.security_config.backup_dr.enable_automated_backups && local.security_config.backup_dr.backup_encryption
  }
  
  security_score = sum([
    local.validate_security_config.encryption_valid ? 20 : 0,
    local.validate_security_config.access_controls_valid ? 20 : 0,
    local.validate_security_config.monitoring_valid ? 20 : 0,
    local.validate_security_config.compliance_valid ? 20 : 0,
    local.validate_security_config.backup_valid ? 20 : 0
  ])
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "security_configuration" {
  description = "Security configuration summary"
  value = {
    encryption_enabled = local.security_config.encryption_at_rest.enabled
    access_controls_enabled = local.security_config.access_controls.principle_of_least_privilege
    monitoring_enabled = local.security_config.monitoring.enable_cloudwatch_logs
    compliance_enabled = local.security_config.compliance.soc2_type_ii
    backup_enabled = local.security_config.backup_dr.enable_automated_backups
    security_score = local.security_score
  }
}

output "compliance_status" {
  description = "Compliance status for SOC2 and PCI-DSS"
  value = {
    soc2_type_ii = local.security_config.compliance.soc2_type_ii
    pci_dss_level_1 = local.security_config.compliance.pci_dss_level_1
    gdpr_compliant = local.security_config.compliance.gdpr_compliant
    data_residency = local.security_config.compliance.data_residency
  }
}

output "monitoring_configuration" {
  description = "Monitoring and alerting configuration"
  value = {
    cloudwatch_alarms = local.monitoring_config.cloudwatch_alarms
    security_monitoring = local.monitoring_config.security_monitoring
    compliance_monitoring = local.monitoring_config.compliance_monitoring
  }
}

output "incident_response_configuration" {
  description = "Incident response configuration"
  value = {
    severity_levels = local.incident_response.severity_levels
    notification_channels = local.incident_response.notification_channels
  }
} 