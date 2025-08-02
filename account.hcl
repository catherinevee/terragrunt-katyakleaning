# =============================================================================
# ACCOUNT-LEVEL CONFIGURATION
# =============================================================================
# This file contains account-specific configuration that applies to all
# regions and environments within this AWS account.

locals {
  # AWS Account Configuration
  aws_account_id   = "123456789012"  # Replace with actual account ID
  aws_account_name = "katyacleaning-production"
  aws_account_role = "arn:aws:iam::123456789012:role/TerragruntExecutionRole"
  
  # Organization and billing
  organization_unit = "Production"
  billing_contact   = "billing@katyacleaning.com"
  technical_contact = "infrastructure@katyacleaning.com"
  
  # Security and compliance
  security_contact     = "security@katyacleaning.com"
  compliance_framework = ["SOC2", "PCI-DSS"]
  data_classification  = "Confidential"
  
  # Backup and disaster recovery
  backup_retention_days = 30
  dr_region            = "eu-west-2"
  
  # Cost management
  cost_center     = "Operations"
  budget_limit    = 1000  # Monthly budget in USD
  cost_alerts     = ["500", "750", "900"]  # Alert thresholds
  
  # Account-wide tags
  account_tags = {
    AccountId        = "123456789012"
    AccountName      = "katyacleaning-production"
    Organization     = "Katya Cleaning Services"
    BusinessUnit     = "Operations"
    CostCenter       = "Operations"
    Owner            = "Infrastructure Team"
    TechnicalContact = "infrastructure@katyacleaning.com"
    SecurityContact  = "security@katyacleaning.com"
    BillingContact   = "billing@katyacleaning.com"
    Compliance       = "SOC2,PCI-DSS"
    DataClass        = "Confidential"
    BackupPolicy     = "Standard"
    DRRegion         = "eu-west-2"
  }
}
