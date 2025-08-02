# =============================================================================
# IAM TERRAGRUNT CONFIGURATION - DEVELOPMENT ENVIRONMENT
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
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/iam/aws?version=5.37.1"
}

# =============================================================================
# LOCAL VARIABLES
# =============================================================================
locals {
  env_vars    = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  region_vars = read_terragrunt_config(find_in_parent_folders("region.hcl"))
  
  iam_tags = merge(
    local.common_tags,
    local.region_vars.locals.region_tags,
    local.env_vars.locals.environment_tags,
    {
      Component      = "Security"
      Service        = "IAM"
      DevelopmentIAM = "true"
    }
  )
}

# =============================================================================
# MODULE INPUTS - PRIMARY IAM ROLE
# =============================================================================
inputs = {
  # We'll create individual IAM resources using generate blocks
  create_role = false
}

# =============================================================================
# GENERATE COMPREHENSIVE IAM RESOURCES
# =============================================================================
generate "iam_development_resources" {
  path      = "iam_development_resources.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# EC2 INSTANCE ROLE AND PROFILE
# =============================================================================
module "ec2_instance_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.37.1"

  role_name = "$${local.env_vars.locals.name_prefix}-ec2-instance-role"
  role_description = "IAM role for EC2 instances in development environment"

  oidc_providers = {}

  role_policy_arns = {
    ssm_managed_instance = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    cloudwatch_agent     = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    s3_read_only        = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  }

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-instance-role"
    Purpose = "EC2InstanceAccess"
  })
}

# Custom policy for EC2 instances
resource "aws_iam_policy" "ec2_custom_policy" {
  name        = "$${local.env_vars.locals.name_prefix}-ec2-custom-policy"
  description = "Custom policy for EC2 instances in development"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath",
          "ssm:PutParameter"
        ]
        Resource = "arn:aws:ssm:$${local.aws_region}:$${local.aws_account_id}:parameter/$${local.env_vars.locals.name_prefix}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:$${local.aws_region}:$${local.aws_account_id}:secret:$${local.env_vars.locals.name_prefix}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-app-assets/*",
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-dev-testing/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
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
      }
    ]
  })

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-custom-policy"
  })
}

resource "aws_iam_role_policy_attachment" "ec2_custom_policy_attachment" {
  role       = module.ec2_instance_role.iam_role_name
  policy_arn = aws_iam_policy.ec2_custom_policy.arn
}

# EC2 Instance Profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "$${local.env_vars.locals.name_prefix}-ec2-instance-profile"
  role = module.ec2_instance_role.iam_role_name

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-ec2-instance-profile"
  })
}

# =============================================================================
# RDS ENHANCED MONITORING ROLE
# =============================================================================
module "rds_monitoring_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.37.1"

  trusted_role_services = ["monitoring.rds.amazonaws.com"]

  create_role = true
  role_name   = "$${local.env_vars.locals.name_prefix}-rds-monitoring-role"
  role_description = "IAM role for RDS enhanced monitoring in development"

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  ]

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-rds-monitoring-role"
    Purpose = "RDSMonitoring"
  })
}

# =============================================================================
# LAMBDA EXECUTION ROLE
# =============================================================================
module "lambda_execution_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.37.1"

  trusted_role_services = ["lambda.amazonaws.com"]

  create_role = true
  role_name   = "$${local.env_vars.locals.name_prefix}-lambda-execution-role"
  role_description = "IAM role for Lambda functions in development"

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
  ]

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-lambda-execution-role"
    Purpose = "LambdaExecution"
  })
}

# Custom Lambda policy
resource "aws_iam_policy" "lambda_custom_policy" {
  name        = "$${local.env_vars.locals.name_prefix}-lambda-custom-policy"
  description = "Custom policy for Lambda functions in development"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-app-assets/*",
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-backups/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = "arn:aws:sns:$${local.aws_region}:$${local.aws_account_id}:$${local.env_vars.locals.name_prefix}-*"
      }
    ]
  })

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-lambda-custom-policy"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_custom_policy_attachment" {
  role       = module.lambda_execution_role.iam_role_name
  policy_arn = aws_iam_policy.lambda_custom_policy.arn
}

# =============================================================================
# S3 CROSS-REGION REPLICATION ROLE
# =============================================================================
module "s3_replication_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.37.1"

  trusted_role_services = ["s3.amazonaws.com"]

  create_role = true
  role_name   = "$${local.env_vars.locals.name_prefix}-s3-replication-role"
  role_description = "IAM role for S3 cross-region replication in development"

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-s3-replication-role"
    Purpose = "S3Replication"
  })
}

# S3 replication policy
resource "aws_iam_policy" "s3_replication_policy" {
  name        = "$${local.env_vars.locals.name_prefix}-s3-replication-policy"
  description = "Policy for S3 cross-region replication in development"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = [
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-app-assets/*",
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-backups/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-app-assets",
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-backups"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = [
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-app-assets-replica/*",
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-backups-replica/*"
        ]
      }
    ]
  })

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-s3-replication-policy"
  })
}

resource "aws_iam_role_policy_attachment" "s3_replication_policy_attachment" {
  role       = module.s3_replication_role.iam_role_name
  policy_arn = aws_iam_policy.s3_replication_policy.arn
}

# =============================================================================
# AUTO SCALING SERVICE ROLE
# =============================================================================
module "autoscaling_service_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.37.1"

  trusted_role_services = ["autoscaling.amazonaws.com"]

  create_role = true
  role_name   = "$${local.env_vars.locals.name_prefix}-autoscaling-service-role"
  role_description = "IAM role for Auto Scaling service in development"

  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AutoScalingNotificationAccessRole"
  ]

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-autoscaling-service-role"
    Purpose = "AutoScalingService"
  })
}

# =============================================================================
# CLOUDWATCH EVENTS ROLE
# =============================================================================
module "cloudwatch_events_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version = "5.37.1"

  trusted_role_services = ["events.amazonaws.com"]

  create_role = true
  role_name   = "$${local.env_vars.locals.name_prefix}-cloudwatch-events-role"
  role_description = "IAM role for CloudWatch Events in development"

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-cloudwatch-events-role"
    Purpose = "CloudWatchEvents"
  })
}

# CloudWatch Events policy
resource "aws_iam_policy" "cloudwatch_events_policy" {
  name        = "$${local.env_vars.locals.name_prefix}-cloudwatch-events-policy"
  description = "Policy for CloudWatch Events in development"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:$${local.aws_region}:$${local.aws_account_id}:function:$${local.env_vars.locals.name_prefix}-*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = "arn:aws:sns:$${local.aws_region}:$${local.aws_account_id}:$${local.env_vars.locals.name_prefix}-*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:SetDesiredCapacity",
          "autoscaling:UpdateAutoScalingGroup"
        ]
        Resource = "arn:aws:autoscaling:$${local.aws_region}:$${local.aws_account_id}:autoScalingGroup:*:autoScalingGroupName/$${local.env_vars.locals.name_prefix}-*"
      }
    ]
  })

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-cloudwatch-events-policy"
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_events_policy_attachment" {
  role       = module.cloudwatch_events_role.iam_role_name
  policy_arn = aws_iam_policy.cloudwatch_events_policy.arn
}

# =============================================================================
# DEVELOPMENT-SPECIFIC IAM USERS AND GROUPS
# =============================================================================

# Development team group
resource "aws_iam_group" "developers" {
  name = "$${local.env_vars.locals.name_prefix}-developers"
  path = "/development/"
}

# Development team policy
resource "aws_iam_policy" "developers_policy" {
  name        = "$${local.env_vars.locals.name_prefix}-developers-policy"
  description = "Policy for development team access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Environment" = "dev"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "rds:Describe*",
          "rds:ListTagsForResource"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-dev-testing",
          "arn:aws:s3:::$${local.env_vars.locals.name_prefix}-dev-testing/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = "arn:aws:logs:$${local.aws_region}:$${local.aws_account_id}:log-group:/aws/ec2/$${local.env_vars.locals.name_prefix}*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "cloudwatch:GetDashboard",
          "cloudwatch:ListDashboards"
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
      }
    ]
  })

  tags = merge(local.iam_tags, {
    Name = "$${local.env_vars.locals.name_prefix}-developers-policy"
  })
}

resource "aws_iam_group_policy_attachment" "developers_policy_attachment" {
  group      = aws_iam_group.developers.name
  policy_arn = aws_iam_policy.developers_policy.arn
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "ec2_instance_role_arn" {
  description = "ARN of the EC2 instance role"
  value       = module.ec2_instance_role.iam_role_arn
}

output "ec2_instance_role_name" {
  description = "Name of the EC2 instance role"
  value       = module.ec2_instance_role.iam_role_name
}

output "ec2_instance_profile_arn" {
  description = "ARN of the EC2 instance profile"
  value       = aws_iam_instance_profile.ec2_instance_profile.arn
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile"
  value       = aws_iam_instance_profile.ec2_instance_profile.name
}

output "rds_monitoring_role_arn" {
  description = "ARN of the RDS monitoring role"
  value       = module.rds_monitoring_role.iam_role_arn
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = module.lambda_execution_role.iam_role_arn
}

output "s3_replication_role_arn" {
  description = "ARN of the S3 replication role"
  value       = module.s3_replication_role.iam_role_arn
}

output "autoscaling_service_role_arn" {
  description = "ARN of the Auto Scaling service role"
  value       = module.autoscaling_service_role.iam_role_arn
}

output "cloudwatch_events_role_arn" {
  description = "ARN of the CloudWatch Events role"
  value       = module.cloudwatch_events_role.iam_role_arn
}

output "developers_group_name" {
  description = "Name of the developers IAM group"
  value       = aws_iam_group.developers.name
}

output "developers_group_arn" {
  description = "ARN of the developers IAM group"
  value       = aws_iam_group.developers.arn
}

# Development-specific outputs
output "iam_roles_summary" {
  description = "Summary of all IAM roles created"
  value = {
    ec2_instance        = module.ec2_instance_role.iam_role_name
    rds_monitoring      = module.rds_monitoring_role.iam_role_name
    lambda_execution    = module.lambda_execution_role.iam_role_name
    s3_replication      = module.s3_replication_role.iam_role_name
    autoscaling_service = module.autoscaling_service_role.iam_role_name
    cloudwatch_events   = module.cloudwatch_events_role.iam_role_name
  }
}

output "development_access_features" {
  description = "Development access features enabled"
  value = {
    developers_group_created = true
    ec2_instance_control    = true
    s3_dev_bucket_access   = true
    logs_read_access       = true
    monitoring_access      = true
    parameter_store_access = true
  }
}
EOF
}
