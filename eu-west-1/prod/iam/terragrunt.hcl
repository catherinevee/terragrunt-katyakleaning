# =============================================================================
# IAM TERRAGRUNT CONFIGURATION
# =============================================================================
# This module creates IAM roles, policies, and instance profiles for the
# production environment following the principle of least privilege.

# Include root configuration
include "root" {
  path = find_in_parent_folders("root.hcl")
}

# Include environment configuration
include "env" {
  path = find_in_parent_folders("env.hcl")
}

# =============================================================================
# TERRAFORM MODULE CONFIGURATION
# =============================================================================
terraform {
  source = "tfr:///terraform-aws-modules/iam/aws?version=5.39.1"
}

# =============================================================================
# MODULE INPUTS
# =============================================================================
inputs = {
  # We'll use generate blocks to create multiple IAM resources
  create_role = false  # We'll create individual roles via generate
}

# =============================================================================
# GENERATE IAM ROLES AND POLICIES
# =============================================================================
generate "iam_resources" {
  path      = "iam_resources.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
# =============================================================================
# EC2 INSTANCE ROLE
# =============================================================================
module "ec2_instance_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.39.1"

  role_name = "$${local.name_prefix}-ec2-instance-role"
  
  role_policy_arns = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    CloudWatchAgentServerPolicy  = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  }
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-ec2-instance-role"
    Component = "IAM"
    Service   = "Role"
    Purpose   = "EC2 Instance"
  })
}

# Custom policy for EC2 instances
resource "aws_iam_policy" "ec2_custom_policy" {
  name        = "$${local.name_prefix}-ec2-custom-policy"
  description = "Custom policy for EC2 instances"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::$${local.name_prefix}-app-assets/*",
          "arn:aws:s3:::$${local.name_prefix}-backups/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:$${local.aws_region}:$${local.aws_account_id}:secret:$${local.name_prefix}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:key/*"
        ]
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.$${local.aws_region}.amazonaws.com",
              "secretsmanager.$${local.aws_region}.amazonaws.com"
            ]
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:$${local.aws_region}:$${local.aws_account_id}:*"
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-ec2-custom-policy"
    Component = "IAM"
    Service   = "Policy"
    Purpose   = "EC2 Custom"
  })
}

# Attach custom policy to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_custom_policy_attachment" {
  role       = module.ec2_instance_role.iam_role_name
  policy_arn = aws_iam_policy.ec2_custom_policy.arn
}

# Instance profile for EC2
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "$${local.name_prefix}-ec2-instance-profile"
  role = module.ec2_instance_role.iam_role_name
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-ec2-instance-profile"
    Component = "IAM"
    Service   = "InstanceProfile"
    Purpose   = "EC2"
  })
}

# =============================================================================
# RDS MONITORING ROLE
# =============================================================================
resource "aws_iam_role" "rds_monitoring_role" {
  name = "$${local.name_prefix}-rds-monitoring-role"
  
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
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-rds-monitoring-role"
    Component = "IAM"
    Service   = "Role"
    Purpose   = "RDS Monitoring"
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring_policy" {
  role       = aws_iam_role.rds_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# =============================================================================
# S3 REPLICATION ROLE
# =============================================================================
resource "aws_iam_role" "s3_replication_role" {
  name = "$${local.name_prefix}-s3-replication-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-s3-replication-role"
    Component = "IAM"
    Service   = "Role"
    Purpose   = "S3 Replication"
  })
}

resource "aws_iam_policy" "s3_replication_policy" {
  name        = "$${local.name_prefix}-s3-replication-policy"
  description = "Policy for S3 cross-region replication"
  
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
          "arn:aws:s3:::$${local.name_prefix}-backups/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::$${local.name_prefix}-backups"
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
          "arn:aws:s3:::$${local.name_prefix}-backups-dr/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = [
          "arn:aws:kms:$${local.aws_region}:$${local.aws_account_id}:key/*"
        ]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.$${local.aws_region}.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey"
        ]
        Resource = [
          "arn:aws:kms:eu-west-2:$${local.aws_account_id}:key/*"
        ]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.eu-west-2.amazonaws.com"
          }
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-s3-replication-policy"
    Component = "IAM"
    Service   = "Policy"
    Purpose   = "S3 Replication"
  })
}

resource "aws_iam_role_policy_attachment" "s3_replication_policy_attachment" {
  role       = aws_iam_role.s3_replication_role.name
  policy_arn = aws_iam_policy.s3_replication_policy.arn
}

# =============================================================================
# LAMBDA EXECUTION ROLE
# =============================================================================
resource "aws_iam_role" "lambda_execution_role" {
  name = "$${local.name_prefix}-lambda-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-lambda-execution-role"
    Component = "IAM"
    Service   = "Role"
    Purpose   = "Lambda Execution"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "lambda_custom_policy" {
  name        = "$${local.name_prefix}-lambda-custom-policy"
  description = "Custom policy for Lambda functions"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::$${local.name_prefix}-app-assets/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:$${local.aws_region}:$${local.aws_account_id}:secret:$${local.name_prefix}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          "arn:aws:sns:$${local.aws_region}:$${local.aws_account_id}:$${local.name_prefix}-*"
        ]
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-lambda-custom-policy"
    Component = "IAM"
    Service   = "Policy"
    Purpose   = "Lambda Custom"
  })
}

resource "aws_iam_role_policy_attachment" "lambda_custom_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_custom_policy.arn
}

# =============================================================================
# AUTO SCALING SERVICE ROLE
# =============================================================================
resource "aws_iam_service_linked_role" "autoscaling" {
  aws_service_name = "autoscaling.amazonaws.com"
  description      = "Service-linked role for Auto Scaling"
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-autoscaling-service-role"
    Component = "IAM"
    Service   = "ServiceLinkedRole"
    Purpose   = "Auto Scaling"
  })
}

# =============================================================================
# CLOUDWATCH EVENTS ROLE
# =============================================================================
resource "aws_iam_role" "cloudwatch_events_role" {
  name = "$${local.name_prefix}-cloudwatch-events-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-cloudwatch-events-role"
    Component = "IAM"
    Service   = "Role"
    Purpose   = "CloudWatch Events"
  })
}

resource "aws_iam_policy" "cloudwatch_events_policy" {
  name        = "$${local.name_prefix}-cloudwatch-events-policy"
  description = "Policy for CloudWatch Events"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          "arn:aws:lambda:$${local.aws_region}:$${local.aws_account_id}:function:$${local.name_prefix}-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          "arn:aws:sns:$${local.aws_region}:$${local.aws_account_id}:$${local.name_prefix}-*"
        ]
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name      = "$${local.name_prefix}-cloudwatch-events-policy"
    Component = "IAM"
    Service   = "Policy"
    Purpose   = "CloudWatch Events"
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_events_policy_attachment" {
  role       = aws_iam_role.cloudwatch_events_role.name
  policy_arn = aws_iam_policy.cloudwatch_events_policy.arn
}

# =============================================================================
# OUTPUTS
# =============================================================================
output "ec2_instance_role_arn" {
  description = "ARN of the EC2 instance role"
  value       = module.ec2_instance_role.iam_role_arn
}

output "ec2_instance_profile_name" {
  description = "Name of the EC2 instance profile"
  value       = aws_iam_instance_profile.ec2_instance_profile.name
}

output "rds_monitoring_role_arn" {
  description = "ARN of the RDS monitoring role"
  value       = aws_iam_role.rds_monitoring_role.arn
}

output "s3_replication_role_arn" {
  description = "ARN of the S3 replication role"
  value       = aws_iam_role.s3_replication_role.arn
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda_execution_role.arn
}
EOF
}
