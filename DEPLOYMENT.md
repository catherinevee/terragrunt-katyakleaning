# Katya Cleaning Services - AWS Infrastructure Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the complete AWS infrastructure for Katya Cleaning Services using Terragrunt. The infrastructure includes VPC, security groups, DNS, EC2, RDS, ElastiCache, ALB, Auto Scaling, S3, CloudFront, IAM, KMS, CloudWatch, and WAF.

## Prerequisites

### Required Tools
- **Terraform**: Version 1.13.0 or higher
- **Terragrunt**: Version 0.84.0 or higher
- **AWS CLI**: Version 2.x configured with appropriate credentials
- **Git**: For version control

### AWS Account Setup
1. AWS Account with appropriate permissions
2. AWS CLI configured with credentials
3. Replace placeholder values in `account.hcl`:
   - `aws_account_id`: Your actual AWS account ID
   - `aws_account_role`: Your Terragrunt execution role ARN

## Infrastructure Architecture

### Services Deployed
- **VPC**: Multi-AZ network with public, private, database, and intra subnets
- **Security Groups**: Layered security with least privilege access
- **DNS**: Route 53 with public/private zones and hybrid resolver
- **EC2**: Auto Scaling Groups with launch templates
- **RDS**: Aurora PostgreSQL cluster with Multi-AZ
- **ElastiCache**: Redis cluster for caching and sessions
- **ALB**: Application Load Balancer with SSL termination
- **S3**: Multiple buckets for assets, backups, and logs
- **CloudFront**: Global CDN with caching and security
- **IAM**: Roles and policies following least privilege
- **KMS**: Encryption keys for all services
- **CloudWatch**: Comprehensive monitoring and alerting
- **WAF**: Web Application Firewall with managed rules

### Network Architecture
```
Internet Gateway
    |
Public Subnets (3 AZs)
    |
NAT Gateways
    |
Private Subnets (3 AZs) - EC2 Instances
    |
Database Subnets (3 AZs) - RDS, ElastiCache
    |
Intra Subnets (3 AZs) - Internal Services
```

## Deployment Steps

### Step 1: Pre-Deployment Configuration

1. **Update Account Configuration**
   ```bash
   # Edit account.hcl with your actual values
   vim account.hcl
   ```
   - Replace `aws_account_id` with your AWS account ID
   - Update contact email addresses
   - Adjust budget limits and cost alerts

2. **Configure Environment Variables**
   ```bash
   # Edit env.hcl for production settings
   vim eu-west-1/prod/env.hcl
   ```
   - Update domain names
   - Adjust instance types and scaling parameters
   - Configure monitoring email addresses

3. **Validate AWS Credentials**
   ```bash
   aws sts get-caller-identity
   ```

### Step 2: Deploy Core Infrastructure

Deploy services in the following order to respect dependencies:

1. **KMS Keys** (No dependencies)
   ```bash
   cd eu-west-1/prod/kms
   terragrunt plan
   terragrunt apply
   ```

2. **IAM Roles** (No dependencies)
   ```bash
   cd ../iam
   terragrunt plan
   terragrunt apply
   ```

3. **VPC** (Depends on: KMS)
   ```bash
   cd ../vpc
   terragrunt plan
   terragrunt apply
   ```

4. **Security Groups** (Depends on: VPC)
   ```bash
   cd ../security-groups
   terragrunt plan
   terragrunt apply
   ```

### Step 3: Deploy Application Infrastructure

5. **DNS** (Depends on: VPC)
   ```bash
   cd ../dns
   terragrunt plan
   terragrunt apply
   ```

6. **RDS** (Depends on: VPC, Security Groups, KMS, IAM)
   ```bash
   cd ../rds
   terragrunt plan
   terragrunt apply
   ```

7. **ElastiCache** (Depends on: VPC, Security Groups, KMS)
   ```bash
   cd ../elasticache
   terragrunt plan
   terragrunt apply
   ```

8. **S3 Buckets** (Depends on: KMS, IAM)
   ```bash
   cd ../s3
   terragrunt plan
   terragrunt apply
   ```

### Step 4: Deploy Load Balancing and Compute

9. **Application Load Balancer** (Depends on: VPC, Security Groups, S3)
   ```bash
   cd ../alb
   terragrunt plan
   terragrunt apply
   ```

10. **Auto Scaling Groups** (Depends on: VPC, Security Groups, ALB, IAM)
    ```bash
    cd ../autoscaling
    terragrunt plan
    terragrunt apply
    ```

11. **EC2 Instances** (Depends on: VPC, Security Groups, IAM)
    ```bash
    cd ../ec2
    terragrunt plan
    terragrunt apply
    ```

### Step 5: Deploy CDN and Security

12. **CloudFront** (Depends on: ALB, S3)
    ```bash
    cd ../cloudfront
    terragrunt plan
    terragrunt apply
    ```

13. **WAF** (Depends on: ALB)
    ```bash
    cd ../waf
    terragrunt plan
    terragrunt apply
    ```

14. **CloudWatch** (Depends on: All services)
    ```bash
    cd ../cloudwatch
    terragrunt plan
    terragrunt apply
    ```

## Post-Deployment Configuration

### SSL Certificates
1. Request SSL certificates in AWS Certificate Manager
2. Update CloudFront and ALB configurations with certificate ARNs
3. Re-run Terragrunt apply for affected services

### DNS Records
1. Update DNS records in Route 53 with actual resource endpoints
2. Configure domain delegation if using external DNS provider

### Application Deployment
1. Deploy application code to EC2 instances via CodeDeploy or S3
2. Configure database connections using Secrets Manager
3. Test application functionality

### Monitoring Setup
1. Configure SNS topic subscriptions for alerts
2. Set up CloudWatch dashboards
3. Test alarm notifications

## Security Checklist

### Encryption
- [x] EBS volumes encrypted with KMS
- [x] RDS encrypted at rest and in transit
- [x] S3 buckets encrypted with KMS
- [x] ElastiCache encrypted at rest and in transit
- [x] Secrets Manager using KMS encryption

### Access Control
- [x] IAM roles follow least privilege principle
- [x] Security groups restrict access by port and source
- [x] S3 buckets block public access where appropriate
- [x] VPC endpoints for AWS services

### Network Security
- [x] Private subnets for application and database tiers
- [x] NAT gateways for outbound internet access
- [x] WAF protecting web applications
- [x] VPC Flow Logs enabled

### Monitoring
- [x] CloudWatch monitoring enabled
- [x] CloudTrail for API logging
- [x] VPC Flow Logs for network monitoring
- [x] WAF logging enabled

## Troubleshooting

### Common Issues

1. **Terraform State Lock**
   ```bash
   # If state is locked, force unlock (use with caution)
   terragrunt force-unlock <LOCK_ID>
   ```

2. **Dependency Errors**
   - Ensure services are deployed in the correct order
   - Check that dependency outputs are available

3. **Permission Errors**
   - Verify AWS credentials have sufficient permissions
   - Check IAM role trust relationships

4. **Resource Limits**
   - Check AWS service limits in your region
   - Request limit increases if needed

### Validation Commands

```bash
# Check VPC configuration
aws ec2 describe-vpcs --filters "Name=tag:Name,Values=*katyacleaning*"

# Verify RDS cluster
aws rds describe-db-clusters --db-cluster-identifier katyacleaning-prod-postgres-cluster

# Check ALB status
aws elbv2 describe-load-balancers --names katyacleaning-prod-alb

# Verify Auto Scaling Group
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names katyacleaning-prod-web-asg
```

## Maintenance

### Regular Tasks
- Monitor CloudWatch dashboards and alarms
- Review WAF logs for security threats
- Update AMIs and redeploy instances
- Review and rotate access keys
- Monitor costs and optimize resources

### Backup Verification
- Test RDS automated backups
- Verify S3 cross-region replication
- Test disaster recovery procedures

### Security Updates
- Apply security patches to EC2 instances
- Update WAF rules as needed
- Review IAM permissions quarterly
- Rotate encryption keys annually

## Cost Optimization

### Recommendations
- Use Reserved Instances for predictable workloads
- Enable S3 Intelligent Tiering
- Monitor unused resources with AWS Cost Explorer
- Set up billing alerts and budgets
- Review and right-size instances regularly

### Estimated Monthly Costs (Production)
- VPC and Networking: $50-100
- EC2 Instances (3x t3.medium): $100-150
- RDS Aurora (2x db.t3.medium): $200-300
- ElastiCache (Redis): $50-75
- ALB: $25-35
- S3 Storage: $20-50
- CloudFront: $10-30
- Other services: $50-100

**Total Estimated: $505-840/month**

## Support and Documentation

### AWS Documentation
- [VPC User Guide](https://docs.aws.amazon.com/vpc/)
- [RDS Aurora Guide](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/)
- [Auto Scaling User Guide](https://docs.aws.amazon.com/autoscaling/)

### Terragrunt Documentation
- [Terragrunt Documentation](https://terragrunt.gruntwork.io/docs/)
- [Best Practices](https://terragrunt.gruntwork.io/docs/getting-started/quick-start/)

### Emergency Contacts
- Infrastructure Team: infrastructure@katyacleaning.com
- Security Team: security@katyacleaning.com
- On-call Engineer: +1-XXX-XXX-XXXX

---

**Note**: This deployment creates production-grade infrastructure. Ensure you understand the costs and security implications before deploying. Always test in a development environment first.
