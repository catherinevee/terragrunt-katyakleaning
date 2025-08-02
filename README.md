# Katya Cleaning Services - AWS Infrastructure

## Overview

This repository contains the complete AWS infrastructure as code for Katya Cleaning Services, built using Terragrunt and following enterprise-grade best practices. The infrastructure is designed for high availability, security, and scalability in the production environment.

## Architecture

### Infrastructure Components

| Service | Purpose | Module Source | Features |
|---------|---------|---------------|----------|
| **VPC** | Network foundation | Terraform Registry | Multi-AZ, VPC endpoints, Flow logs |
| **Security Groups** | Network security | Terraform Registry | Layered security, least privilege |
| **DNS** | Domain management | GitHub (catherinevee/tfm-aws-dns) | Public/private zones, health checks |
| **EC2** | Compute instances | GitHub (catherinevee/ec2) | Auto Scaling, monitoring, encryption |
| **RDS** | Database cluster | Terraform Registry | Aurora PostgreSQL, Multi-AZ, encryption |
| **ElastiCache** | Caching layer | Terraform Registry | Redis cluster, encryption |
| **ALB** | Load balancing | Terraform Registry | SSL termination, health checks |
| **Auto Scaling** | Dynamic scaling | Terraform Registry | Target tracking, instance refresh |
| **S3** | Object storage | Terraform Registry | Multiple buckets, lifecycle policies |
| **CloudFront** | CDN | Terraform Registry | Global distribution, caching |
| **IAM** | Access management | Terraform Registry | Least privilege roles and policies |
| **KMS** | Encryption keys | Terraform Registry | Service-specific keys |
| **CloudWatch** | Monitoring | Terraform Registry | Dashboards, alarms, log aggregation |
| **WAF** | Web security | Terraform Registry | Managed rules, rate limiting |

### Network Architecture

```
Internet Gateway
    |
Public Subnets (3 AZs) - ALB, NAT Gateways
    |
Private Subnets (3 AZs) - EC2 Instances
    |
Database Subnets (3 AZs) - RDS, ElastiCache
    |
Intra Subnets (3 AZs) - Internal Services
```

## Directory Structure

```
terragrunt-katyakleaning/
├── root.hcl                    # Global Terragrunt configuration
├── account.hcl                 # Account-level settings
├── DEPLOYMENT.md               # Detailed deployment guide
├── README.md                   # This file
└── eu-west-1/                  # Region-specific configuration
    ├── region.hcl              # Region-level settings
    └── prod/                   # Production environment
        ├── env.hcl             # Environment-specific settings
        ├── vpc/                # VPC and networking
        ├── security-groups/    # Security group definitions
        ├── dns/                # Route 53 DNS management
        ├── ec2/                # EC2 instance configuration
        ├── rds/                # Aurora PostgreSQL cluster
        ├── elasticache/        # Redis cache cluster
        ├── alb/                # Application Load Balancer
        ├── autoscaling/        # Auto Scaling Groups
        ├── s3/                 # S3 bucket configuration
        ├── cloudfront/         # CloudFront distribution
        ├── iam/                # IAM roles and policies
        ├── kms/                # KMS encryption keys
        ├── cloudwatch/         # Monitoring and alerting
        └── waf/                # Web Application Firewall
```

## Key Features

### Security
- **End-to-end encryption**: All data encrypted at rest and in transit
- **Network isolation**: Multi-tier architecture with private subnets
- **Access control**: IAM roles with least privilege principles
- **Web protection**: WAF with managed rules and rate limiting
- **Monitoring**: Comprehensive logging and alerting

### High Availability
- **Multi-AZ deployment**: Resources distributed across 3 availability zones
- **Auto Scaling**: Dynamic scaling based on demand
- **Load balancing**: Application Load Balancer with health checks
- **Database clustering**: Aurora with automatic failover
- **Backup and recovery**: Automated backups with cross-region replication

### Performance
- **CDN**: CloudFront for global content delivery
- **Caching**: Redis for session storage and application caching
- **Optimized instances**: Right-sized instances with monitoring
- **Network optimization**: VPC endpoints and enhanced networking

### Cost Optimization
- **Intelligent tiering**: S3 lifecycle policies for cost savings
- **Reserved capacity**: Options for predictable workloads
- **Monitoring**: Cost tracking and budget alerts
- **Resource optimization**: Auto Scaling and spot instances where appropriate

## Quick Start

### Prerequisites
- Terraform >= 1.13.0
- Terragrunt (latest)
- AWS CLI v2 configured
- Appropriate AWS permissions

### Configuration
1. Update `account.hcl` with your AWS account details
2. Modify `eu-west-1/prod/env.hcl` for your environment
3. Replace placeholder values (domains, IPs, etc.)

### Deployment
```bash
# Deploy in dependency order
cd eu-west-1/prod/kms && terragrunt apply
cd ../iam && terragrunt apply
cd ../vpc && terragrunt apply
cd ../security-groups && terragrunt apply
# ... continue with remaining services
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.

## Configuration Guidelines

### Naming Convention
- Resources: `{environment}-katyacleaning-{service}`
- Variables: `snake_case`
- Directories: `kebab-case`

### Tagging Strategy
- **Environment**: prod, staging, dev
- **Project**: KatyaCleaning
- **Owner**: Infrastructure Team
- **CostCenter**: Operations
- **Compliance**: SOC2

### Security Best Practices
- All resources encrypted with KMS
- Network segmentation with security groups
- IAM roles with minimal permissions
- Regular security updates and patches
- Comprehensive audit logging

## Monitoring and Alerting

### CloudWatch Dashboards
- Main infrastructure dashboard
- WAF security dashboard
- Cost and usage tracking

### Alarms
- High CPU/memory utilization
- Application response time
- Error rate thresholds
- Database connection limits
- Security events

### Log Aggregation
- Application logs
- System logs
- Access logs
- Security logs
- DNS query logs

## Estimated Costs

| Service Category | Monthly Cost (USD) |
|------------------|--------------------|
| Compute (EC2, ALB) | $150-200 |
| Database (RDS Aurora) | $200-300 |
| Storage (S3, EBS) | $50-100 |
| Network (CloudFront, Data Transfer) | $50-100 |
| Security (WAF, KMS) | $25-50 |
| Monitoring (CloudWatch) | $30-50 |
| **Total** | **$505-800** |

*Costs vary based on usage patterns and data transfer*

## Support

### Documentation
- [Deployment Guide](DEPLOYMENT.md) - Step-by-step deployment instructions
- [Terragrunt Documentation](https://terragrunt.gruntwork.io/docs/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)

### Contacts
- **Infrastructure Team**: infrastructure@katyacleaning.com
- **Security Team**: security@katyacleaning.com
- **Emergency**: See deployment guide for on-call contacts

## Contributing

1. Follow the established naming conventions
2. Ensure all resources are properly tagged
3. Include comprehensive documentation
4. Test changes in development environment first
5. Follow security best practices

## License

This infrastructure code is proprietary to Katya Cleaning Services.

---

**Built with ❤️ using Terragrunt and AWS**

*Last updated: $(date +'%Y-%m-%d')*