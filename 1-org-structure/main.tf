# AWS Security Landing Zone Terraform Configuration
# This creates a simplified landing zone with:
# - AWS Organization
# - Security tooling account
# - Workload account
# - Cross-account access roles

# This implementation is designed to work with a fresh AWS account where only the root user exists.
# The deployment is structured in a way to handle the proper dependency chain and account creation process.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Provider configuration for the management account
provider "aws" {
  region = "us-east-1"
  alias = "management"
}

# Create AWS Organization
resource "aws_organizations_organization" "org" {
  # No provider specified - uses the default (root credentials)
  
  # Enable features needed for security management
  feature_set = "ALL"
  
  # Enable AWS services that will integrate with Organizations
  aws_service_access_principals = [
    "sso.amazonaws.com",
    "cloudtrail.amazonaws.com",
  ]
  
  # Enable IAM user access to billing
  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY",
  ]
}

# Create Organizational Units
resource "aws_organizations_organizational_unit" "security" {
  provider  = aws.management
  name      = "Security"
  parent_id = aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_organizational_unit" "workloads" {
  provider  = aws.management
  name      = "Workloads"
  parent_id = aws_organizations_organization.org.roots[0].id
}

# Create member accounts
resource "aws_organizations_account" "security_tooling" {
  provider                   = aws.management
  name                       = "security-tooling"
  email                      = var.security_account_email
  parent_id                  = aws_organizations_organizational_unit.security.id
  role_name                  = "OrganizationAccountAccessRole"
  close_on_deletion          = false
  iam_user_access_to_billing = "ALLOW"
}

resource "aws_organizations_account" "workload" {
  provider                   = aws.management
  name                       = "workload"
  email                      = var.workload_account_email
  parent_id                  = aws_organizations_organizational_unit.workloads.id
  role_name                  = "OrganizationAccountAccessRole"
  close_on_deletion          = false
  iam_user_access_to_billing = "ALLOW"
}

# Create an IAM user in the management account for administrative access
resource "aws_iam_user" "admin_user" {
  name = "admin-user"
}

# Create access keys for the admin user (for programmatic access)
resource "aws_iam_access_key" "admin_user_key" {
  user = aws_iam_user.admin_user.name
}

# Store the access keys securely in a local file
resource "local_file" "admin_credentials" {
  content  = jsonencode({
    access_key = aws_iam_access_key.admin_user_key.id,
    secret_key = aws_iam_access_key.admin_user_key.secret
  })
  filename = "${path.module}/admin_credentials.json"
  file_permission = "0600" # Restrictive permissions
}

# Create an IAM policy for accessing member accounts from the management account
resource "aws_iam_policy" "assume_role_policy" {
  name        = "AssumeOrganizationAccountAccessRole"
  description = "Policy to allow assuming the OrganizationAccountAccessRole in member accounts"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/OrganizationAccountAccessRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = aws_organizations_organization.org.id
          }
        }
      }
    ]
  })
}

# Grant admin permissions to the admin user
resource "aws_iam_user_policy_attachment" "admin_user_policy" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Attach the assume role policy to the admin user
resource "aws_iam_user_policy_attachment" "assume_role_attachment" {
  user       = aws_iam_user.admin_user.name
  policy_arn = aws_iam_policy.assume_role_policy.arn
}

# Create a local file to store account information for the second phase of deployment
resource "local_file" "account_info" {
  content = jsonencode({
    management_account_id = aws_organizations_organization.org.master_account_id,
    security_account_id   = aws_organizations_account.security_tooling.id,
    workload_account_id   = aws_organizations_account.workload.id
  })
  filename = "${path.module}/account_info.json"
}

# Note: We won't define providers for member accounts in the first phase
# Instead we'll create a second Terraform configuration (phase2.tf) that will be applied after 
# the IAM users and access keys are created in the management account

# These resources will be created in phase2.tf after IAM users and access keys are created
# We'll move all workload account resources to the second phase of deployment

# These resources will be created in phase2.tf after IAM users and access keys are created
# We'll move all security tooling account resources to the second phase of deployment

# Organization Service Control Policy (SCP) to restrict to free tier services
resource "aws_organizations_policy" "free_tier_scp" {
  provider = aws.management
  name     = "FreeTierServicesOnly"
  content  = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Action = [
          "config:*",           # Explicitly deny AWS Config
          "guardduty:*",        # Deny GuardDuty
          "securityhub:*",      # Deny Security Hub
          "macie:*",            # Deny Macie
          "inspector:*",        # Deny Inspector
          "detective:*"         # Deny Detective
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach the SCP to the organization root
resource "aws_organizations_policy_attachment" "free_tier_attachment" {
  provider  = aws.management
  policy_id = aws_organizations_policy.free_tier_scp.id
  target_id = aws_organizations_organization.org.roots[0].id
}

# Variables
variable "security_account_email" {
  description = "Email address for the security tooling account"
  type        = string
}

variable "workload_account_email" {
  description = "Email address for the workload account"
  type        = string
}

# Outputs
output "management_account_id" {
  value = aws_organizations_organization.org.master_account_id
}

output "security_tooling_account_id" {
  value = aws_organizations_account.security_tooling.id
}

output "workload_account_id" {
  value = aws_organizations_account.workload.id
}