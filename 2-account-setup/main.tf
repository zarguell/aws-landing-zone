# Phase 2 of AWS Security Landing Zone setup
# This file should be used AFTER the main Terraform configuration has been applied
# and the IAM user/access keys have been created in the management account

# Read the account information from the file created in phase 1
data "local_file" "account_info" {
  filename = "${path.module}/account_info.json"
}

locals {
  account_info = jsondecode(data.local_file.account_info.content)
  management_account_id = local.account_info.management_account_id
  security_account_id   = local.account_info.security_account_id
  workload_account_id   = local.account_info.workload_account_id
}

# Read the admin credentials from the file created in phase 1
data "local_file" "admin_credentials" {
  filename = "${path.module}/admin_credentials.json"
}

locals {
  admin_credentials = jsondecode(data.local_file.admin_credentials.content)
}

# Management account provider using the admin user credentials
provider "aws" {
  region     = "us-east-1"
  alias      = "management"
  access_key = local.admin_credentials.access_key
  secret_key = local.admin_credentials.secret_key
}

# Security tooling account provider using assume role
provider "aws" {
  region  = "us-east-1"
  alias   = "security_tooling"
  
  access_key = local.admin_credentials.access_key
  secret_key = local.admin_credentials.secret_key
  
  assume_role {
    role_arn = "arn:aws:iam::${local.security_account_id}:role/OrganizationAccountAccessRole"
  }
}

# Workload account provider using assume role
provider "aws" {
  region  = "us-east-1"
  alias   = "workload"
  
  access_key = local.admin_credentials.access_key
  secret_key = local.admin_credentials.secret_key
  
  assume_role {
    role_arn = "arn:aws:iam::${local.workload_account_id}:role/OrganizationAccountAccessRole"
  }
}

# Create SecurityAuditor role in the workload account that can be assumed by the security tooling account
resource "aws_iam_role" "security_auditor_role" {
  provider = aws.workload
  name     = "SecurityAuditorRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = {
          AWS = "arn:aws:iam::${local.security_account_id}:root"
        }
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = local.management_account_id
          }
        }
      }
    ]
  })
}

# Attach the SecurityAudit policy to the SecurityAuditor role
resource "aws_iam_role_policy_attachment" "security_auditor_policy" {
  provider   = aws.workload
  role       = aws_iam_role.security_auditor_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Create the SecurityAutomation role in the security tooling account
resource "aws_iam_role" "security_automation_role" {
  provider = aws.security_tooling
  name     = "SecurityAutomationRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Policy to allow security tooling to assume SecurityAuditorRole in other accounts
resource "aws_iam_policy" "assume_security_auditor_policy" {
  provider    = aws.security_tooling
  name        = "AssumeSecurityAuditorRole"
  description = "Policy to allow assuming the SecurityAuditorRole in member accounts"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/SecurityAuditorRole"
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = local.management_account_id
          }
        }
      }
    ]
  })
}

# Attach the policy to the SecurityAutomation role
resource "aws_iam_role_policy_attachment" "security_automation_policy" {
  provider   = aws.security_tooling
  role       = aws_iam_role.security_automation_role.name
  policy_arn = aws_iam_policy.assume_security_auditor_policy.arn
}

# Allow Lambda basic execution permissions
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  provider   = aws.security_tooling
  role       = aws_iam_role.security_automation_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Sample Lambda function for security scanning
resource "aws_lambda_function" "security_scanner" {
  provider      = aws.security_tooling
  function_name = "security-scanner"
  role          = aws_iam_role.security_automation_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
  timeout       = 30
  
  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip")
  
  environment {
    variables = {
      WORKLOAD_ACCOUNT_ID = local.workload_account_id
    }
  }
}

# EventBridge rule to trigger the Lambda function daily
resource "aws_cloudwatch_event_rule" "daily_security_scan" {
  provider            = aws.security_tooling
  name                = "daily-security-scan"
  description         = "Trigger security scanner Lambda function daily"
  schedule_expression = "cron(0 1 * * ? *)" # 1:00 AM UTC daily
}

resource "aws_cloudwatch_event_target" "security_scan_target" {
  provider = aws.security_tooling
  rule     = aws_cloudwatch_event_rule.daily_security_scan.name
  arn      = aws_lambda_function.security_scanner.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  provider      = aws.security_tooling
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_security_scan.arn
}