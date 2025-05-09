# AWS Security Landing Zone Deployment Guide

This guide walks you through setting up a simplified AWS landing zone focused on security tooling, using Terraform. This setup is designed to work with AWS Free Tier while providing a foundation for security engineering and automation.

## Architecture Overview

The architecture includes:

1. **Management Account**: Hosts the AWS Organization and manages member accounts
2. **Security Tooling Account**: For security automation and monitoring
3. **Workload Account**: For your applications and resources to monitor

## Prerequisites

- AWS Account (no organization yet)
- [AWS CLI](https://aws.amazon.com/cli/) installed and configured
- [Terraform](https://www.terraform.io/downloads.html) (version 1.0.0+)
- Two unique email addresses for creating member accounts

## Important: Two-Phase Deployment

This solution uses a two-phase deployment approach to handle the transition from a single account to a multi-account organization:

1. **Phase 1**: Creates the AWS Organization, member accounts, and IAM users/credentials in the management account
2. **Phase 2**: Uses the IAM credentials to set up cross-account access and deploy resources in member accounts

## Initial Setup

### 1. Prepare Your Environment

Create a new directory for your Terraform configuration:

```bash
mkdir aws-landing-zone
cd aws-landing-zone
```

Create a file named `terraform.tfvars` with the following content (replace with your email addresses):

```hcl
security_account_email = "security@yourdomain.com"
workload_account_email = "workload@yourdomain.com"
```

### 2. Create the Lambda Code Archive

Create a `lambda` directory and add the Python code:

```bash
mkdir lambda
cd lambda
```

Create the ZIP archive:

```bash
zip -r ../lambda_function.zip .
cd ..
```

## Phase 1 Deployment

### 1. Initialize Terraform

```bash
terraform init
```

### 2. Plan and Apply Phase 1

```bash
terraform plan
terraform apply
```

Enter `yes` when prompted to confirm the deployment.

The initial deployment may take 5-10 minutes as AWS Organizations creates the member accounts.

> **Important**: After this step, Terraform will create two JSON files:
> - `account_info.json`: Contains the AWS account IDs
> - `admin_credentials.json`: Contains the access key and secret for the admin IAM user

## Phase 2 Deployment

After Phase 1 completes successfully and the JSON files are created, proceed with Phase 2:

### 1. Apply Phase 2 Configuration

The Phase 2 Terraform will use the credentials and account information generated in Phase 1:

```bash
# Copy the phase2.tf file from the artifact to your working directory
# Then run:
terraform init  # To initialize any new providers
terraform apply # To apply the phase 2 configuration
```

Enter `yes` when prompted to confirm the deployment.

This phase will:
1. Set up cross-account IAM roles in the workload account
2. Create the security automation role in the security tooling account
3. Deploy the Lambda function and EventBridge rule

## Post-Deployment Setup

### 1. Access Member Accounts

After deployment, you should verify access to the member accounts:

1. Log in to the Management account
2. Navigate to AWS Organizations
3. Find the Security Tooling account and select "Access" to sign in with the OrganizationAccountAccessRole
4. Repeat for the Workload account

### 2. Set Up MFA for Root Users

For each account (Management, Security Tooling, Workload):

1. Log in as the root user (using the email you provided)
2. Set up MFA for the root user
3. Store the root user credentials securely

### 3. Verify Cross-Account Access

Test that the Security Tooling account can access the Workload account:

1. Configure AWS CLI with the admin user access keys:
   ```bash
   aws configure --profile admin
   # Enter the access key and secret from admin_credentials.json
   ```

2. Use the AWS CLI to assume the SecurityAuditorRole in the Workload account:
   ```bash
   aws sts assume-role \
     --profile admin \
     --role-arn arn:aws:iam::<WORKLOAD_ACCOUNT_ID>:role/SecurityAuditorRole \
     --role-session-name TestSession
   ```

### 4. Test the Security Scanner Lambda

1. Log in to the Security Tooling account
2. Navigate to the Lambda console
3. Find the `security-scanner` function
4. Create a test event (empty JSON `{}`)
5. Execute the test and review the results

## Next Steps

Now that your security landing zone is set up, here are some next steps to enhance your security posture:

1. **Enhance the Security Scanner**: Add more security checks to the Lambda function
2. **Add More Member Accounts**: Create separate accounts for development, testing, and production
3. **Implement AWS Organizations SCPs**: Create additional service control policies to enforce security guardrails
4. **Set Up CloudTrail**: Configure CloudTrail in the Management account with a central S3 bucket
5. **Implement Budgets**: Set up AWS Budgets to monitor costs and avoid unexpected charges

