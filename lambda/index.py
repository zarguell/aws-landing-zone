import boto3
import os
import json
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Lambda function to perform security scanning across AWS accounts.
    This is a simple example that checks for public S3 buckets and unencrypted EBS volumes.
    """
    workload_account_id = os.environ.get('WORKLOAD_ACCOUNT_ID')
    
    if not workload_account_id:
        logger.error("WORKLOAD_ACCOUNT_ID environment variable not set")
        return {
            'statusCode': 500,
            'body': 'WORKLOAD_ACCOUNT_ID environment variable not set'
        }
    
    # Assume the SecurityAuditorRole in the workload account
    sts_client = boto3.client('sts')
    
    try:
        # Assume role in the workload account
        role_arn = f"arn:aws:iam::{workload_account_id}:role/SecurityAuditorRole"
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SecurityScanSession",
            ExternalId="UniqueSecurityScanID123"
        )
        
        # Extract temporary credentials
        credentials = assumed_role['Credentials']
        
        # Create boto3 clients using the temporary credentials
        s3_client = boto3.client(
            's3',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        # Check for public S3 buckets
        public_buckets = check_public_buckets(s3_client)
        
        # Check for unencrypted EBS volumes
        unencrypted_volumes = check_unencrypted_volumes(ec2_client)
        
        # Prepare findings
        findings = {
            'account_id': workload_account_id,
            'public_buckets': public_buckets,
            'unencrypted_volumes': unencrypted_volumes
        }
        
        # Log findings
        logger.info(f"Security scan findings: {json.dumps(findings)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(findings)
        }
    
    except Exception as e:
        logger.error(f"Error during security scan: {str(e)}")
        return {
            'statusCode': 500,
            'body': f"Error during security scan: {str(e)}"
        }

def check_public_buckets(s3_client):
    """Check for publicly accessible S3 buckets"""
    public_buckets = []
    
    try:
        # List all buckets
        response = s3_client.list_buckets()
        
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy['Policy'])
                
                # Simple check for public access in policy (this is a basic check)
                if any('*' in str(statement.get('Principal', '')) for statement in policy_json.get('Statement', [])):
                    public_buckets.append({
                        'name': bucket_name,
                        'issue': 'Bucket policy grants public access'
                    })
                    continue
            except s3_client.exceptions.NoSuchBucketPolicy:
                # No bucket policy, continue checking other public access methods
                pass
            except Exception as e:
                logger.warning(f"Error checking bucket policy for {bucket_name}: {str(e)}")
            
            # Check bucket ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                
                # Check for public access in ACL
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        public_buckets.append({
                            'name': bucket_name,
                            'issue': 'Bucket ACL grants public access'
                        })
                        break
            except Exception as e:
                logger.warning(f"Error checking bucket ACL for {bucket_name}: {str(e)}")
            
            # Check bucket public access block settings
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_access_block['PublicAccessBlockConfiguration']
                
                # If any of these are False, the bucket might be public
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    public_buckets.append({
                        'name': bucket_name,
                        'issue': 'Public access block not fully enabled'
                    })
            except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                # No public access block configuration means the bucket could be public
                public_buckets.append({
                    'name': bucket_name,
                    'issue': 'No public access block configuration'
                })
            except Exception as e:
                logger.warning(f"Error checking public access block for {bucket_name}: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error checking for public buckets: {str(e)}")
    
    return public_buckets

def check_unencrypted_volumes(ec2_client):
    """Check for unencrypted EBS volumes"""
    unencrypted_volumes = []
    
    try:
        # List all EBS volumes
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_id = volume['VolumeId']
                encrypted = volume.get('Encrypted', False)
                
                if not encrypted:
                    # Check for attached instances
                    attached_instances = []
                    for attachment in volume.get('Attachments', []):
                        attached_instances.append(attachment.get('InstanceId', 'Unknown'))
                    
                    unencrypted_volumes.append({
                        'volume_id': volume_id,
                        'size_gb': volume.get('Size', 0),
                        'attached_instances': attached_instances,
                        'creation_time': str(volume.get('CreateTime', ''))
                    })
    
    except Exception as e:
        logger.error(f"Error checking for unencrypted volumes: {str(e)}")
    
    return unencrypted_volumes

# Additional security checks that could be added:
# - IAM users with console access but no MFA
# - Security groups with 0.0.0.0/0 ingress rules
# - CloudTrail logging status
# - Default VPC security groups
# - Unused IAM roles
# - Public RDS instances