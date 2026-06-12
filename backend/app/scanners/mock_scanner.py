"""
CloudGuard-AI — Mock Scanner
Returns realistic fake AWS assets when no credentials are configured.
Used for demo/development mode.
"""
import asyncio
from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType


class MockScanner(BaseScanner):
    """
    Returns a fixed set of realistic assets for demo purposes.
    Triggered automatically when AWS credentials are not configured.
    """
    service_name = "mock"

    async def scan(self) -> list[ScanResult]:
        # Simulate scan delay
        await asyncio.sleep(0.5)
        return [
            ScanResult(AssetType.S3_BUCKET, "arn:aws:s3:::prod-customer-data",
                "prod-customer-data", "us-east-1", {
                    "Name": "prod-customer-data",
                    "PublicAccessBlockConfiguration": None,  # triggers S3-001
                    "ServerSideEncryptionConfiguration": None,  # triggers S3-002
                    "VersioningConfiguration": {},
                    "LoggingEnabled": None,
                    "ACL": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]},
                }),
            ScanResult(AssetType.S3_BUCKET, "arn:aws:s3:::dev-backups-2024",
                "dev-backups-2024", "us-east-1", {
                    "Name": "dev-backups-2024",
                    "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
                    "ServerSideEncryptionConfiguration": None,  # triggers S3-002
                    "VersioningConfiguration": {},
                    "LoggingEnabled": None,
                    "ACL": {"Grants": []},
                }),
            ScanResult(AssetType.S3_BUCKET, "arn:aws:s3:::static-assets-cdn",
                "static-assets-cdn", "us-east-1", {
                    "Name": "static-assets-cdn",
                    "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
                    "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                    "VersioningConfiguration": {},  # triggers S3-003
                    "LoggingEnabled": None,
                    "ACL": {"Grants": []},
                }),
            ScanResult(AssetType.IAM_POLICY, "arn:aws:iam::123456789012:policy/DevFullAccess",
                "DevFullAccess", "global", {
                    "PolicyName": "DevFullAccess",
                    "PolicyDocument": {
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                    },
                    "InlinePolicies": [],
                    "AttachedPolicies": [],
                }),
            ScanResult(AssetType.IAM_USER, "arn:aws:iam::123456789012:user/john.smith",
                "john.smith", "global", {
                    "UserName": "john.smith",
                    "Arn": "arn:aws:iam::123456789012:user/john.smith",
                    "MFADevices": [],  # triggers IAM-002
                    "AccessKeys": [],
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                }),
            ScanResult(AssetType.IAM_USER, "arn:aws:iam::123456789012:user/ci-deploy",
                "ci-deploy", "global", {
                    "UserName": "ci-deploy",
                    "Arn": "arn:aws:iam::123456789012:user/ci-deploy",
                    "MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/ci-deploy"}],
                    "AccessKeys": [{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active", "CreateDate": "2024-12-01T00:00:00+00:00"}],  # triggers IAM-003
                    "AttachedPolicies": [],
                    "InlinePolicies": [],
                }),
            ScanResult(AssetType.SECURITY_GROUP, "sg-0a1b2c3d4e5f",
                "web-tier-sg", "us-east-1", {
                    "GroupId": "sg-0a1b2c3d4e5f",
                    "GroupName": "web-tier-sg",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},  # triggers EC2-001
                    ],
                }),
            ScanResult(AssetType.SECURITY_GROUP, "sg-9z8y7x6w5v",
                "bastion-sg", "us-east-1", {
                    "GroupId": "sg-9z8y7x6w5v",
                    "GroupName": "bastion-sg",
                    "IpPermissions": [
                        {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                         "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},  # triggers EC2-002
                    ],
                }),
            ScanResult(AssetType.VPC, "vpc-0123456789abc",
                "prod-vpc", "us-east-1", {
                    "VpcId": "vpc-0123456789abc",
                    "IsDefault": False,
                    "FlowLogs": [],  # triggers VPC-001
                    "InternetGateways": [],
                    "Subnets": [],
                    "RouteTables": [],
                    "NetworkAcls": [],
                }),
            ScanResult(AssetType.VPC, "vpc-default",
                "default", "us-east-1", {
                    "VpcId": "vpc-default",
                    "IsDefault": True,  # triggers VPC-002
                    "FlowLogs": [{"FlowLogStatus": "ACTIVE"}],
                    "InternetGateways": [],
                    "Subnets": [],
                    "RouteTables": [],
                    "NetworkAcls": [],
                }),
            # RDS
            ScanResult(AssetType.RDS_INSTANCE, "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                "prod-db", "us-east-1", {
                    "DBInstanceIdentifier": "prod-db",
                    "StorageEncrypted": False,  # triggers RDS-001
                    "PubliclyAccessible": False,
                    "DeletionProtection": False,  # triggers RDS-003
                    "BackupRetentionPeriod": 1,  # triggers RDS-004
                    "AutoMinorVersionUpgrade": False,  # triggers RDS-005
                    "MultiAZ": True,
                    "Engine": "postgres",
                    "EngineVersion": "15.4",
                }),
            ScanResult(AssetType.RDS_INSTANCE, "arn:aws:rds:us-east-1:123456789012:db:staging-db",
                "staging-db", "us-east-1", {
                    "DBInstanceIdentifier": "staging-db",
                    "StorageEncrypted": True,
                    "PubliclyAccessible": True,  # triggers RDS-002
                    "DeletionProtection": True,
                    "BackupRetentionPeriod": 35,
                    "AutoMinorVersionUpgrade": True,
                    "MultiAZ": False,
                    "Engine": "mysql",
                    "EngineVersion": "8.0",
                }),
            # Lambda
            ScanResult(AssetType.LAMBDA_FUNCTION, "arn:aws:lambda:us-east-1:123456789012:function:data-processor",
                "data-processor", "us-east-1", {
                    "FunctionName": "data-processor",
                    "Runtime": "python3.8",  # triggers LAMBDA-002
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                    "Timeout": 900,  # triggers LAMBDA-004
                    "MemorySize": 512,
                    "VpcConfig": {"SubnetIds": ["subnet-123"], "SecurityGroupIds": ["sg-123"]},
                    "Environment": {"Variables": {"DB_URL": "postgresql://localhost/mydb"}},
                }),
            ScanResult(AssetType.LAMBDA_FUNCTION, "arn:aws:lambda:us-east-1:123456789012:function:api-handler",
                "api-handler", "us-east-1", {
                    "FunctionName": "api-handler",
                    "Runtime": "nodejs18.x",
                    "Role": "arn:aws:iam::123456789012:role/lambda-role",
                    "Timeout": 30,
                    "MemorySize": 256,
                    "VpcConfig": {},
                }),
            # CloudTrail
            ScanResult(AssetType.CLOUDTRAIL_TRAIL, "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-events",
                "management-events", "us-east-1", {
                    "Name": "management-events",
                    "TrailsExist": True,
                    "IsMultiRegionTrail": False,  # triggers CT-002
                    "LogFileValidationEnabled": False,  # triggers CT-003
                    "KmsKeyId": "",  # triggers CT-004
                    "S3BucketName": "cloudtrail-logs-123456789012",
                    "IncludeGlobalServiceEvents": True,
                    "Status": {"IsLogging": True},
                }),
            # KMS
            ScanResult(AssetType.KMS_KEY, "arn:aws:kms:us-east-1:123456789012:key/mrk-1234567890abcdef0",
                "mrk-1234567890abcdef0", "us-east-1", {
                    "KeyId": "mrk-1234567890abcdef0",
                    "KeyState": "Enabled",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeyManager": "CUSTOMER",
                    "Enabled": True,
                    "KeyRotationEnabled": False,  # triggers KMS-001
                    "MultiRegion": True,
                    "Description": "Encryption key for prod data",
                }),
            ScanResult(AssetType.KMS_KEY, "arn:aws:kms:us-east-1:123456789012:key/abcdef0123456789",
                "abcdef0123456789", "us-east-1", {
                    "KeyId": "abcdef0123456789",
                    "KeyState": "Disabled",  # triggers KMS-003
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeyManager": "AWS",  # triggers KMS-004
                    "Enabled": False,
                    "KeyRotationEnabled": False,
                    "MultiRegion": False,
                    "Description": "AWS managed key for S3",
                }),
        ]
