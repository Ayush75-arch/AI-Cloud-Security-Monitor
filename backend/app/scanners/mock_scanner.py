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
        ]
