"""
CloudGuard-AI — Constants & Enumerations
Single source of truth for severity, status, asset types, compliance frameworks.
"""
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"


class AssetType(str, Enum):
    S3_BUCKET = "s3_bucket"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    IAM_USER = "iam_user"
    EC2_INSTANCE = "ec2_instance"
    SECURITY_GROUP = "security_group"
    VPC = "vpc"
    SUBNET = "subnet"
    INTERNET_GATEWAY = "internet_gateway"


class ComplianceFramework(str, Enum):
    CIS = "CIS"
    NIST = "NIST"
    PCI_DSS = "PCI-DSS"


# Severity → numeric weight for risk score computation
SEVERITY_WEIGHTS: dict[str, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
}

# Services supported by scanner
SUPPORTED_SERVICES = ["s3", "iam", "ec2", "vpc"]
