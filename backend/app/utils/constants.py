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
    ISO_27001 = "ISO-27001"
    GDPR = "GDPR"


# Severity → numeric weight for risk score computation
SEVERITY_WEIGHTS: dict[str, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
}

# Services supported by scanner
SUPPORTED_SERVICES = ["s3", "iam", "ec2", "vpc"]

# ── Compliance control mappings ───────────────────────────────────────────────
# Extended mappings used by the compliance service to score ISO 27001 and GDPR.
# Maps rule_id → framework → control

EXTENDED_COMPLIANCE: dict[str, dict[str, str]] = {
    "S3-001": {
        "ISO-27001": "A.13.1.3",   # Segregation in networks
        "GDPR": "Art.32",           # Security of processing
    },
    "S3-002": {
        "ISO-27001": "A.10.1.1",   # Policy on use of cryptographic controls
        "GDPR": "Art.32",
    },
    "S3-003": {
        "ISO-27001": "A.12.3.1",   # Information backup
        "GDPR": "Art.5.1.f",        # Integrity and confidentiality
    },
    "S3-004": {
        "ISO-27001": "A.12.4.1",   # Event logging
        "GDPR": "Art.30",           # Records of processing activities
    },
    "IAM-001": {
        "ISO-27001": "A.9.2.3",    # Management of privileged access rights
        "GDPR": "Art.25",           # Data protection by design
    },
    "IAM-002": {
        "ISO-27001": "A.9.4.2",    # Secure log-on procedures
        "GDPR": "Art.32",
    },
    "IAM-003": {
        "ISO-27001": "A.9.4.3",    # Password management system
        "GDPR": "Art.32",
    },
    "EC2-001": {
        "ISO-27001": "A.13.1.1",   # Network controls
        "GDPR": "Art.32",
    },
    "EC2-002": {
        "ISO-27001": "A.13.1.1",
        "GDPR": "Art.32",
    },
    "VPC-001": {
        "ISO-27001": "A.12.4.1",   # Event logging
        "GDPR": "Art.30",
    },
    "VPC-002": {
        "ISO-27001": "A.13.1.2",   # Security of network services
        "GDPR": "Art.25",
    },
}
