"""Scanner package — maps service names to scanner classes."""
from app.scanners.base import BaseScanner, ScanResult
from app.scanners.cloudtrail_scanner import CloudTrailScanner
from app.scanners.ec2_scanner import EC2Scanner
from app.scanners.iam_scanner import IAMScanner
from app.scanners.kms_scanner import KMSScanner
from app.scanners.lambda_scanner import LambdaScanner
from app.scanners.rds_scanner import RDSScanner
from app.scanners.s3_scanner import S3Scanner
from app.scanners.vpc_scanner import VPCScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "s3": S3Scanner,
    "iam": IAMScanner,
    "ec2": EC2Scanner,
    "vpc": VPCScanner,
    "rds": RDSScanner,
    "lambda": LambdaScanner,
    "cloudtrail": CloudTrailScanner,
    "kms": KMSScanner,
}

__all__ = ["SCANNER_REGISTRY", "BaseScanner", "ScanResult"]
