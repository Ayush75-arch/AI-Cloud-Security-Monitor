"""Scanner package — maps service names to scanner classes."""
from app.scanners.base import BaseScanner, ScanResult
from app.scanners.ec2_scanner import EC2Scanner
from app.scanners.iam_scanner import IAMScanner
from app.scanners.s3_scanner import S3Scanner
from app.scanners.vpc_scanner import VPCScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "s3": S3Scanner,
    "iam": IAMScanner,
    "ec2": EC2Scanner,
    "vpc": VPCScanner,
}

__all__ = ["SCANNER_REGISTRY", "BaseScanner", "ScanResult"]
