"""
CloudGuard-AI — S3 Scanner
Collects S3 bucket configurations: ACLs, public access blocks,
encryption, versioning, logging, lifecycle policies.
"""
import asyncio
from typing import Any

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class S3Scanner(BaseScanner):
    service_name = "s3"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        try:
            response = client.list_buckets()
            buckets = response.get("Buckets", [])
        except botocore.exceptions.ClientError as exc:
            logger.error("s3_list_buckets_failed", error=str(exc))
            return results

        logger.info("s3_scan_start", bucket_count=len(buckets))

        for bucket in buckets:
            name = bucket["Name"]
            config = self._collect_bucket_config(client, name)
            config["Name"] = name
            config["CreationDate"] = bucket.get("CreationDate", "").isoformat() if bucket.get("CreationDate") else ""

            results.append(ScanResult(
                asset_type=AssetType.S3_BUCKET,
                asset_id=f"arn:aws:s3:::{name}",
                asset_name=name,
                region=self._get_bucket_region(client, name),
                raw_config=config,
            ))

        logger.info("s3_scan_complete", collected=len(results))
        return results

    def _collect_bucket_config(self, client: Any, bucket_name: str) -> dict:
        """Collect all relevant security configurations for a single bucket."""
        config: dict[str, Any] = {}

        # Public access block settings
        config["PublicAccessBlockConfiguration"] = self._safe_get(
            client.get_public_access_block,
            "PublicAccessBlockConfiguration",
            Bucket=bucket_name,
        )

        # ACL
        config["ACL"] = self._safe_get(client.get_bucket_acl, None, Bucket=bucket_name)

        # Server-side encryption
        config["ServerSideEncryptionConfiguration"] = self._safe_get(
            client.get_bucket_encryption,
            "ServerSideEncryptionConfiguration",
            Bucket=bucket_name,
        )

        # Versioning
        config["VersioningConfiguration"] = self._safe_get(
            client.get_bucket_versioning, None, Bucket=bucket_name
        )

        # Logging
        config["LoggingEnabled"] = self._safe_get(
            client.get_bucket_logging, "LoggingEnabled", Bucket=bucket_name
        )

        # Bucket policy (presence only — content irrelevant for public check)
        try:
            policy = client.get_bucket_policy(Bucket=bucket_name)
            config["Policy"] = policy.get("Policy", "")
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
                config["Policy"] = None
            else:
                config["Policy"] = None

        return config

    def _get_bucket_region(self, client: Any, bucket_name: str) -> str:
        try:
            loc = client.get_bucket_location(Bucket=bucket_name)
            region = loc.get("LocationConstraint") or "us-east-1"
            return region
        except botocore.exceptions.ClientError:
            return self.region

    @staticmethod
    def _safe_get(fn, key: str | None, **kwargs) -> Any:
        """Call an AWS API function, return key from response or None on error."""
        try:
            result = fn(**kwargs)
            result.pop("ResponseMetadata", None)
            return result.get(key) if key else result
        except botocore.exceptions.ClientError:
            return None
