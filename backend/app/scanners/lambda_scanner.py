"""
CloudGuard-AI — Lambda Scanner
Collects Lambda function configurations: runtime, IAM role,
environment variables, VPC config, reserved concurrency.
"""
import asyncio
from typing import Any

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class LambdaScanner(BaseScanner):
    service_name = "lambda"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        try:
            functions = self._paginate(client, "list_functions", "Functions")
        except botocore.exceptions.ClientError as exc:
            logger.error("lambda_list_failed", error=str(exc))
            return results

        for fn in functions:
            fn_name = fn.get("FunctionName", "unknown")
            arn = fn.get("FunctionArn", "")

            config = {
                "FunctionName": fn_name,
                "Runtime": fn.get("Runtime", ""),
                "Role": fn.get("Role", ""),
                "Handler": fn.get("Handler", ""),
                "CodeSize": fn.get("CodeSize", 0),
                "Description": fn.get("Description", ""),
                "Timeout": fn.get("Timeout", 0),
                "MemorySize": fn.get("MemorySize", 0),
                "LastModified": str(fn.get("LastModified", "")),
                "CodeSha256": fn.get("CodeSha256", ""),
                "Version": fn.get("Version", ""),
                "VpcConfig": fn.get("VpcConfig", {}),
                "Environment": fn.get("Environment", {}),
                "KMSKeyArn": fn.get("KMSKeyArn", ""),
                "TracingConfig": fn.get("TracingConfig", {}),
                "ReservedConcurrentExecutions": fn.get("ReservedConcurrentExecutions"),
                "PackageType": fn.get("PackageType", "Zip"),
            }

            results.append(ScanResult(
                asset_type=AssetType.LAMBDA_FUNCTION,
                asset_id=arn,
                asset_name=fn_name,
                region=self.region,
                raw_config=config,
            ))

        logger.info("lambda_scan_complete", collected=len(results))
        return results
