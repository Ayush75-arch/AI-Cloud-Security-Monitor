"""
CloudGuard-AI — CloudTrail Scanner
Collects CloudTrail trail configurations: multi-region, log file validation,
KMS encryption, S3 bucket destination, and insights settings.
"""
import asyncio

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class CloudTrailScanner(BaseScanner):
    service_name = "cloudtrail"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        try:
            trails = client.describe_trails().get("trailList", [])
        except botocore.exceptions.ClientError as exc:
            logger.error("cloudtrail_describe_failed", error=str(exc))
            return results

        if not trails:
            results.append(ScanResult(
                asset_type=AssetType.CLOUDTRAIL_TRAIL,
                asset_id=f"arn:aws:cloudtrail:{self.region}:{self.account_id}:trail/none",
                asset_name="No CloudTrail Trails",
                region=self.region,
                raw_config={"TrailsExist": False},
            ))
            return results

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            arn = trail.get("TrailARN", "")

            try:
                status = client.get_trail_status(Name=trail_name)
            except botocore.exceptions.ClientError:
                status = {}

            try:
                event_selectors = client.get_event_selectors(TrailName=trail_name).get("EventSelectors", [])
            except botocore.exceptions.ClientError:
                event_selectors = []

            config = {
                "Name": trail_name,
                "S3BucketName": trail.get("S3BucketName", ""),
                "S3KeyPrefix": trail.get("S3KeyPrefix", ""),
                "SnsTopicName": trail.get("SnsTopicName", ""),
                "IncludeGlobalServiceEvents": trail.get("IncludeGlobalServiceEvents", True),
                "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
                "HomeRegion": trail.get("HomeRegion", ""),
                "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
                "KmsKeyId": trail.get("KmsKeyId", ""),
                "HasCustomEventSelectors": trail.get("HasCustomEventSelectors", False),
                "IsOrganizationTrail": trail.get("IsOrganizationTrail", False),
                "TrailsExist": True,
                "Status": {
                    "IsLogging": status.get("IsLogging", False),
                    "LatestDeliveryTime": str(status.get("LatestDeliveryTime", "")),
                    "LatestDigestDeliveryTime": str(status.get("LatestDigestDeliveryTime", "")),
                    "StartLoggingTime": str(status.get("StartLoggingTime", "")),
                    "StopLoggingTime": str(status.get("StopLoggingTime", "")),
                },
                "EventSelectors": [
                    {
                        "ReadWriteType": es.get("ReadWriteType", ""),
                        "IncludeManagementEvents": es.get("IncludeManagementEvents", False),
                        "DataResources": es.get("DataResources", []),
                        "ExcludeManagementEventSources": es.get("ExcludeManagementEventSources", []),
                    }
                    for es in event_selectors
                ],
            }

            results.append(ScanResult(
                asset_type=AssetType.CLOUDTRAIL_TRAIL,
                asset_id=arn,
                asset_name=trail_name,
                region=self.region,
                raw_config=config,
            ))

        logger.info("cloudtrail_scan_complete", collected=len(results))
        return results
