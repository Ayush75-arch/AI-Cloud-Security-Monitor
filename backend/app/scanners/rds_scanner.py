"""
CloudGuard-AI — RDS Scanner
Collects RDS instance configurations: encryption, public accessibility,
backup retention, deletion protection, auto-minor version upgrades.
"""
import asyncio

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class RDSScanner(BaseScanner):
    service_name = "rds"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        try:
            instances = self._paginate(client, "describe_db_instances", "DBInstances")
        except botocore.exceptions.ClientError as exc:
            logger.error("rds_describe_failed", error=str(exc))
            return results

        for instance in instances:
            instance_id = instance.get("DBInstanceIdentifier", "unknown")
            arn = instance.get("DBInstanceArn", f"arn:aws:rds:{self.region}:{self.account_id}:db:{instance_id}")

            config = {
                "DBInstanceIdentifier": instance_id,
                "DBInstanceClass": instance.get("DBInstanceClass", ""),
                "Engine": instance.get("Engine", ""),
                "EngineVersion": instance.get("EngineVersion", ""),
                "MultiAZ": instance.get("MultiAZ", False),
                "StorageEncrypted": instance.get("StorageEncrypted", False),
                "PubliclyAccessible": instance.get("PubliclyAccessible", False),
                "DeletionProtection": instance.get("DeletionProtection", False),
                "BackupRetentionPeriod": instance.get("BackupRetentionPeriod", 0),
                "AutoMinorVersionUpgrade": instance.get("AutoMinorVersionUpgrade", False),
                "CopyTagsToSnapshot": instance.get("CopyTagsToSnapshot", False),
                "VpcSecurityGroups": instance.get("VpcSecurityGroups", []),
                "DBSecurityGroups": instance.get("DBSecurityGroups", []),
                "EnhancedMonitoringResourceArn": instance.get("EnhancedMonitoringResourceArn"),
                "PerformanceInsightsEnabled": instance.get("PerformanceInsightsEnabled", False),
                "IAMDatabaseAuthenticationEnabled": instance.get("IAMDatabaseAuthenticationEnabled", False),
                "StorageType": instance.get("StorageType", ""),
            }

            results.append(ScanResult(
                asset_type=AssetType.RDS_INSTANCE,
                asset_id=arn,
                asset_name=instance_id,
                region=self.region,
                raw_config=config,
            ))

        logger.info("rds_scan_complete", collected=len(results))
        return results
