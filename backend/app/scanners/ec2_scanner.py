"""
CloudGuard-AI — EC2 Scanner
Collects EC2 instances and security group configurations.
Captures ingress/egress rules for open-port detection.
"""
import asyncio
from typing import Any

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class EC2Scanner(BaseScanner):
    service_name = "ec2"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        results.extend(self._scan_instances(client))
        results.extend(self._scan_security_groups(client))

        logger.info("ec2_scan_complete", collected=len(results))
        return results

    # ── Instances ─────────────────────────────────────────────────────────

    def _scan_instances(self, client: Any) -> list[ScanResult]:
        results = []
        try:
            reservations = self._paginate(client, "describe_instances", "Reservations")
        except botocore.exceptions.ClientError as exc:
            logger.error("ec2_describe_instances_failed", error=str(exc))
            return results

        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                name = self._extract_name_tag(instance.get("Tags", []), instance_id)

                # Normalize datetime fields
                config = {
                    **instance,
                    "LaunchTime": instance.get("LaunchTime", "").isoformat() if instance.get("LaunchTime") else "",
                }

                results.append(ScanResult(
                    asset_type=AssetType.EC2_INSTANCE,
                    asset_id=instance_id,
                    asset_name=name,
                    region=self.region,
                    raw_config=config,
                ))

        return results

    # ── Security Groups ───────────────────────────────────────────────────

    def _scan_security_groups(self, client: Any) -> list[ScanResult]:
        results = []
        try:
            groups = self._paginate(client, "describe_security_groups", "SecurityGroups")
        except botocore.exceptions.ClientError as exc:
            logger.error("ec2_describe_sgs_failed", error=str(exc))
            return results

        for sg in groups:
            sg_id = sg["GroupId"]
            name = sg.get("GroupName", sg_id)

            results.append(ScanResult(
                asset_type=AssetType.SECURITY_GROUP,
                asset_id=sg_id,
                asset_name=name,
                region=self.region,
                raw_config=sg,
            ))

        return results

    @staticmethod
    def _extract_name_tag(tags: list[dict], default: str) -> str:
        for tag in tags:
            if tag.get("Key") == "Name":
                return tag["Value"]
        return default
