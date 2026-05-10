"""
CloudGuard-AI — VPC Scanner
Collects VPC configurations: flow logs, route tables,
internet gateways, NACLs, and subnets.
"""
import asyncio
from typing import Any

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class VPCScanner(BaseScanner):
    service_name = "ec2"  # VPC APIs live under ec2 client

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        try:
            vpcs = self._paginate(client, "describe_vpcs", "Vpcs")
        except botocore.exceptions.ClientError as exc:
            logger.error("vpc_describe_failed", error=str(exc))
            return results

        # Build a map of VPC → flow logs
        flow_log_map = self._get_flow_log_map(client)

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            name = self._extract_name_tag(vpc.get("Tags", []), vpc_id)

            # Enrich with related resources
            config = {
                **vpc,
                "FlowLogs": flow_log_map.get(vpc_id, []),
                "InternetGateways": self._get_igws(client, vpc_id),
                "Subnets": self._get_subnets(client, vpc_id),
                "RouteTables": self._get_route_tables(client, vpc_id),
                "NetworkAcls": self._get_nacls(client, vpc_id),
            }

            results.append(ScanResult(
                asset_type=AssetType.VPC,
                asset_id=vpc_id,
                asset_name=name,
                region=self.region,
                raw_config=config,
            ))

        logger.info("vpc_scan_complete", collected=len(results))
        return results

    def _get_flow_log_map(self, client: Any) -> dict[str, list]:
        """Returns dict of vpc_id → list of flow log configs."""
        result: dict[str, list] = {}
        try:
            logs = self._paginate(client, "describe_flow_logs", "FlowLogs")
            for log in logs:
                resource_id = log.get("ResourceId", "")
                result.setdefault(resource_id, []).append(log)
        except botocore.exceptions.ClientError:
            pass
        return result

    def _get_igws(self, client: Any, vpc_id: str) -> list:
        try:
            return self._paginate(
                client, "describe_internet_gateways", "InternetGateways",
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}],
            )
        except botocore.exceptions.ClientError:
            return []

    def _get_subnets(self, client: Any, vpc_id: str) -> list:
        try:
            return self._paginate(
                client, "describe_subnets", "Subnets",
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
            )
        except botocore.exceptions.ClientError:
            return []

    def _get_route_tables(self, client: Any, vpc_id: str) -> list:
        try:
            return self._paginate(
                client, "describe_route_tables", "RouteTables",
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
            )
        except botocore.exceptions.ClientError:
            return []

    def _get_nacls(self, client: Any, vpc_id: str) -> list:
        try:
            return self._paginate(
                client, "describe_network_acls", "NetworkAcls",
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}],
            )
        except botocore.exceptions.ClientError:
            return []

    @staticmethod
    def _extract_name_tag(tags: list[dict], default: str) -> str:
        for tag in tags:
            if tag.get("Key") == "Name":
                return tag["Value"]
        return default
