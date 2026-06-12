"""
CloudGuard-AI — KMS Scanner
Collects KMS key configurations: key rotation, key state,
key usage, and aliases for each key.
"""
import asyncio
from typing import Any

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class KMSScanner(BaseScanner):
    service_name = "kms"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        try:
            keys = self._paginate(client, "list_keys", "Keys")
        except botocore.exceptions.ClientError as exc:
            logger.error("kms_list_keys_failed", error=str(exc))
            return results

        for key_entry in keys:
            key_id = key_entry.get("KeyId", "")
            arn = key_entry.get("KeyArn", "")

            try:
                key_info = client.describe_key(KeyId=key_id).get("KeyMetadata", {})
            except botocore.exceptions.ClientError:
                logger.warning("kms_describe_failed", key_id=key_id)
                continue

            try:
                rotation = client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
            except botocore.exceptions.ClientError:
                rotation = False

            try:
                aliases = self._paginate(client, "list_aliases", "Aliases")
                key_aliases = [a for a in aliases if a.get("TargetKeyId") == key_id]
            except botocore.exceptions.ClientError:
                key_aliases = []

            config = {
                "KeyId": key_id,
                "Arn": arn,
                "Description": key_info.get("Description", ""),
                "KeyState": key_info.get("KeyState", ""),
                "KeyUsage": key_info.get("KeyUsage", ""),
                "CustomerMasterKeySpec": key_info.get("CustomerMasterKeySpec", ""),
                "KeyManager": key_info.get("KeyManager", "AWS"),
                "CreationDate": str(key_info.get("CreationDate", "")),
                "Enabled": key_info.get("Enabled", False),
                "MultiRegion": key_info.get("MultiRegion", False),
                "KeyRotationEnabled": rotation,
                "Aliases": [
                    {"AliasName": a.get("AliasName", ""), "AliasArn": a.get("AliasArn", "")}
                    for a in key_aliases
                ],
            }

            results.append(ScanResult(
                asset_type=AssetType.KMS_KEY,
                asset_id=arn,
                asset_name=key_id,
                region=self.region,
                raw_config=config,
            ))

        logger.info("kms_scan_complete", collected=len(results))
        return results
