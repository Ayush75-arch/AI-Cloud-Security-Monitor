"""
CloudGuard-AI — Azure Scanner (Mock)
Multi-cloud support: scans Azure resources for misconfigurations.
Mock mode returns realistic Azure assets for demo purposes.
Extend with Azure SDK (azure-identity, azure-mgmt-*) for real scans.
"""
import asyncio
from typing import Any

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class AzureScanner(BaseScanner):
    """
    Azure CSPM scanner. In demo mode, returns realistic mock assets.
    For production: use DefaultAzureCredential and Azure Resource Graph.
    """
    service_name = "azure"

    async def scan(self) -> list[ScanResult]:
        await asyncio.sleep(0.5)
        logger.info("azure_mock_scan_active")
        return [
            ScanResult(
                "azure_storage_account",
                "/subscriptions/sub-123/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/proddata",
                "proddata", "eastus", {
                    "name": "proddata",
                    "allowBlobPublicAccess": True,
                    "supportsHttpsTrafficOnly": False,
                    "defaultNetworkAction": "Allow",
                    "minimumTlsVersion": "TLS_1_0",
                }
            ),
            ScanResult(
                "azure_vm",
                "/subscriptions/sub-123/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web-server-01",
                "web-server-01", "eastus", {
                    "name": "web-server-01",
                    "osType": "Linux",
                    "publicIpAddress": "20.10.20.30",
                    "networkSecurityGroups": [{"id": "nsg-web", "name": "web-nsg"}],
                    "managedDiskEncryption": False,
                    "bootDiagnosticsEnabled": False,
                }
            ),
            ScanResult(
                "azure_sql_server",
                "/subscriptions/sub-123/resourceGroups/prod/providers/Microsoft.Sql/servers/prod-sql",
                "prod-sql", "eastus", {
                    "name": "prod-sql",
                    "publicNetworkAccess": "Enabled",
                    "minimalTlsVersion": "1.0",
                    "auditingEnabled": False,
                    "encryptionProtector": "ServiceManaged",
                }
            ),
        ]


SCANNER_REGISTRY_AZURE: dict[str, type[BaseScanner]] = {
    "azure": AzureScanner,
}
