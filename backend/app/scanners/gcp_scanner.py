"""
CloudGuard-AI — GCP Scanner (Mock)
Multi-cloud support: scans GCP resources for misconfigurations.
Mock mode returns realistic GCP assets for demo purposes.
Extend with Google Cloud client libraries for real scans.
"""
import asyncio

from app.scanners.base import BaseScanner, ScanResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


class GCPScanner(BaseScanner):
    """
    GCP CSPM scanner. In demo mode, returns realistic mock assets.
    For production: use google-cloud-resource-manager and google-cloud-asset.
    """
    service_name = "gcp"

    async def scan(self) -> list[ScanResult]:
        await asyncio.sleep(0.5)
        logger.info("gcp_mock_scan_active")
        return [
            ScanResult(
                "gcp_storage_bucket",
                "//storage.googleapis.com/projects/_/buckets/prod-customer-data",
                "prod-customer-data", "us-central1", {
                    "name": "prod-customer-data",
                    "uniformBucketLevelAccess": False,
                    "publicAccessPrevention": "inherited",
                    "versioningEnabled": False,
                    "encryption": "GoogleManaged",
                    "logBucket": None,
                }
            ),
            ScanResult(
                "gcp_compute_instance",
                "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/api-server-01",
                "api-server-01", "us-central1", {
                    "name": "api-server-01",
                    "machineType": "e2-medium",
                    "networkInterfaces": [{"accessConfigs": [{"natIP": "34.10.20.30"}]}],
                    "serviceAccounts": [{"email": "api-sa@my-project.iam.gserviceaccount.com"}],
                    "shieldedVmEnabled": False,
                    "confidentialComputingEnabled": False,
                }
            ),
            ScanResult(
                "gcp_iam_service_account",
                "//iam.googleapis.com/projects/my-project/serviceAccounts/deploy-sa@my-project.iam.gserviceaccount.com",
                "deploy-sa", "global", {
                    "name": "deploy-sa",
                    "email": "deploy-sa@my-project.iam.gserviceaccount.com",
                    "roles": ["roles/editor", "roles/storage.admin"],
                    "keys": [{"name": "key-1", "keyType": "USER_MANAGED"}],
                }
            ),
            ScanResult(
                "gcp_sql_instance",
                "//sqladmin.googleapis.com/projects/my-project/instances/prod-db",
                "prod-db", "us-central1", {
                    "name": "prod-db",
                    "databaseVersion": "POSTGRES_14",
                    "requireSsl": False,
                    "authorizedNetworks": ["0.0.0.0/0"],
                    "backupConfiguration": {"enabled": False},
                    "deletionProtectionEnabled": False,
                }
            ),
        ]


SCANNER_REGISTRY_GCP: dict[str, type[BaseScanner]] = {
    "gcp": GCPScanner,
}
