"""
CloudGuard-AI — IAM Scanner
Collects IAM users, roles, and customer-managed policies.
Retrieves inline/attached policies and password policy.
"""
import asyncio
import json
from typing import Any

import botocore.exceptions

from app.scanners.base import BaseScanner, ScanResult
from app.utils.constants import AssetType
from app.utils.logger import get_logger

logger = get_logger(__name__)


class IAMScanner(BaseScanner):
    service_name = "iam"

    async def scan(self) -> list[ScanResult]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self) -> list[ScanResult]:
        client = self._get_client()
        results: list[ScanResult] = []

        results.extend(self._scan_users(client))
        results.extend(self._scan_roles(client))
        results.extend(self._scan_policies(client))

        logger.info("iam_scan_complete", collected=len(results))
        return results

    # ── Users ─────────────────────────────────────────────────────────────

    def _scan_users(self, client: Any) -> list[ScanResult]:
        results = []
        try:
            users = self._paginate(client, "list_users", "Users")
        except botocore.exceptions.ClientError as exc:
            logger.error("iam_list_users_failed", error=str(exc))
            return results

        for user in users:
            username = user["UserName"]
            arn = user["Arn"]

            # Collect attached + inline policies
            try:
                attached = client.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                inline_names = client.list_user_policies(UserName=username).get("PolicyNames", [])
                inline_policies = []
                for pname in inline_names:
                    doc = client.get_user_policy(UserName=username, PolicyName=pname)
                    inline_policies.append({
                        "PolicyName": pname,
                        "PolicyDocument": json.loads(doc["PolicyDocument"]) if isinstance(doc["PolicyDocument"], str) else doc["PolicyDocument"],
                    })

                # Access keys info
                keys = client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                mfa = client.list_mfa_devices(UserName=username).get("MFADevices", [])
            except botocore.exceptions.ClientError as exc:
                logger.warning("iam_user_detail_failed", user=username, error=str(exc))
                attached, inline_policies, keys, mfa = [], [], [], []

            config = {
                **user,
                "CreateDate": user.get("CreateDate", "").isoformat() if user.get("CreateDate") else "",
                "PasswordLastUsed": user.get("PasswordLastUsed", "").isoformat() if user.get("PasswordLastUsed") else None,
                "AttachedPolicies": attached,
                "InlinePolicies": inline_policies,
                "AccessKeys": [
                    {**k, "CreateDate": k.get("CreateDate", "").isoformat() if k.get("CreateDate") else ""}
                    for k in keys
                ],
                "MFADevices": mfa,
            }

            results.append(ScanResult(
                asset_type=AssetType.IAM_USER,
                asset_id=arn,
                asset_name=username,
                region="global",
                raw_config=config,
            ))

        return results

    # ── Roles ─────────────────────────────────────────────────────────────

    def _scan_roles(self, client: Any) -> list[ScanResult]:
        results = []
        try:
            roles = self._paginate(client, "list_roles", "Roles")
        except botocore.exceptions.ClientError as exc:
            logger.error("iam_list_roles_failed", error=str(exc))
            return results

        for role in roles:
            role_name = role["RoleName"]
            arn = role["Arn"]

            try:
                attached = client.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                inline_names = client.list_role_policies(RoleName=role_name).get("PolicyNames", [])
                inline_policies = []
                for pname in inline_names:
                    doc = client.get_role_policy(RoleName=role_name, PolicyName=pname)
                    inline_policies.append({
                        "PolicyName": pname,
                        "PolicyDocument": doc["PolicyDocument"],
                    })
            except botocore.exceptions.ClientError as exc:
                logger.warning("iam_role_detail_failed", role=role_name, error=str(exc))
                attached, inline_policies = [], []

            config = {
                **role,
                "CreateDate": role.get("CreateDate", "").isoformat() if role.get("CreateDate") else "",
                "AttachedPolicies": attached,
                "InlinePolicies": inline_policies,
            }

            results.append(ScanResult(
                asset_type=AssetType.IAM_ROLE,
                asset_id=arn,
                asset_name=role_name,
                region="global",
                raw_config=config,
            ))

        return results

    # ── Customer-managed Policies ─────────────────────────────────────────

    def _scan_policies(self, client: Any) -> list[ScanResult]:
        results = []
        try:
            policies = self._paginate(client, "list_policies", "Policies", Scope="Local")
        except botocore.exceptions.ClientError as exc:
            logger.error("iam_list_policies_failed", error=str(exc))
            return results

        for policy in policies:
            arn = policy["Arn"]
            name = policy["PolicyName"]
            version_id = policy.get("DefaultVersionId", "v1")

            try:
                version = client.get_policy_version(PolicyArn=arn, VersionId=version_id)
                document = version.get("PolicyVersion", {}).get("Document", {})
            except botocore.exceptions.ClientError:
                document = {}

            config = {
                **policy,
                "CreateDate": policy.get("CreateDate", "").isoformat() if policy.get("CreateDate") else "",
                "UpdateDate": policy.get("UpdateDate", "").isoformat() if policy.get("UpdateDate") else "",
                "PolicyDocument": document,
            }

            results.append(ScanResult(
                asset_type=AssetType.IAM_POLICY,
                asset_id=arn,
                asset_name=name,
                region="global",
                raw_config=config,
            ))

        return results
