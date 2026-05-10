"""
CloudGuard-AI — IAM Rules
Detection rules for IAM misconfigurations: wildcard permissions,
missing MFA, admin policies, stale access keys.
"""
import json
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


def _has_wildcard_action(policy_doc: dict) -> bool:
    """Check if any statement grants Action: '*' to Resource: '*'."""
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


class IAMWildcardPolicyRule(BaseRule):
    """IAM-001: Policy grants Action:* Resource:*."""
    rule_id = "IAM-001"
    title = "IAM Policy Grants Wildcard Admin Permissions"
    description = (
        "This IAM policy contains a statement with Action: '*' and Resource: '*'. "
        "This grants full administrative access, violating the principle of least privilege."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.IAM_POLICY, AssetType.IAM_ROLE, AssetType.IAM_USER]
    compliance_mappings = {
        "CIS": "1.16",
        "NIST": "AC-6",
        "PCI_DSS": "7.1.2",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        # Check customer-managed policy document
        doc = asset_config.get("PolicyDocument", {})
        if doc and _has_wildcard_action(doc):
            return self._finding()

        # Check inline policies on roles/users
        for inline in asset_config.get("InlinePolicies", []):
            if _has_wildcard_action(inline.get("PolicyDocument", {})):
                return self._finding(
                    f"Inline policy '{inline['PolicyName']}' grants Action:* Resource:*."
                )

        # Check attached policy names (heuristic — AdministratorAccess)
        for attached in asset_config.get("AttachedPolicies", []):
            if attached.get("PolicyName") == "AdministratorAccess":
                return self._finding(
                    "AWS managed policy 'AdministratorAccess' is attached, granting full admin access."
                )

        return None


class IAMUserMFARule(BaseRule):
    """IAM-002: Console user has no MFA device."""
    rule_id = "IAM-002"
    title = "IAM User Has No MFA Device"
    description = (
        "This IAM user does not have an MFA device configured. "
        "Accounts without MFA are vulnerable to credential compromise attacks."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.IAM_USER]
    compliance_mappings = {
        "CIS": "1.5",
        "NIST": "IA-2",
        "PCI_DSS": "8.3.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        mfa_devices = asset_config.get("MFADevices", [])
        if not mfa_devices:
            return self._finding()
        return None


class IAMAccessKeyRotationRule(BaseRule):
    """IAM-003: Access key older than 90 days."""
    rule_id = "IAM-003"
    title = "IAM User Access Key Not Rotated (>90 days)"
    description = (
        "One or more IAM access keys have not been rotated in over 90 days. "
        "Long-lived credentials increase the blast radius of a key compromise."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.IAM_USER]
    compliance_mappings = {
        "CIS": "1.14",
        "NIST": "IA-5",
        "PCI_DSS": "8.3.9",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        from datetime import datetime, timezone, timedelta
        threshold = datetime.now(timezone.utc) - timedelta(days=90)

        for key in asset_config.get("AccessKeys", []):
            create_date_str = key.get("CreateDate", "")
            if not create_date_str:
                continue
            try:
                create_date = datetime.fromisoformat(create_date_str.replace("Z", "+00:00"))
                if create_date < threshold and key.get("Status") == "Active":
                    return self._finding(
                        f"Access key {key.get('AccessKeyId', '')} created {create_date_str[:10]} "
                        "has not been rotated in over 90 days."
                    )
            except ValueError:
                continue
        return None


class IAMRootAccountUsageRule(BaseRule):
    """IAM-004: Root account access keys exist."""
    rule_id = "IAM-004"
    title = "Root Account Access Keys Active"
    description = (
        "The AWS root account has active programmatic access keys. "
        "Root keys cannot be scoped and represent maximum privilege. "
        "Their compromise would result in complete account takeover."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.IAM_USER]
    compliance_mappings = {
        "CIS": "1.4",
        "NIST": "AC-2",
        "PCI_DSS": "8.2.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        # Root user has username "<root_account>" or Arn contains ":root"
        arn = asset_config.get("Arn", "")
        if ":root" in arn:
            active_keys = [
                k for k in asset_config.get("AccessKeys", [])
                if k.get("Status") == "Active"
            ]
            if active_keys:
                return self._finding()
        return None
