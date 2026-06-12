"""
CloudGuard-AI — KMS Rules
Detection rules for KMS key misconfigurations.
"""
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


class KMSKeyRotationRule(BaseRule):
    """KMS-001: Automatic key rotation not enabled."""
    rule_id = "KMS-001"
    title = "KMS Customer-Managed Key Rotation Disabled"
    description = (
        "Automatic yearly key rotation is not enabled for this KMS key. "
        "Without rotation, a compromised key exposes all data encrypted under it."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.KMS_KEY]
    compliance_mappings = {
        "CIS": "3.8",
        "NIST": "SC-28",
        "PCI_DSS": "3.6.4",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("KeyRotationEnabled"):
            return self._finding()
        return None


class KMSScheduledDeletionRule(BaseRule):
    """KMS-002: Key is pending deletion."""
    rule_id = "KMS-002"
    title = "KMS Key Is Pending Deletion"
    description = (
        "This KMS key is pending deletion and will be permanently removed. "
        "All data encrypted under this key will become inaccessible."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.KMS_KEY]
    compliance_mappings = {
        "NIST": "SC-28",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if asset_config.get("KeyState") == "PendingDeletion":
            return self._finding()
        return None


class KMSDisabledKeyRule(BaseRule):
    """KMS-003: Key is disabled."""
    rule_id = "KMS-003"
    title = "KMS Key Is Disabled"
    description = (
        "This KMS key is disabled. Any operations relying on this key "
        "for encryption or decryption will fail."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.KMS_KEY]
    compliance_mappings = {}

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if asset_config.get("KeyState") == "Disabled":
            return self._finding()
        return None


class KMSAwsManagedKeyRule(BaseRule):
    """KMS-004: AWS managed key used instead of customer managed."""
    rule_id = "KMS-004"
    title = "KMS Key Is AWS-Managed"
    description = (
        "This KMS key is managed by AWS. Customer-managed keys provide "
        "more control over access, rotation, and auditing."
    )
    severity = Severity.LOW
    applicable_asset_types = [AssetType.KMS_KEY]
    compliance_mappings = {
        "CIS": "3.7",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if asset_config.get("KeyManager") == "AWS":
            return self._finding()
        return None
