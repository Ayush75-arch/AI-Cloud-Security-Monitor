"""
CloudGuard-AI — RDS Rules
Detection rules for RDS instance misconfigurations.
"""
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


class RDSEncryptionDisabledRule(BaseRule):
    """RDS-001: Storage encryption not enabled."""
    rule_id = "RDS-001"
    title = "RDS Instance Storage Encryption Disabled"
    description = (
        "The RDS instance does not have storage encryption enabled. "
        "Data at rest is not encrypted, violating data protection standards."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.RDS_INSTANCE]
    compliance_mappings = {
        "CIS": "2.1.1",
        "NIST": "SC-28",
        "PCI_DSS": "3.5",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("StorageEncrypted"):
            return self._finding()
        return None


class RDSPubliclyAccessibleRule(BaseRule):
    """RDS-002: RDS instance publicly accessible."""
    rule_id = "RDS-002"
    title = "RDS Instance Publicly Accessible"
    description = (
        "The RDS instance is configured as publicly accessible. "
        "This exposes the database to the internet, increasing the attack surface."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.RDS_INSTANCE]
    compliance_mappings = {
        "CIS": "2.1.5",
        "NIST": "SC-7",
        "PCI_DSS": "1.3.2",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if asset_config.get("PubliclyAccessible"):
            return self._finding()
        return None


class RDSDeletionProtectionRule(BaseRule):
    """RDS-003: Deletion protection not enabled."""
    rule_id = "RDS-003"
    title = "RDS Instance Deletion Protection Disabled"
    description = (
        "The RDS instance does not have deletion protection enabled. "
        "This risks accidental or malicious deletion of critical databases."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.RDS_INSTANCE]
    compliance_mappings = {
        "NIST": "CP-9",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("DeletionProtection"):
            return self._finding()
        return None


class RDSBackupRetentionRule(BaseRule):
    """RDS-004: Backup retention too short."""
    rule_id = "RDS-004"
    title = "RDS Instance Backup Retention Period Too Short"
    description = (
        "The RDS instance has a backup retention period of less than 7 days. "
        "Short retention limits recovery point objectives during incidents."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.RDS_INSTANCE]
    compliance_mappings = {
        "CIS": "2.1.3",
        "NIST": "CP-9",
        "PCI_DSS": "10.5.1",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        retention = asset_config.get("BackupRetentionPeriod", 0)
        if retention < 7:
            return self._finding(
                f"Backup retention period is {retention} days (minimum recommended: 7 days)."
            )
        return None


class RDSMinorUpgradeRule(BaseRule):
    """RDS-005: Auto minor version upgrade disabled."""
    rule_id = "RDS-005"
    title = "RDS Instance Auto Minor Version Upgrade Disabled"
    description = (
        "The RDS instance does not have auto minor version upgrade enabled. "
        "Critical security patches may not be applied automatically."
    )
    severity = Severity.LOW
    applicable_asset_types = [AssetType.RDS_INSTANCE]
    compliance_mappings = {
        "NIST": "SI-2",
        "SOC2": "CC7.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("AutoMinorVersionUpgrade"):
            return self._finding()
        return None
