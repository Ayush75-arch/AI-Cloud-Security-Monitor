"""
CloudGuard-AI — CloudTrail Rules
Detection rules for CloudTrail misconfigurations.
"""
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


class CloudTrailNoTrailsRule(BaseRule):
    """CT-001: No CloudTrail trails configured."""
    rule_id = "CT-001"
    title = "CloudTrail Not Configured"
    description = (
        "No CloudTrail trails are configured in this account. "
        "All API activity is unaudited — critical for security and compliance."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.CLOUDTRAIL_TRAIL]
    compliance_mappings = {
        "CIS": "3.1",
        "NIST": "AU-2",
        "PCI_DSS": "10.2",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("TrailsExist", True):
            return self._finding()
        return None


class CloudTrailNotMultiRegionRule(BaseRule):
    """CT-002: CloudTrail not multi-region."""
    rule_id = "CT-002"
    title = "CloudTrail Trail Not Multi-Region"
    description = (
        "This CloudTrail trail is not configured to log events from all regions. "
        "Activity in non-tracked regions will go unaudited."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.CLOUDTRAIL_TRAIL]
    compliance_mappings = {
        "CIS": "3.2",
        "NIST": "AU-12",
        "PCI_DSS": "10.2.1",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("IsMultiRegionTrail"):
            return self._finding()
        return None


class CloudTrailLogValidationRule(BaseRule):
    """CT-003: Log file validation not enabled."""
    rule_id = "CT-003"
    title = "CloudTrail Log File Validation Not Enabled"
    description = (
        "Log file validation is not enabled for this trail. "
        "Without validation, log integrity cannot be cryptographically verified."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.CLOUDTRAIL_TRAIL]
    compliance_mappings = {
        "CIS": "3.4",
        "NIST": "AU-2",
        "PCI_DSS": "10.5.2",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("LogFileValidationEnabled"):
            return self._finding()
        return None


class CloudTrailKMSEncryptionRule(BaseRule):
    """CT-004: CloudTrail logs not encrypted with KMS."""
    rule_id = "CT-004"
    title = "CloudTrail Logs Not Encrypted with KMS"
    description = (
        "CloudTrail logs are not encrypted with a KMS customer-managed key. "
        "Server-side encryption with S3-managed keys is less auditable."
    )
    severity = Severity.LOW
    applicable_asset_types = [AssetType.CLOUDTRAIL_TRAIL]
    compliance_mappings = {
        "CIS": "3.7",
        "NIST": "SC-28",
        "PCI_DSS": "3.5",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if not asset_config.get("KmsKeyId"):
            return self._finding()
        return None


class CloudTrailNotLoggingRule(BaseRule):
    """CT-005: CloudTrail trail not logging."""
    rule_id = "CT-005"
    title = "CloudTrail Trail Is Not Logging"
    description = (
        "This CloudTrail trail exists but is not actively logging. "
        "No API events are being recorded for this trail."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.CLOUDTRAIL_TRAIL]
    compliance_mappings = {
        "CIS": "3.1",
        "NIST": "AU-2",
        "PCI_DSS": "10.2",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        status = asset_config.get("Status", {})
        if asset_config.get("TrailsExist") and not status.get("IsLogging", False):
            return self._finding()
        return None
