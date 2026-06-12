"""
CloudGuard-AI — S3 Rules
Detection rules for S3 bucket misconfigurations.
"""
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


class S3PublicAccessBlockRule(BaseRule):
    """S3-001: Public access block not fully enabled."""
    rule_id = "S3-001"
    title = "S3 Bucket Public Access Block Disabled"
    description = (
        "The S3 bucket does not have all four public access block settings enabled. "
        "This may allow public access via ACLs or bucket policies."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.S3_BUCKET]
    compliance_mappings = {
        "CIS": "2.1.5",
        "NIST": "AC-3",
        "PCI_DSS": "1.3.2",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        pab = asset_config.get("PublicAccessBlockConfiguration") or {}
        required_keys = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        if not pab or not all(pab.get(k) is True for k in required_keys):
            return self._finding()
        return None


class S3EncryptionRule(BaseRule):
    """S3-002: Server-side encryption not configured."""
    rule_id = "S3-002"
    title = "S3 Bucket Encryption Not Enabled"
    description = (
        "The S3 bucket lacks a default server-side encryption configuration. "
        "Data at rest is not encrypted, violating data protection standards."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.S3_BUCKET]
    compliance_mappings = {
        "CIS": "2.1.1",
        "NIST": "SC-28",
        "PCI_DSS": "3.5",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        sse = asset_config.get("ServerSideEncryptionConfiguration")
        if not sse:
            return self._finding()
        rules = sse.get("Rules", [])
        if not rules:
            return self._finding()
        return None


class S3VersioningRule(BaseRule):
    """S3-003: Versioning not enabled."""
    rule_id = "S3-003"
    title = "S3 Bucket Versioning Disabled"
    description = (
        "Object versioning is disabled on this bucket. "
        "Without versioning, accidental deletions or overwrites cannot be recovered."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.S3_BUCKET]
    compliance_mappings = {
        "CIS": "2.1.3",
        "NIST": "CP-9",
        "PCI_DSS": "10.5.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        versioning = asset_config.get("VersioningConfiguration") or {}
        status = versioning.get("Status", "")
        if status != "Enabled":
            return self._finding()
        return None


class S3LoggingRule(BaseRule):
    """S3-004: Access logging disabled."""
    rule_id = "S3-004"
    title = "S3 Bucket Access Logging Not Enabled"
    description = (
        "S3 server access logging is disabled. "
        "Without logging, there is no audit trail for data access, "
        "making incident investigation impossible."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.S3_BUCKET]
    compliance_mappings = {
        "CIS": "2.1.2",
        "NIST": "AU-2",
        "PCI_DSS": "10.2",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        logging_enabled = asset_config.get("LoggingEnabled")
        if not logging_enabled:
            return self._finding()
        return None


class S3PublicACLRule(BaseRule):
    """S3-005: Bucket ACL grants public read/write."""
    rule_id = "S3-005"
    title = "S3 Bucket Has Public ACL Grant"
    description = (
        "The S3 bucket ACL grants read or write access to AllUsers or AuthenticatedUsers. "
        "This exposes bucket contents to the public internet."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.S3_BUCKET]
    compliance_mappings = {
        "CIS": "2.1.5",
        "NIST": "AC-3",
        "PCI_DSS": "1.3.2",
    }

    _PUBLIC_URIS = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        acl = asset_config.get("ACL") or {}
        grants = acl.get("Grants", [])
        for grant in grants:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            permission = grant.get("Permission", "")
            if uri in self._PUBLIC_URIS and permission in ("READ", "WRITE", "FULL_CONTROL"):
                return self._finding(
                    f"Bucket ACL grants {permission} to {uri.split('/')[-1]}."
                )
        return None
