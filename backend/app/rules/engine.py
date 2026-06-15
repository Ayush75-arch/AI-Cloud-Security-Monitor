"""
CloudGuard-AI — Rule Engine
Central engine: loads all rules, evaluates against scanned assets,
returns findings. Zero engine changes needed to add new rules.
"""

from app.rules.base_rule import BaseRule, RuleFinding
from app.rules.cloudtrail_rules import (
    CloudTrailKMSEncryptionRule,
    CloudTrailLogValidationRule,
    CloudTrailNoTrailsRule,
    CloudTrailNotLoggingRule,
    CloudTrailNotMultiRegionRule,
)
from app.rules.ec2_vpc_rules import (
    SGAllTrafficRule,
    SGUnrestrictedRDPRule,
    SGUnrestrictedSSHRule,
    VPCDefaultSecurityGroupRule,
    VPCFlowLogsRule,
)
from app.rules.iam_rules import (
    IAMAccessKeyRotationRule,
    IAMRootAccountUsageRule,
    IAMUserMFARule,
    IAMWildcardPolicyRule,
)
from app.rules.kms_rules import (
    KMSAwsManagedKeyRule,
    KMSDisabledKeyRule,
    KMSKeyRotationRule,
    KMSScheduledDeletionRule,
)
from app.rules.lambda_rules import (
    LambdaPublicEventInvokeRule,
    LambdaRuntimeDeprecatedRule,
    LambdaTimeoutRule,
    LambdaVPCNoInternetRule,
)
from app.rules.rds_rules import (
    RDSBackupRetentionRule,
    RDSDeletionProtectionRule,
    RDSEncryptionDisabledRule,
    RDSMinorUpgradeRule,
    RDSPubliclyAccessibleRule,
)
from app.rules.s3_rules import (
    S3EncryptionRule,
    S3LoggingRule,
    S3PublicAccessBlockRule,
    S3PublicACLRule,
    S3VersioningRule,
)
from app.scanners.base import ScanResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Rule Registry ─────────────────────────────────────────────────────────────
# Add new rules here. Engine auto-discovers applicable rules per asset type.

ALL_RULES: list[BaseRule] = [
    # S3
    S3PublicAccessBlockRule(),
    S3EncryptionRule(),
    S3VersioningRule(),
    S3LoggingRule(),
    S3PublicACLRule(),
    # IAM
    IAMWildcardPolicyRule(),
    IAMUserMFARule(),
    IAMAccessKeyRotationRule(),
    IAMRootAccountUsageRule(),
    # EC2 / Security Groups
    SGUnrestrictedSSHRule(),
    SGUnrestrictedRDPRule(),
    SGAllTrafficRule(),
    # VPC
    VPCFlowLogsRule(),
    VPCDefaultSecurityGroupRule(),
    # RDS
    RDSEncryptionDisabledRule(),
    RDSPubliclyAccessibleRule(),
    RDSDeletionProtectionRule(),
    RDSBackupRetentionRule(),
    RDSMinorUpgradeRule(),
    # Lambda
    LambdaPublicEventInvokeRule(),
    LambdaRuntimeDeprecatedRule(),
    LambdaVPCNoInternetRule(),
    LambdaTimeoutRule(),
    # CloudTrail
    CloudTrailNoTrailsRule(),
    CloudTrailNotMultiRegionRule(),
    CloudTrailLogValidationRule(),
    CloudTrailKMSEncryptionRule(),
    CloudTrailNotLoggingRule(),
    # KMS
    KMSKeyRotationRule(),
    KMSScheduledDeletionRule(),
    KMSDisabledKeyRule(),
    KMSAwsManagedKeyRule(),
]

# Build a lookup: asset_type → applicable rules (avoids O(n*m) iteration)
_RULE_INDEX: dict[str, list[BaseRule]] = {}
for _rule in ALL_RULES:
    for _at in (_rule.applicable_asset_types or []):
        _RULE_INDEX.setdefault(_at, []).append(_rule)


class RuleEngine:
    """
    Stateless engine: call evaluate_asset() per asset, collect findings.
    Thread-safe — no mutable state.
    """

    def evaluate_asset(self, asset: ScanResult) -> list[RuleFinding]:
        """Run all applicable rules against a single asset."""
        applicable = _RULE_INDEX.get(asset.asset_type, [])
        findings: list[RuleFinding] = []

        for rule in applicable:
            try:
                result = rule.evaluate(asset.raw_config)
                if result is not None:
                    findings.append(result)
                    logger.debug(
                        "rule_triggered",
                        rule_id=rule.rule_id,
                        asset=asset.asset_id,
                        severity=result.severity,
                    )
            except Exception as exc:
                # Never let a buggy rule crash the scan
                logger.error(
                    "rule_evaluation_error",
                    rule_id=rule.rule_id,
                    asset=asset.asset_id,
                    error=str(exc),
                )

        return findings

    def evaluate_all(self, assets: list[ScanResult]) -> dict[str, list[RuleFinding]]:
        """
        Evaluate all assets. Returns dict of asset_id → list of findings.
        Suitable for parallel processing if needed.
        """
        results: dict[str, list[RuleFinding]] = {}
        for asset in assets:
            findings = self.evaluate_asset(asset)
            if findings:
                results[asset.asset_id] = findings

        total = sum(len(v) for v in results.values())
        logger.info("rule_engine_complete", assets_scanned=len(assets), total_findings=total)
        return results
