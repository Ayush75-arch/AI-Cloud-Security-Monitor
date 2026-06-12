"""
CloudGuard-AI — Lambda Rules
Detection rules for Lambda function misconfigurations.
"""
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


class LambdaPublicEventInvokeRule(BaseRule):
    """LAMBDA-001: Function can be invoked from any AWS account."""
    rule_id = "LAMBDA-001"
    title = "Lambda Function Has Public Resource-Based Policy"
    description = (
        "The Lambda function has a resource-based policy that allows invocation "
        "from any AWS account or any principal, posing a security risk."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.LAMBDA_FUNCTION]
    compliance_mappings = {
        "NIST": "AC-3",
        "PCI_DSS": "7.1.2",
        "SOC2": "CC6.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        policy = asset_config.get("Policy") or {}
        statements = policy.get("Statement", []) if isinstance(policy, dict) else []
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", {})
                if principal == "*" or principal.get("AWS") == "*":
                    return self._finding()
        return None


class LambdaRuntimeDeprecatedRule(BaseRule):
    """LAMBDA-002: Deprecated runtime in use."""
    rule_id = "LAMBDA-002"
    title = "Lambda Function Uses Deprecated Runtime"
    description = (
        "The Lambda function uses a deprecated runtime that no longer receives "
        "security updates and patches."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.LAMBDA_FUNCTION]
    compliance_mappings = {
        "NIST": "SI-2",
        "SOC2": "CC7.1",
    }

    _DEPRECATED_RUNTIMES = {
        "nodejs", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs8.10",
        "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
        "python2.7", "python3.6", "python3.7", "python3.8",
        "ruby2.5",
        "java8", "java8.al2",
        "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
        "provided", "provided.al1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        runtime = asset_config.get("Runtime", "")
        if runtime in self._DEPRECATED_RUNTIMES:
            return self._finding(f"Deprecated runtime '{runtime}' in use.")
        return None


class LambdaVPCNoInternetRule(BaseRule):
    """LAMBDA-003: Function in VPC without internet access."""
    rule_id = "LAMBDA-003"
    title = "Lambda Function in VPC Without Internet Access"
    description = (
        "The Lambda function is configured with a VPC but may lack internet access "
        "via a NAT gateway. This can cause timeouts when accessing external APIs."
    )
    severity = Severity.LOW
    applicable_asset_types = [AssetType.LAMBDA_FUNCTION]
    compliance_mappings = {}

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        vpc_config = asset_config.get("VpcConfig", {})
        subnet_ids = vpc_config.get("SubnetIds", [])
        if subnet_ids and not vpc_config.get("InternetAccess"):
            return self._finding(
                "Function is VPC-locked without internet access. "
                "Ensure a NAT Gateway is configured for outbound connectivity."
            )
        return None


class LambdaTimeoutRule(BaseRule):
    """LAMBDA-004: Function timeout too high."""
    rule_id = "LAMBDA-004"
    title = "Lambda Function Timeout Exceeds Best Practice"
    description = (
        "The Lambda function has a timeout greater than 5 minutes (300 seconds). "
        "Long-running functions increase costs and risk of throttling."
    )
    severity = Severity.LOW
    applicable_asset_types = [AssetType.LAMBDA_FUNCTION]
    compliance_mappings = {}

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        timeout = asset_config.get("Timeout", 0)
        if timeout > 300:
            return self._finding(f"Function timeout is {timeout}s (recommended: <= 300s).")
        return None
