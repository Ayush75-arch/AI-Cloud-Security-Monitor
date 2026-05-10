"""
CloudGuard-AI — EC2 & VPC Rules
Detection rules for security groups and VPC misconfigurations.
"""
from typing import Any

from app.rules.base_rule import BaseRule, RuleFinding
from app.utils.constants import AssetType, Severity


# ── Security Group Rules ──────────────────────────────────────────────────────

def _allows_unrestricted(ip_permissions: list, port: int) -> bool:
    """Returns True if any rule allows 0.0.0.0/0 or ::/0 access on given port."""
    OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
    for perm in ip_permissions:
        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 65535)
        protocol = perm.get("IpProtocol", "-1")

        in_range = (protocol == "-1") or (from_port <= port <= to_port)
        if not in_range:
            continue

        for range_ in perm.get("IpRanges", []):
            if range_.get("CidrIp") in OPEN_CIDRS:
                return True
        for range_ in perm.get("Ipv6Ranges", []):
            if range_.get("CidrIpv6") in OPEN_CIDRS:
                return True
    return False


class SGUnrestrictedSSHRule(BaseRule):
    """EC2-001: Security group allows SSH from 0.0.0.0/0."""
    rule_id = "EC2-001"
    title = "Security Group Allows Unrestricted SSH (Port 22)"
    description = (
        "This security group allows inbound SSH (port 22) from any IP address (0.0.0.0/0). "
        "This exposes instances to brute-force and credential-stuffing attacks from the internet."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.SECURITY_GROUP]
    compliance_mappings = {
        "CIS": "5.2",
        "NIST": "SC-7",
        "PCI_DSS": "1.3.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        ingress = asset_config.get("IpPermissions", [])
        if _allows_unrestricted(ingress, 22):
            return self._finding()
        return None


class SGUnrestrictedRDPRule(BaseRule):
    """EC2-002: Security group allows RDP from 0.0.0.0/0."""
    rule_id = "EC2-002"
    title = "Security Group Allows Unrestricted RDP (Port 3389)"
    description = (
        "This security group allows inbound RDP (port 3389) from any IP address. "
        "Exposing RDP to the internet is a leading cause of ransomware infections."
    )
    severity = Severity.CRITICAL
    applicable_asset_types = [AssetType.SECURITY_GROUP]
    compliance_mappings = {
        "CIS": "5.3",
        "NIST": "SC-7",
        "PCI_DSS": "1.3.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        ingress = asset_config.get("IpPermissions", [])
        if _allows_unrestricted(ingress, 3389):
            return self._finding()
        return None


class SGAllTrafficRule(BaseRule):
    """EC2-003: Security group allows all inbound traffic."""
    rule_id = "EC2-003"
    title = "Security Group Allows All Inbound Traffic"
    description = (
        "This security group has a rule permitting all inbound traffic (protocol -1) "
        "from 0.0.0.0/0. This eliminates network-level isolation entirely."
    )
    severity = Severity.HIGH
    applicable_asset_types = [AssetType.SECURITY_GROUP]
    compliance_mappings = {
        "CIS": "5.4",
        "NIST": "SC-7",
        "PCI_DSS": "1.3.2",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        ingress = asset_config.get("IpPermissions", [])
        OPEN_CIDRS = {"0.0.0.0/0", "::/0"}
        for perm in ingress:
            if perm.get("IpProtocol") == "-1":
                for r in perm.get("IpRanges", []):
                    if r.get("CidrIp") in OPEN_CIDRS:
                        return self._finding()
                for r in perm.get("Ipv6Ranges", []):
                    if r.get("CidrIpv6") in OPEN_CIDRS:
                        return self._finding()
        return None


# ── VPC Rules ─────────────────────────────────────────────────────────────────

class VPCFlowLogsRule(BaseRule):
    """VPC-001: VPC flow logs disabled."""
    rule_id = "VPC-001"
    title = "VPC Flow Logs Not Enabled"
    description = (
        "VPC Flow Logs are not enabled for this VPC. "
        "Without flow logs, network traffic is unaudited and forensic investigation "
        "of security incidents is severely impaired."
    )
    severity = Severity.MEDIUM
    applicable_asset_types = [AssetType.VPC]
    compliance_mappings = {
        "CIS": "3.9",
        "NIST": "AU-12",
        "PCI_DSS": "10.8",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        flow_logs = asset_config.get("FlowLogs", [])
        active_logs = [
            fl for fl in flow_logs
            if fl.get("FlowLogStatus") == "ACTIVE"
        ]
        if not active_logs:
            return self._finding()
        return None


class VPCDefaultSecurityGroupRule(BaseRule):
    """VPC-002: Default VPC exists in account."""
    rule_id = "VPC-002"
    title = "Default VPC Detected"
    description = (
        "The default VPC is present in this region. "
        "Default VPCs have permissive default security group rules and "
        "should be removed to enforce intentional network segmentation."
    )
    severity = Severity.LOW
    applicable_asset_types = [AssetType.VPC]
    compliance_mappings = {
        "CIS": "5.5",
        "NIST": "SC-7",
        "PCI_DSS": "1.2.1",
    }

    def evaluate(self, asset_config: dict[str, Any]) -> RuleFinding | None:
        if asset_config.get("IsDefault") is True:
            return self._finding()
        return None
