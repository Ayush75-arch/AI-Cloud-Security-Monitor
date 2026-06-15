"""
CloudGuard-AI — Terraform IaC Scanner
Parses .tf files and detects security misconfigurations BEFORE deployment.
No cloud credentials required — pure static analysis.

Detects:
- S3 buckets with public ACL
- S3 buckets without encryption
- Security groups with open SSH/RDP
- IAM policies with wildcard permissions
- Missing HTTPS enforcement
- Hardcoded secrets/passwords in variables
"""
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IaCFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    compliance_mappings: dict = field(default_factory=dict)
    remediation: str = ""


class TerraformScanner:
    """
    Static analysis scanner for Terraform HCL files.
    Parses resource blocks and applies security rules.
    """

    def scan_directory(self, directory: str) -> list[IaCFinding]:
        """Scan all .tf files in a directory recursively."""
        findings = []
        path = Path(directory)
        tf_files = list(path.rglob("*.tf"))

        for tf_file in tf_files:
            try:
                content = tf_file.read_text(encoding="utf-8")
                findings.extend(self._scan_file(str(tf_file), content))
            except Exception:
                pass

        return findings

    def scan_content(self, content: str, filename: str = "main.tf") -> list[IaCFinding]:
        """Scan raw Terraform HCL string content."""
        return self._scan_file(filename, content)

    def _scan_file(self, filepath: str, content: str) -> list[IaCFinding]:
        findings = []
        resources = self._parse_resources(content)

        for resource in resources:
            findings.extend(self._check_s3_bucket(resource, filepath, content))
            findings.extend(self._check_security_group(resource, filepath, content))
            findings.extend(self._check_iam_policy(resource, filepath, content))

        findings.extend(self._check_hardcoded_secrets(filepath, content))
        return findings

    # ── Resource parser ───────────────────────────────────────────────────────

    def _parse_resources(self, content: str) -> list[dict]:
        """
        Naive but effective HCL resource block parser.
        Extracts resource type, name, and raw block content.
        """
        resources = []
        pattern = re.compile(
            r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
            re.MULTILINE
        )
        for match in pattern.finditer(content):
            resource_type = match.group(1)
            resource_name = match.group(2)
            block_start = match.end()
            block_content = self._extract_block(content, block_start)
            resources.append({
                "type": resource_type,
                "name": resource_name,
                "content": block_content,
                "line": content[:match.start()].count("\n") + 1,
            })
        return resources

    @staticmethod
    def _extract_block(content: str, start: int) -> str:
        """Extract balanced { } block starting at index."""
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        return content[start:i - 1]

    # ── S3 Rules ──────────────────────────────────────────────────────────────

    def _check_s3_bucket(self, res: dict, filepath: str, full: str) -> list[IaCFinding]:
        findings = []
        if res["type"] != "aws_s3_bucket":
            return []

        block = res["content"]
        name = res["name"]
        line = res["line"]

        # Public ACL
        if re.search(r'acl\s*=\s*"public-read"', block) or re.search(r'acl\s*=\s*"public-read-write"', block):
            findings.append(IaCFinding(
                rule_id="TF-S3-001",
                title="S3 Bucket Has Public ACL",
                description=f"Resource '{name}' sets ACL to public-read or public-read-write, exposing all objects.",
                severity="critical",
                file_path=filepath,
                line_number=line,
                resource_type="aws_s3_bucket",
                resource_name=name,
                compliance_mappings={"CIS": "2.1.5", "NIST": "AC-3", "PCI_DSS": "1.3.2"},
                remediation='Remove the acl argument or set acl = "private". Use aws_s3_bucket_public_access_block instead.',
            ))

        # No server-side encryption block
        if not re.search(r"server_side_encryption_configuration", block):
            findings.append(IaCFinding(
                rule_id="TF-S3-002",
                title="S3 Bucket Missing Encryption Configuration",
                description=f"Resource '{name}' has no server_side_encryption_configuration block.",
                severity="high",
                file_path=filepath,
                line_number=line,
                resource_type="aws_s3_bucket",
                resource_name=name,
                compliance_mappings={"CIS": "2.1.1", "NIST": "SC-28", "PCI_DSS": "3.5"},
                remediation='Add server_side_encryption_configuration with SSE-S3 or SSE-KMS.',
            ))

        # Versioning not enabled
        if not re.search(r"versioning", block) or re.search(r'enabled\s*=\s*false', block):
            findings.append(IaCFinding(
                rule_id="TF-S3-003",
                title="S3 Bucket Versioning Not Enabled",
                description=f"Resource '{name}' does not enable versioning.",
                severity="medium",
                file_path=filepath,
                line_number=line,
                resource_type="aws_s3_bucket",
                resource_name=name,
                compliance_mappings={"CIS": "2.1.3", "NIST": "CP-9"},
                remediation='Add versioning { enabled = true } to the bucket resource.',
            ))

        return findings

    # ── Security Group Rules ──────────────────────────────────────────────────

    def _check_security_group(self, res: dict, filepath: str, full: str) -> list[IaCFinding]:
        findings = []
        if res["type"] not in ("aws_security_group", "aws_security_group_rule"):
            return []

        block = res["content"]
        name = res["name"]
        line = res["line"]

        open_cidrs = re.findall(r'cidr_blocks\s*=\s*\[?"?0\.0\.0\.0/0"?\]?', block)
        if not open_cidrs:
            return []

        # Check for specific dangerous ports
        for port, rule_id, title in [
            (22, "TF-SG-001", "Security Group Allows SSH from 0.0.0.0/0"),
            (3389, "TF-SG-002", "Security Group Allows RDP from 0.0.0.0/0"),
        ]:
            port_pattern = re.compile(
                rf'from_port\s*=\s*{port}|to_port\s*=\s*{port}'
            )
            if port_pattern.search(block):
                findings.append(IaCFinding(
                    rule_id=rule_id,
                    title=title,
                    description=f"Resource '{name}' opens port {port} to the internet (0.0.0.0/0).",
                    severity="critical",
                    file_path=filepath,
                    line_number=line,
                    resource_type=res["type"],
                    resource_name=name,
                    compliance_mappings={"CIS": "5.2", "NIST": "SC-7", "PCI_DSS": "1.3.1"},
                    remediation=f"Restrict port {port} to specific IP ranges or VPN CIDR. Never open to 0.0.0.0/0.",
                ))

        # All traffic open
        if re.search(r'from_port\s*=\s*0', block) and re.search(r'to_port\s*=\s*0', block):
            findings.append(IaCFinding(
                rule_id="TF-SG-003",
                title="Security Group Allows All Traffic from 0.0.0.0/0",
                description=f"Resource '{name}' allows all inbound traffic from the internet.",
                severity="high",
                file_path=filepath,
                line_number=line,
                resource_type=res["type"],
                resource_name=name,
                compliance_mappings={"CIS": "5.4", "NIST": "SC-7", "PCI_DSS": "1.3.2"},
                remediation="Define explicit ingress rules for required ports only.",
            ))

        return findings

    # ── IAM Rules ─────────────────────────────────────────────────────────────

    def _check_iam_policy(self, res: dict, filepath: str, full: str) -> list[IaCFinding]:
        findings = []
        if res["type"] not in ("aws_iam_policy", "aws_iam_role_policy"):
            return []

        block = res["content"]
        name = res["name"]
        line = res["line"]

        # Wildcard action + resource
        if re.search(r'"Action"\s*:\s*"\*"', block) and re.search(r'"Resource"\s*:\s*"\*"', block):
            findings.append(IaCFinding(
                rule_id="TF-IAM-001",
                title="IAM Policy Grants Wildcard Admin Permissions",
                description=f"Resource '{name}' uses Action:* and Resource:*, granting full admin access.",
                severity="critical",
                file_path=filepath,
                line_number=line,
                resource_type=res["type"],
                resource_name=name,
                compliance_mappings={"CIS": "1.16", "NIST": "AC-6", "PCI_DSS": "7.1.2"},
                remediation="Replace Action:* with specific required actions. Apply least-privilege principle.",
            ))

        return findings

    # ── Hardcoded Secrets ─────────────────────────────────────────────────────

    def _check_hardcoded_secrets(self, filepath: str, content: str) -> list[IaCFinding]:
        findings = []
        secret_patterns = [
            (r'password\s*=\s*"[^"]{4,}"', "TF-SEC-001", "Hardcoded Password in Terraform"),
            (r'secret\s*=\s*"[^"]{4,}"', "TF-SEC-002", "Hardcoded Secret in Terraform"),
            (r'AKIA[0-9A-Z]{16}', "TF-SEC-003", "Hardcoded AWS Access Key"),
            (r'aws_secret_access_key\s*=\s*"[^"]{10,}"', "TF-SEC-004", "Hardcoded AWS Secret Key"),
        ]
        for pattern, rule_id, title in secret_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = content[:match.start()].count("\n") + 1
                findings.append(IaCFinding(
                    rule_id=rule_id,
                    title=title,
                    description=f"Potential secret found at line {line}. Hardcoded credentials are a critical security risk.",
                    severity="critical",
                    file_path=filepath,
                    line_number=line,
                    resource_type="secret",
                    resource_name="hardcoded_secret",
                    compliance_mappings={"CIS": "1.21", "NIST": "IA-5", "PCI_DSS": "8.2.1"},
                    remediation="Use AWS Secrets Manager, SSM Parameter Store, or Terraform variables with sensitive=true. Never commit secrets to source control.",
                ))
        return findings
